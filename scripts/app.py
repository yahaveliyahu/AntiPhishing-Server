"""
AntiPhishing – Flask Backend (Phase 1 + Phase 2 ML + Domain Age)
=================================================================
Endpoints:
    POST /api/check          → Full pipeline: DB check + ML model + domain age
    POST /api/score          → ML model scoring only (called by Android Step 3)
    GET  /api/stats          → DB stats
    POST /api/report         → User-reported malicious URL
    POST /api/qr/check       → QR scan check (same pipeline as /api/check)
    POST /api/qr/report      → Save QR scan result to MongoDB

Pipeline for each URL:
    Step 1 — MongoDB whitelist/blacklist (fast path)
    Step 2 — Lexical analysis (on Android device)
    Step 3 — ML model scoring (/api/score)
    Step 3b — Domain age post-processing (WHOIS)
"""

import os
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from lookup import URLLookup
from datetime import datetime, timezone
from feature_extractor import extract_features
from domain_age import get_age_adjusted_confidence

app = Flask(__name__)

lookup = URLLookup(
    mongo_uri=os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
    db_name=os.environ.get("DB_NAME", "antiphishing"),
)

# ── Load ML model on startup ──────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'model.pkl')
_model_data = None
_model = None
_feature_names = None


def _load_model():
    global _model_data, _model, _feature_names
    if _model is not None:
        return True
    try:
        print(f"[ML] Loading model from: {MODEL_PATH}", flush=True)
        if not os.path.exists(MODEL_PATH):
            print(f"[ML] ERROR: model.pkl not found at {MODEL_PATH}", flush=True)
            return False
        _model_data = joblib.load(MODEL_PATH)
        _model = _model_data['model']
        _feature_names = _model_data['feature_names']
        print(f"[ML] Model loaded successfully: {len(_feature_names)} features, "
              f"accuracy {_model_data['accuracy'] * 100:.2f}%", flush=True)
        return True
    except Exception as e:
        print(f"[ML] ERROR loading model: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return False


# Load model immediately on startup
_load_model()

# Collection for storing QR scan history
COLLECTION_QR_SCANS = "qr_scans"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/api/score", methods=["POST"])
def score_url():
    """
    Step 3 ML scoring endpoint — called by Android after lexical analysis.

    The Android app sends the URL and its pre-computed lexical features.
    This endpoint runs the ML model and domain age check, returning
    a final malicious probability.

    Request body:
    {
        "url": "https://example.com/login",
        "features": {
            "url_length": 35,
            "is_https": 1,
            "lexical_risk_score": 20,
            ... (all 57 features)
        }
    }

    Response:
    {
        "url": "...",
        "is_malicious": true/false,
        "confidence": 0-100,
        "match_type": "ml_model",
        "explanation": "..."
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    features = data.get("features", {})

    if not url:
        return jsonify({"error": "url field required"}), 400

    return jsonify(_run_ml_scoring(url, features))


@app.route("/api/check", methods=["POST"])
def check_url():
    """
    Main pipeline entry point (mirrors README Algorithm):

    1. Normalise URL
    2. DB lookup (Phase 1 – fast path)
       → If found: return malicious immediately
    3. Not found → proceed to heuristic / ML (Phase 2 – stub here)

    Request body: { "url": "https://example.com/login" }
    Response:
    {
        "url": "...",
        "is_malicious": true/false,
        "confidence": 0-100,
        "match_type": "url" | "domain" | "heuristic" | "safe",
        "source": "...",
        "explanation": "..."
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field required"}), 400

    return jsonify(_run_check_pipeline(url))


@app.route("/api/qr/check", methods=["POST"])
def check_qr():
    """
    Check a URL decoded from a QR code.
    Runs the exact same pipeline as /api/check.

    Request body:  { "url": "https://example.com" }
    Response:      same shape as /api/check
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field required"}), 400

    return jsonify(_run_check_pipeline(url))


@app.route("/api/qr/report", methods=["POST"])
def report_qr_scan():
    """
    Save a QR scan result to MongoDB for history and analytics.
    Called by the Android app after every QR scan, regardless of result.

    Request body:
    {
        "url":          "https://example.com",
        "is_malicious": true | false,
        "confidence":   0-100,
        "source":       "PhishTank" | "Lexical Analysis" | null,
        "match_type":   "url" | "domain" | "whitelist" | "safe" | "lexical"
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field required"}), 400

    scan_record = {
        "url": url,
        "is_malicious": data.get("is_malicious", False),
        "confidence": data.get("confidence", 0),
        "source": data.get("source"),
        "match_type": data.get("match_type", ""),
        "scanned_at": datetime.now(timezone.utc),
    }

    lookup._db[COLLECTION_QR_SCANS].insert_one(scan_record)
    return jsonify({"status": "saved", "url": url})


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(lookup.stats())


@app.route("/api/report", methods=["POST"])
def report_url():
    """User-confirmed malicious URL – add to DB for future fast-path hits."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    lookup.add_url(url, source="user_report")
    return jsonify({"status": "added", "url": url})


# ── Shared pipeline ───────────────────────────────────────────────────────────

def _run_check_pipeline(url: str) -> dict:
    """
    Shared check logic used by both /api/check and /api/qr/check.

    Phase 1 — DB lookup (fast path):
        - If the URL or domain is whitelisted → return safe immediately.
        - If the URL or domain is blacklisted → return malicious immediately.

    Phase 2 — Heuristic / ML analysis (stub, implement next):
        - Reached only when Phase 1 finds no match.
    """
    result = lookup.check(url)

    # Whitelisted → immediately safe, skip all analysis
    if result.get("safe"):
        return {
            "url": url,
            "is_malicious": False,
            "confidence": 100,
            "match_type": "whitelist",
            "source": None,
            "explanation": f"This is a known safe site: {result.get('description', '')}.",
        }

    # Found in blacklist/threat intel → ML model for risk % and explanation
    # Skip lexical analyzer — MongoDB already confirmed it is malicious
    if result["found"]:
        threat = result["threat"]
        db_source = threat.get("source", "threat database")
        db_type = threat.get("type", "malicious")
        ml_result = _run_ml_scoring(url, {})
        # Force malicious — MongoDB confirmed it regardless of ML score
        ml_result["is_malicious"] = True
        ml_result["match_type"] = result["match_type"]
        ml_result["explanation"] = (
                f"Found in {db_source} as {db_type}."
                + ml_result["explanation"]
        )
        return ml_result

        # Not found in MongoDB → return Unknown so Android handles:
        #   Step 2: Lexical Analyzer (obvious killers → block, safe → allow)
        #   Step 3: ML model via /api/score (uncertain URLs)
    return {
        "url": url,
        "is_malicious": False,
        "confidence": 0,
        "match_type": "unknown",
        "source": None,
        "explanation": "Not found in threat database. Proceeding to deep analysis.",
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_explanation(result: dict) -> str:
    """Build a human-readable explanation string from a blacklist hit."""
    threat = result["threat"]
    match = result["match_type"]
    source = threat.get("source", "unknown")
    t = threat.get("type", "malicious")

    if match == "url":
        return f"This exact URL is listed as {t} in {source}."
    return f"The domain of this URL is listed as {t} in {source}."


def _run_ml_scoring(url: str, features: dict) -> dict:
    """
    Phase 2: Run ML model + domain age post-processing.

    If Android sent pre-computed features, use them directly.
    Otherwise compute features from the URL here on the server.
    """
    # ── Step 1: Get feature vector ────────────────────────────────────────────
    if not _load_model():
        return {
            "url":          url,
            "is_malicious": False,
            "confidence":   0,
            "match_type":   "ml_unavailable",
            "source":       None,
            "explanation":  "ML model not available.",
        }

    try:
        # Always compute the full feature vector on the server.
        # Android's LexicalAnalyzer only produces a subset of features
        # (missing is_classic_phishing, brand_is_registrable, deep_subdomain_abuse,
        # brand_hijack_with_keywords, brands_in_subdomain, and others added since).
        # Using partial features silently zeroes these out and corrupts the
        # ML score. feature_extractor.py here is the authoritative, complete
        # implementation — always use it regardless of what Android sends.
        feature_vector = extract_features(url)

        # Build feature matrix in correct column order
        X = pd.DataFrame([feature_vector])[_feature_names].values

        # Run ML model
        ml_prob = float(_model.predict_proba(X)[0][1])  # probability of malicious
        ml_confident = ml_prob >= 0.5

    except Exception as e:
        app.logger.error(f"ML scoring failed for {url}: {e}")
        return {
            "url":          url,
            "is_malicious": False,
            "confidence":   0,
            "match_type":   "ml_error",
            "source":       None,
            "explanation":  "ML scoring error.",
        }

    # ── Step 2: Domain age post-processing ───────────────────────────────────
    try:
        domain = urlparse(url).hostname or ""
        adjusted_prob, age_explanation = get_age_adjusted_confidence(
            domain, ml_prob
        )
    except Exception as e:
        app.logger.warning(f"Domain age check failed for {url}: {e}")
        adjusted_prob = ml_prob
        age_explanation = None

    # ── Step 3: Final decision ────────────────────────────────────────────────
    is_malicious = adjusted_prob >= 0.5
    confidence = int(round(adjusted_prob * 100))  # whole integer — Android expects optInt()

    # Build specific explanation based on actual feature values
    if is_malicious:
        reasons = []

        # Use features from Android if available, otherwise extract from URL
        f = feature_vector if feature_vector else {}

        if f.get("is_ip_address", 0):
            reasons.append("IP address used instead of a domain name")

        if not f.get("is_https", 1):
            reasons.append("Unencrypted HTTP connection (not HTTPS)")

        if f.get("brand_in_subdomain", 0):
            reasons.append("Brand name found in subdomain — classic phishing pattern")

        if f.get("brand_hijack_with_keywords", 0) or f.get("brand_in_path", 0):
            reasons.append("Brand name appears in path but not in the real domain")

        if f.get("is_classic_phishing", 0):
            reasons.append("URL matches known phishing structure patterns")

        if f.get("visual_spoof_detected", 0):
            reasons.append("Domain name visually imitates a known brand (typosquatting)")

        if f.get("is_punycode", 0):
            reasons.append("Punycode domain — used to visually spoof real domains")

        if f.get("is_shortener", 0):
            reasons.append("URL shortener used to hide the real destination")

        kw_count = f.get("high_risk_keyword_count", 0)
        if kw_count >= 2:
            reasons.append(f"Multiple high-risk keywords detected (login, verify, account, update...)")
        elif kw_count == 1:
            reasons.append("High-risk keyword detected in URL")

        if f.get("subdomain_count", 0) >= 3:
            reasons.append(f"Unusually many subdomains ({int(f.get('subdomain_count', 0))})")

        if f.get("path_depth", 0) >= 4:
            reasons.append(f"Suspiciously deep URL path ({int(f.get('path_depth', 0))} levels)")

        if f.get("is_suspicious_tld", 0):
            reasons.append("Suspicious top-level domain (commonly used in phishing)")

        if f.get("has_at_symbol", 0):
            reasons.append("@ symbol in URL — used to hide the real destination")

        if f.get("has_credentials_pattern", 0):
            reasons.append("URL contains embedded credentials")

        if f.get("deep_subdomain_abuse", 0):
            reasons.append("Brand name buried deep in subdomains to appear legitimate")

        if f.get("obvious_killer_count", 0):
            reasons.append("URL contains dangerous patterns (javascript:, data:, null bytes)")

        if age_explanation:
            reasons.append(age_explanation)

        # Build source description
        if reasons:
            explanation = (
                f"Risk: {confidence}%\n"
                + "\n".join(f"• {r}" for r in reasons)
            )
        else:
            explanation = (
                f"Risk: {confidence}%\n"
                f"• Multiple phishing indicators detected"
            )

    else:
        explanation = (
            f"Risk: {round(100-confidence)}% safe\n"
            f"• No phishing patterns detected. This URL appears safe."
        )

    return {
        "url":          url,
        "is_malicious": is_malicious,
        "confidence":   confidence,
        "match_type":   "ml_model",
        "source":       "XGBoost + Domain Age",
        "explanation":  explanation,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)