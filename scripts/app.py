"""
AntiPhishing – Flask Backend (Phase 1 + Phase 2 stub)
======================================================
Endpoints:
    POST /api/check          → Phase 1 DB check + Phase 2 ML stub
    GET  /api/stats          → DB stats
    POST /api/report         → User-reported malicious URL
    POST /api/qr/check       → QR scan check (same pipeline as /api/check)
    POST /api/qr/report      → Save QR scan result to MongoDB

"""

import os
from flask import Flask, request, jsonify
from lookup import URLLookup
from datetime import datetime, timezone

app = Flask(__name__)

lookup = URLLookup(
    mongo_uri=os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
    db_name=os.environ.get("DB_NAME", "antiphishing"),
)

# Collection for storing QR scan history
COLLECTION_QR_SCANS = "qr_scans"


# ── Endpoints ─────────────────────────────────────────────────────────────────

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

    # Found in blacklist → malicious
    if result["found"]:
        threat = result["threat"]
        return {
            "url": url,
            "is_malicious": True,
            "confidence": 100,
            "match_type": result["match_type"],
            "source": threat.get("source"),
            "type": threat.get("type"),
            "explanation": _build_explanation(result),
        }

    # Phase 2: Heuristic / ML analysis (stub – implement next)
    # TODO: call heuristic engine + ML model
    ml_result = _phase2_stub(url)
    return ml_result


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


def _phase2_stub(url: str) -> dict:
    """Placeholder for Phase 2 heuristic + ML pipeline."""
    return {
        "url":          url,
        "is_malicious": False,
        "confidence":   0,
        "match_type":   "safe",
        "source":       None,
        "explanation":  "Not found in threat database. Deep analysis pending (Phase 2).",
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
