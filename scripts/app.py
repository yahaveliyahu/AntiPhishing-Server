"""
AntiPhishing – Flask Backend (Phase 1 + Phase 2 stub)
======================================================
Endpoints:
    POST /api/check          → Phase 1 DB check + Phase 2 ML stub
    GET  /api/stats          → DB stats
    POST /api/report         → User-reported malicious URL

Run:
    pip install flask pymongo
    MONGO_URI=mongodb://localhost:27017 python app.py
"""

import os
from flask import Flask, request, jsonify
from lookup import URLLookup

app = Flask(__name__)

lookup = URLLookup(
    mongo_uri=os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
    db_name=os.environ.get("DB_NAME", "antiphishing"),
)


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
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field required"}), 400

    # ── Phase 1: DB Lookup ────────────────────────────────────────
    result = lookup.check(url)

    if result["found"]:
        threat = result["threat"]
        return jsonify({
            "url":          url,
            "is_malicious": True,
            "confidence":   100,
            "match_type":   result["match_type"],
            "source":       threat.get("source"),
            "type":         threat.get("type"),
            "explanation":  _build_explanation(result),
        })

    # ── Phase 2: Heuristic / ML analysis (stub – implement next) ──
    # TODO: call heuristic engine + ML model
    ml_result = _phase2_stub(url)
    return jsonify(ml_result)


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(lookup.stats())


@app.route("/api/report", methods=["POST"])
def report_url():
    """User-confirmed malicious URL – add to DB for future fast-path hits."""
    data = request.get_json(force=True, silent=True) or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    lookup.add_url(url, source="user_report")
    return jsonify({"status": "added", "url": url})


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_explanation(result: dict) -> str:
    threat = result["threat"]
    match  = result["match_type"]
    source = threat.get("source", "unknown")
    t      = threat.get("type", "malicious")
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
