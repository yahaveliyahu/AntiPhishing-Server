"""
AntiPhishing – Phase 1: URL Lookup
===================================
This is the DB check called by the main pipeline before heuristic/ML analysis.

Usage (from Flask backend or Android backend):
    from lookup import URLLookup

    checker = URLLookup()                          # uses env MONGO_URI / DB_NAME
    result  = checker.check("https://paypa1.com/login")
    # result → {"found": True, "threat": {...}} or {"found": False}
"""

import os
import logging
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

log = logging.getLogger(__name__)

DEFAULT_MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DEFAULT_DB_NAME   = os.environ.get("DB_NAME",   "antiphishing")

COLLECTION_URLS    = "malicious_urls"
COLLECTION_DOMAINS = "malicious_domains"
COLLECTION_CACHE   = "checked_urls_cache"


def normalize_url(raw: str) -> str | None:
    """Lowercase + clean URL for consistent lookup."""
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        if not p.netloc:
            return None
        return urlunparse(p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower()))
    except Exception:
        return None


def extract_domain(url: str) -> str | None:
    """Extract bare domain without www."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower() or None
    except Exception:
        return None


class URLLookup:
    """
    Phase 1 DB lookup.

    check(url) returns:
        {
            "found": True,
            "match_type": "url" | "domain",
            "threat": { ... mongo document ... }
        }
        or
        {
            "found": False
        }

    If found=False the caller should proceed to heuristic / ML analysis.
    """

    def __init__(
        self,
        mongo_uri: str = DEFAULT_MONGO_URI,
        db_name:   str = DEFAULT_DB_NAME,
    ):
        self._client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        self._db     = self._client[db_name]
        self._ensure_cache_index()

    def _ensure_cache_index(self):
        self._db[COLLECTION_CACHE].create_index(
            [("url", 1)], unique=True, sparse=True
        )

    # ── Public API ────────────────────────────────────────────────

    def check(self, raw_url: str) -> dict:
        """
        Main lookup entry point.
        1. Normalise URL
        2. Check full URL in malicious_urls
        3. Check domain in malicious_domains
        4. Cache result for future fast hits
        """
        url    = normalize_url(raw_url)
        domain = extract_domain(raw_url)

        if not url and not domain:
            return {"found": False, "error": "invalid_url"}

        # ── 1. Cache hit ──────────────────────────────────────────
        cached = self._check_cache(url)
        if cached is not None:
            return cached

        # ── 2. Exact URL match ────────────────────────────────────
        if url:
            doc = self._db[COLLECTION_URLS].find_one(
                {"url": url}, {"_id": 0}
            )
            if doc:
                result = {"found": True, "match_type": "url", "threat": doc}
                self._cache(url, result)
                return result

        # ── 3. Domain match ───────────────────────────────────────
        if domain:
            doc = self._db[COLLECTION_DOMAINS].find_one(
                {"domain": domain}, {"_id": 0}
            )
            if doc:
                result = {"found": True, "match_type": "domain", "threat": doc}
                self._cache(url, result)
                return result

        # ── 4. Not found → proceed to deep analysis ───────────────
        result = {"found": False}
        self._cache(url, result)
        return result

    def add_url(self, url: str, source: str = "user_report", threat_type: str = "phishing"):
        """
        Add a newly discovered malicious URL to the DB (used after ML confirms threat).
        This is the 'save new URL to DB' step from the README algorithm.
        """
        url    = normalize_url(url)
        domain = extract_domain(url)
        if not url:
            return

        now = datetime.now(timezone.utc)
        self._db[COLLECTION_URLS].update_one(
            {"url": url},
            {"$set": {
                "url": url,
                "domain": domain,
                "source": source,
                "type": threat_type,
                "updated_at": now,
            }, "$setOnInsert": {"created_at": now}},
            upsert=True,
        )
        if domain:
            self._db[COLLECTION_DOMAINS].update_one(
                {"domain": domain},
                {
                    "$addToSet": {"sources": source},
                    "$set": {"type": threat_type, "updated_at": now},
                    "$setOnInsert": {"domain": domain, "created_at": now},
                },
                upsert=True,
            )
        # Invalidate cache for this URL
        self._db[COLLECTION_CACHE].delete_one({"url": url})

    # ── Internal ──────────────────────────────────────────────────

    def _check_cache(self, url: str | None) -> dict | None:
        if not url:
            return None
        doc = self._db[COLLECTION_CACHE].find_one({"url": url}, {"_id": 0, "result": 1})
        return doc["result"] if doc else None

    def _cache(self, url: str | None, result: dict):
        if not url:
            return
        try:
            self._db[COLLECTION_CACHE].update_one(
                {"url": url},
                {"$set": {"url": url, "result": result, "cached_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
        except Exception:
            pass   # cache is best-effort

    def stats(self) -> dict:
        return {
            "malicious_urls":    self._db[COLLECTION_URLS].count_documents({}),
            "malicious_domains": self._db[COLLECTION_DOMAINS].count_documents({}),
            "cached_checks":     self._db[COLLECTION_CACHE].count_documents({}),
        }
