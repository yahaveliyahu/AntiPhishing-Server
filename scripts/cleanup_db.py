"""
AntiPhishing - Database Cleanup Utility
Deletes records that haven't been updated in over X days.
Phishing sites have a short lifespan, so old records are safely removed to save space.

Usage:
    python scripts/cleanup_db.py [--days 90]
"""

import os
import argparse
import logging
from datetime import datetime, timedelta, timezone

try:
    from pymongo import MongoClient
except ImportError:
    import sys

    sys.exit("pymongo not installed. Run: pip install pymongo")

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cleanup")

DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_DB_NAME = "antiphishing"

COLLECTION_URLS = "malicious_urls"
COLLECTION_DOMAINS = "malicious_domains"
COLLECTION_CACHE = "checked_urls_cache"


def run_cleanup(mongo_uri: str, db_name: str, days_old: int):
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db = client[db_name]

    # Calculate the decisive date (X days ago from now)
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
    log.info(
        f"Connected to DB. Searching for records older than {cutoff_date.strftime('%Y-%m-%d')} ({days_old} days)...")

    # The query that finds every document whose updated_at field is less than (older than) the specified date
    query = {"updated_at": {"$lt": cutoff_date}}

    # 1. URL cleaning
    urls_result = db[COLLECTION_URLS].delete_many(query)
    log.info(f"Deleted {urls_result.deleted_count:,} outdated URLs.")

    # 2. Domain cleaning
    domains_result = db[COLLECTION_DOMAINS].delete_many(query)
    log.info(f"Deleted {domains_result.deleted_count:,} outdated Domains.")

    # 3. Cache cleaning
    cache_query = {"cached_at": {"$lt": cutoff_date}}
    cache_result = db[COLLECTION_CACHE].delete_many(cache_query)
    log.info(f"Deleted {cache_result.deleted_count:,} outdated Cache entries.")

    log.info("=" * 50)
    log.info("Cleanup complete!")
    log.info("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AntiPhishing DB Cleanup")
    parser.add_argument("--mongo-uri", default=os.environ.get("MONGO_URI", DEFAULT_MONGO_URI))
    parser.add_argument("--db", default=os.environ.get("DB_NAME", DEFAULT_DB_NAME))
    parser.add_argument("--days", type=int, default=90,
                        help="Number of days before a record is considered outdated (default: 90)")

    args = parser.parse_args()

    run_cleanup(args.mongo_uri, args.db, args.days)
