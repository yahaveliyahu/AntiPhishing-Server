"""
AntiPhishing - Automatic Scheduler
====================================
Runs automatically in the background:
  - Every 12 hours  → seed_db.py   (fetch new malicious URLs from all feeds)
  - Every 7 days    → cleanup_db.py (delete records older than 90 days)

Usage:
    python scripts/scheduler.py

Environment variables (same as seed_db.py):
    MONGO_URI  - MongoDB connection string
    DB_NAME    - Database name
"""

import os
import sys
import logging
import schedule
import time
from datetime import datetime, timezone

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scheduler")

# ─── Import our own scripts ──────────────────────────────────────────────────
# Add scripts folder to path so we can import seed_db and cleanup_db
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import seed_db
import cleanup_db

# ─── Config ──────────────────────────────────────────────────────────────────
MONGO_URI     = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME       = os.environ.get("DB_NAME",   "antiphishing")
CLEANUP_DAYS  = int(os.environ.get("CLEANUP_DAYS", "90"))


# ─── Tasks ───────────────────────────────────────────────────────────────────

def run_seed():
    """Fetch new malicious URLs from all feeds and upsert into MongoDB."""
    log.info("=" * 60)
    log.info(f"[SCHEDULER] Starting scheduled seed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    log.info("=" * 60)
    try:
        seed_db.run(MONGO_URI, DB_NAME, clear=False)
        log.info("[SCHEDULER] Seed completed successfully")
    except Exception as e:
        log.error(f"[SCHEDULER] Seed failed: {e}")


def run_cleanup():
    """Delete records older than CLEANUP_DAYS days."""
    log.info("=" * 60)
    log.info(f"[SCHEDULER] Starting scheduled cleanup at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    log.info(f"[SCHEDULER] Removing records older than {CLEANUP_DAYS} days")
    log.info("=" * 60)
    try:
        cleanup_db.run_cleanup(MONGO_URI, DB_NAME, CLEANUP_DAYS)
        log.info("[SCHEDULER] Cleanup completed successfully")
    except Exception as e:
        log.error(f"[SCHEDULER] Cleanup failed: {e}")


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("AntiPhishing Scheduler starting...")
    log.info(f"  MongoDB:      {MONGO_URI}")
    log.info(f"  Database:     {DB_NAME}")
    log.info(f"  Seed:         every 12 hours")
    log.info(f"  Cleanup:      every 7 days (removes records older than {CLEANUP_DAYS} days)")

    # ── Run both tasks immediately on startup ─────────────────────
    log.info("[SCHEDULER] Running initial seed on startup...")
    run_seed()

    log.info("[SCHEDULER] Running initial cleanup on startup...")
    run_cleanup()

    # ── Schedule recurring tasks ──────────────────────────────────
    schedule.every(12).hours.do(run_seed)
    schedule.every(7).days.do(run_cleanup)

    log.info("[SCHEDULER] Scheduler is running. Press Ctrl+C to stop.")
    log.info(f"  Next seed:    {schedule.next_run()}")

    # ── Keep running forever ──────────────────────────────────────
    while True:
        schedule.run_pending()
        time.sleep(60)   # check every minute
