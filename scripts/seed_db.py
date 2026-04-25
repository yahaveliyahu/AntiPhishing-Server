"""
AntiPhishing - Phase 1: MongoDB Seeder
Populates MongoDB with malicious URLs from:
  1. Public Blacklists (PhishTank, OpenPhish, URLhaus, abuse.ch)
  2. Threat Intelligence Databases (AlienVault OTX, Feodo Tracker, etc.)
  3. Known malicious domain lists

Usage:
    python seed_db.py [--mongo-uri MONGO_URI] [--db DB_NAME] [--clear]

Environment variables:
    MONGO_URI          - MongoDB connection string (default: mongodb://localhost:27017)
    DB_NAME            - Database name (default: antiphishing)
    PHISHTANK_API_KEY  - PhishTank API key (free at phishtank.org)
    OTX_API_KEY        - AlienVault OTX API key (free at otx.alienvault.com)
"""

import argparse
import csv
import gzip
import io
import json
import logging
import os
import re
import sys
import time
import cloudscraper
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

try:
    from pymongo import MongoClient, ASCENDING, UpdateOne
    from pymongo.errors import BulkWriteError, ConnectionFailure
except ImportError:
    sys.exit("pymongo not installed. Run: pip install pymongo")

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("seeder")

# ─── Constants ──────────────────────────────────────────────────────────────
DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_DB_NAME = "antiphishing"
COLLECTION_URLS = "malicious_urls"
COLLECTION_DOMAINS = "malicious_domains"
COLLECTION_META = "feed_metadata"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ─── Feed Definitions ────────────────────────────────────────────────────────
# Each feed dict:
#   url      - where to fetch
#   name     - display / source tag
#   format   - "csv", "json", "txt", "tsv"
#   parser   - function name string (resolved below)
#   enabled  - bool (some require API keys – disabled by default)

FEEDS = [
    # ── Blacklists ────────────────────────────────────────────────
    {
        "name": "PhishTank",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "format": "json",
        "parser": "parse_phishtank_json",
        "enabled": True,
        "type": "blacklist",
        "description": "Community-verified phishing URLs from PhishTank (Public JSON)",
        "extra_headers": {"Referer": "https://www.phishtank.com/", "App-Key": ""},
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "format": "txt",
        "parser": "parse_plain_urls",
        "enabled": True,
        "type": "blacklist",
        "description": "OpenPhish free phishing URL feed",
        "ssl_verify": False,
    },
    {
        "name": "URLhaus_URLs",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "format": "txt",
        "parser": "parse_plain_urls",
        "enabled": True,
        "type": "blacklist",
        "description": "Abuse.ch URLhaus malware URLs (text feed)",
    },
    {
        "name": "URLhaus_Domains",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "format": "txt",
        "parser": "parse_hosts_file",
        "enabled": True,
        "type": "blacklist",
        "description": "Abuse.ch URLhaus malware domains (hosts file)",
    },
    {
        "name": "abuse.ch_SSLBL",
        "url": "https://sslbl.abuse.ch/blacklist/dstip.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "blacklist",
        "description": "Abuse.ch SSL Blacklist - malicious destination IPs",
    },
    {
        "name": "Phishing_Army",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": True,
        "type": "blacklist",
        "description": "Phishing Army extended domain blocklist",
    },
    {
        "name": "OISD_Basic",
        "url": "https://abp.oisd.nl/basic/",
        "format": "txt",
        "parser": "parse_abp_filter",
        "enabled": False,
        "type": "blacklist",
        "description": "OISD basic ad/malware domain blocklist",
    },
    {
        "name": "Phishing_Database",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": True,
        "type": "blacklist",
        "description": "Mitchell Krogza active phishing domains database",
    },
    {
        "name": "StevenBlack_Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "txt",
        "parser": "parse_hosts_file",
        "enabled": False,
        "type": "blacklist",
        "description": "StevenBlack unified hosts (adware + malware)",
    },
    {
        "name": "Hagezi_Pro",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "blacklist",
        "description": "Hagezi Pro DNS blocklist",
    },
    # ── Threat Intelligence ───────────────────────────────────────
    {
        "name": "Hagezi_TIF",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "threat_intel",
        "description": "Hagezi Threat Intelligence Feeds",
    },
    {
        "name": "Feodo_Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "format": "csv",
        "parser": "parse_feodo",
        "enabled": False,
        "type": "threat_intel",
        "description": "Feodo Tracker C2 IP blocklist",
    },
    {
        "name": "Feodo_Recommended",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "threat_intel",
        "description": "Feodo Tracker recommended IP blocklist",
    },
    {
        "name": "DisconnectMe_Malware",
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": True,
        "type": "threat_intel",
        "description": "Disconnect.me malware domains",
    },
    {
        "name": "DisconnectMe_Tracking",
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "threat_intel",
        "description": "Disconnect.me tracking domains",
    },
    {
        "name": "Malware_Domain_List",
        "url": "https://www.malwaredomainlist.com/hostslist/hosts.txt",
        "format": "txt",
        "parser": "parse_hosts_file",
        "enabled": False,
        "type": "threat_intel",
        "description": "Malware Domain List hosts file",
    },
    {
        "name": "Ultimate_Hosts_Blacklist",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Ultimate.Hosts.Blacklist/master/hosts/hosts0",
        "format": "txt",
        "parser": "parse_hosts_file",
        "enabled": True,
        "type": "threat_intel",
        "description": "Ultimate Hosts Blacklist (malware domains)",
    },
    {
        "name": "Botvrij_Domains",
        "url": "https://www.botvrij.eu/data/ioclist.domain.raw",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": True,
        "type": "threat_intel",
        "description": "Botvrij.eu IOC domain list",
    },
    {
        "name": "Botvrij_URLs",
        "url": "https://www.botvrij.eu/data/ioclist.url.raw",
        "format": "txt",
        "parser": "parse_plain_urls",
        "enabled": True,
        "type": "threat_intel",
        "description": "Botvrij.eu IOC URL list",
    },
    {
        "name": "CINS_Score",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "format": "txt",
        "parser": "parse_plain_domains",
        "enabled": False,
        "type": "threat_intel",
        "description": "CINS Score bad IP list",
    },
    # ── Requires API key – disabled by default ─────────────────────
    {
        "name": "AlienVault_OTX",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "format": "json",
        "parser": "parse_otx",
        "enabled": True,   # Set OTX_API_KEY env var and change to True
        "api_key_env": "OTX_API_KEY",
        "type": "threat_intel",
        "description": "AlienVault OTX subscribed pulses (requires free API key)",
    },
]


# ─── URL / Domain Normalisation ──────────────────────────────────────────────

def normalize_url(raw: str) -> str | None:
    """
    Lowercase, strip tracking params, decode, extract clean URL.
    Returns None if the input cannot be parsed into a valid URL.
    """
    raw = raw.strip()
    if not raw or raw.startswith("#") or raw.startswith("//"):
        return None
    # Ensure scheme
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        if not parsed.netloc:
            return None
        # Lowercase host
        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
        )
        return urlunparse(normalized)
    except Exception:
        return None


def extract_domain(url: str) -> str | None:
    """Extract bare domain (no port, no www prefix) from a URL or hostname."""
    url = url.strip()
    if not url or url.startswith("#"):
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower() or None
    except Exception:
        return None


# ─── Feed Parsers ─────────────────────────────────────────────────────────────

def parse_phishtank_json(content: bytes, feed: dict) -> list[dict]:
    """PhishTank JSON (Public): phish_id, url, verified, submission_time, target"""
    records = []
    try:
        # Convert the received content to a Python dictionary
        data = json.loads(content)

        for row in data:
            url = normalize_url(row.get("url", ""))
            if not url:
                continue

            records.append({
                "url": url,
                "domain": extract_domain(url),
                "source": feed["name"],
                "type": feed["type"],
                "extra": {
                    "phish_id": row.get("phish_id"),
                    "verified": row.get("verified") == "yes",
                    "submitted": row.get("submission_time"),
                    "target": row.get("target"),
                },
            })
    except Exception as e:
        log.warning(f"PhishTank JSON parse error: {e}")

    return records


def parse_plain_urls(content: bytes, feed: dict) -> list[dict]:
    """One URL per line, ignore comment lines."""
    records = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        url = normalize_url(line)
        if url:
            records.append({
                "url": url,
                "domain": extract_domain(url),
                "source": feed["name"],
                "type": feed["type"],
                "extra": {},
            })
    return records


def parse_plain_domains(content: bytes, feed: dict) -> list[dict]:
    """One domain per line."""
    records = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue
        # Skip lines with spaces unless it is a hosts file style entry
        if " " in line and not line.startswith(("0.0.0.0", "127.0.0.1")):
            continue
        # Handle hosts file style lines within plain domain lists
        parts = line.split()
        candidate = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
        domain = extract_domain(candidate)
        if domain and domain not in ("localhost", "local", "broadcasthost", "0.0.0.0", "127.0.0.1"):
            records.append({
                "domain": domain,
                "source": feed["name"],
                "type": feed["type"],
                "extra": {},
            })
    return records


def parse_hosts_file(content: bytes, feed: dict) -> list[dict]:
    """Hosts file format: 0.0.0.0 malicious.domain.com"""
    records = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domain = extract_domain(parts[1])
            if domain and domain not in ("localhost", "broadcasthost", "local", "0.0.0.0"):
                records.append({
                    "domain": domain,
                    "source": feed["name"],
                    "type": feed["type"],
                    "extra": {},
                })
    return records


def parse_feodo(content: bytes, feed: dict) -> list[dict]:
    """Feodo Tracker IP CSV: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware"""
    records = []
    text = content.decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if not l.startswith("#")]
    if not lines:
        return records
    reader = csv.DictReader(lines)
    for row in reader:
        ip = row.get("dst_ip", "").strip()
        if ip:
            records.append({
                "domain": ip,
                "source": feed["name"],
                "type": feed["type"],
                "extra": {
                    "port": row.get("dst_port"),
                    "malware": row.get("malware"),
                    "status": row.get("c2_status"),
                    "first_seen": row.get("first_seen_utc"),
                },
            })
    return records


def parse_urlhaus(content: bytes, feed: dict) -> list[dict]:
    """URLhaus CSV: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter"""
    records = []
    text = content.decode("utf-8", errors="replace")
    # Skip header comment lines
    lines = [l for l in text.splitlines() if not l.startswith("#")]
    if not lines:
        return records
    reader = csv.DictReader(lines)
    for row in reader:
        url = normalize_url(row.get("url", ""))
        if not url:
            continue
        records.append({
            "url": url,
            "domain": extract_domain(url),
            "source": feed["name"],
            "type": feed["type"],
            "extra": {
                "status": row.get("url_status"),
                "threat": row.get("threat"),
                "tags": row.get("tags"),
                "date_added": row.get("dateadded"),
            },
        })
    return records


def parse_sslbl(content: bytes, feed: dict) -> list[dict]:
    """SSL Blacklist CSV: Listingdate, SHA1, Listingreason"""
    records = []
    text = content.decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if not l.startswith("#")]
    if not lines:
        return records
    reader = csv.DictReader(lines)
    for row in reader:
        sha1 = row.get("SHA1", "").strip()
        if sha1:
            records.append({
                "domain": sha1,   # stored as identifier
                "source": feed["name"],
                "type": feed["type"],
                "extra": {
                    "sha1": sha1,
                    "reason": row.get("Listingreason"),
                    "date": row.get("Listingdate"),
                },
            })
    return records


def parse_abp_filter(content: bytes, feed: dict) -> list[dict]:
    """AdBlock Plus filter list – extract ||domain^ style rules."""
    records = []
    pattern = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^")
    for line in content.decode("utf-8", errors="replace").splitlines():
        m = pattern.match(line.strip())
        if m:
            domain = m.group(1).lower()
            if domain:
                records.append({
                    "domain": domain,
                    "source": feed["name"],
                    "type": feed["type"],
                    "extra": {},
                })
    return records


def parse_otx(content: bytes, feed: dict) -> list[dict]:
    """AlienVault OTX pulse API (JSON)."""
    records = []
    try:
        data = json.loads(content)
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                itype = indicator.get("type", "")
                value = indicator.get("indicator", "").strip()
                if not value:
                    continue
                if itype in ("URL", "FileHash-URL"):
                    url = normalize_url(value)
                    if url:
                        records.append({
                            "url": url,
                            "domain": extract_domain(url),
                            "source": feed["name"],
                            "type": feed["type"],
                            "extra": {"pulse": pulse.get("name"), "itype": itype},
                        })
                elif itype in ("domain", "hostname", "FQDN"):
                    domain = extract_domain(value)
                    if domain:
                        records.append({
                            "domain": domain,
                            "source": feed["name"],
                            "type": feed["type"],
                            "extra": {"pulse": pulse.get("name"), "itype": itype},
                        })
    except Exception as e:
        log.warning(f"OTX parse error: {e}")
    return records


# Map parser name → function
PARSERS = {
    "parse_phishtank_json": parse_phishtank_json,
    "parse_plain_urls":  parse_plain_urls,
    "parse_plain_domains": parse_plain_domains,
    "parse_hosts_file":  parse_hosts_file,
    "parse_urlhaus":     parse_urlhaus,
    "parse_sslbl":       parse_sslbl,
    "parse_feodo":       parse_feodo,
    "parse_abp_filter":  parse_abp_filter,
    "parse_otx":         parse_otx,
}


# ─── Fetch ────────────────────────────────────────────────────────────────────

def fetch_feed(feed: dict, timeout: int = 60) -> bytes | None:
    headers = dict(HEADERS)
    url = feed["url"]

    if feed.get("api_in_url") and "api_key_env" in feed:
        key = os.environ.get(feed["api_key_env"], "")
        if not key:
            log.warning(
                f"[{feed['name']}] Skipped – set env var {feed['api_key_env']}. "
                f"Get a free key at phishtank.org"
            )
            return None
        url = url.replace("{" + feed["api_key_env"] + "}", key)
    elif "api_key_env" in feed:
        key = os.environ.get(feed["api_key_env"], "")
        if not key:
            log.warning(f"[{feed['name']}] Skipped – set {feed['api_key_env']} env var")
            return None
        headers["X-OTX-API-KEY"] = key

    # Update here to url instead of feed['url'] so that it displays the real address if there is an API
    log.info(f"[{feed['name']}] Fetching {feed['url']}")
    try:
        # Create a scraper that simulates a Chrome browser to bypass blocks (like Cloudflare)
        scraper = cloudscraper.create_scraper(browser={
            'browser': 'chrome',
            'platform': 'windows',
            'desktop': True
        })
        # Sending the request through the scraper
        response = scraper.get(url, headers=headers, timeout=timeout)

        # If the request was successful
        if response.status_code == 200:
            return response.content
        else:
            log.warning(f"[{feed['name']}] HTTP {response.status_code}: {response.reason}")
            return None

    except Exception as e:
        log.warning(f"[{feed['name']}] Error: {e}")
    return None


# ─── MongoDB Helpers ──────────────────────────────────────────────────────────

def get_db(mongo_uri: str, db_name: str):
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        log.info(f"Connected to MongoDB at {mongo_uri}")
    except ConnectionFailure:
        sys.exit(f"Cannot connect to MongoDB at {mongo_uri}. Is it running?")
    return client[db_name]


def ensure_indexes(db):
    """Create indexes for fast lookup (the core Phase 1 check)."""
    db[COLLECTION_URLS].create_index([("url", ASCENDING)], unique=True, sparse=True)
    db[COLLECTION_URLS].create_index([("domain", ASCENDING)], sparse=True)
    db[COLLECTION_URLS].create_index([("source", ASCENDING)])

    db[COLLECTION_DOMAINS].create_index([("domain", ASCENDING)], unique=True)
    db[COLLECTION_DOMAINS].create_index([("sources", ASCENDING)])

    log.info("Indexes ensured")


def upsert_records(db, records: list[dict]) -> tuple[int, int]:
    """
    Upsert into two collections:
      - malicious_urls   (records that have a 'url' field)
      - malicious_domains (all records, keyed by domain)

    Returns (url_upserts, domain_upserts).
    """
    now = datetime.now(timezone.utc)
    url_ops, dom_ops = [], []

    for r in records:
        url    = r.get("url")
        domain = r.get("domain")
        source = r["source"]

        if url:
            url_ops.append(UpdateOne(
                {"url": url},
                {"$set": {
                    "url": url,
                    "domain": domain,
                    "source": source,
                    "type": r["type"],
                    "extra": r.get("extra", {}),
                    "updated_at": now,
                }, "$setOnInsert": {"created_at": now}},
                upsert=True,
            ))

        if domain:
            dom_ops.append(UpdateOne(
                {"domain": domain},
                {
                    "$addToSet": {"sources": source},
                    "$set": {"type": r["type"], "updated_at": now},
                    "$setOnInsert": {"domain": domain, "created_at": now},
                },
                upsert=True,
            ))

    url_count = dom_count = 0

    if url_ops:
        try:
            result = db[COLLECTION_URLS].bulk_write(url_ops, ordered=False)
            url_count = result.upserted_count + result.modified_count
        except BulkWriteError as bwe:
            url_count = bwe.details.get("nUpserted", 0) + bwe.details.get("nModified", 0)

    if dom_ops:
        try:
            result = db[COLLECTION_DOMAINS].bulk_write(dom_ops, ordered=False)
            dom_count = result.upserted_count + result.modified_count
        except BulkWriteError as bwe:
            dom_count = bwe.details.get("nUpserted", 0) + bwe.details.get("nModified", 0)

    return url_count, dom_count


def log_feed_run(db, feed: dict, records_count: int, success: bool, error: str = ""):
    db[COLLECTION_META].update_one(
        {"feed_name": feed["name"]},
        {"$set": {
            "feed_name": feed["name"],
            "url": feed["url"],
            "type": feed["type"],
            "description": feed.get("description", ""),
            "last_run": datetime.now(timezone.utc),
            "last_count": records_count,
            "success": success,
            "error": error,
        }, "$inc": {"total_runs": 1}},
        upsert=True,
    )


# ─── Main ─────────────────────────────────────────────────────────────────────

def run(mongo_uri: str, db_name: str, clear: bool = False, feeds_filter: list[str] | None = None):
    db = get_db(mongo_uri, db_name)

    if clear:
        log.warning("--clear specified: dropping existing collections")
        db[COLLECTION_URLS].drop()
        db[COLLECTION_DOMAINS].drop()

    ensure_indexes(db)

    total_urls = 0
    total_domains = 0
    feeds_run = 0

    for feed in FEEDS:
        if not feed["enabled"]:
            log.info(f"[{feed['name']}] Disabled – skipping")
            continue
        if feeds_filter and feed["name"] not in feeds_filter:
            continue

        parser_fn = PARSERS.get(feed["parser"])
        if not parser_fn:
            log.error(f"[{feed['name']}] Unknown parser: {feed['parser']}")
            continue

        content = fetch_feed(feed)
        if content is None:
            log_feed_run(db, feed, 0, False, "fetch failed")
            continue

        try:
            records = parser_fn(content, feed)
        except Exception as e:
            log.error(f"[{feed['name']}] Parse error: {e}")
            log_feed_run(db, feed, 0, False, str(e))
            continue

        if not records:
            log.warning(f"[{feed['name']}] No records parsed")
            log_feed_run(db, feed, 0, True, "no records")
            continue

        urls_written, doms_written = upsert_records(db, records)
        total_urls += urls_written
        total_domains += doms_written
        feeds_run += 1
        log_feed_run(db, feed, len(records), True)
        log.info(
            f"[{feed['name']}] Parsed {len(records):,} records "
            f"→ {urls_written:,} URL upserts, {doms_written:,} domain upserts"
        )

        time.sleep(0.5)   # polite delay between fetches

    # ── Summary ──────────────────────────────────────────────────
    url_total  = db[COLLECTION_URLS].count_documents({})
    dom_total  = db[COLLECTION_DOMAINS].count_documents({})
    log.info("=" * 60)
    log.info(f"Seeding complete. Feeds processed: {feeds_run}")
    log.info(f"  malicious_urls    collection: {url_total:,} documents")
    log.info(f"  malicious_domains collection: {dom_total:,} documents")
    log.info("=" * 60)


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AntiPhishing DB Seeder – Phase 1")
    parser.add_argument("--mongo-uri", default=os.environ.get("MONGO_URI", DEFAULT_MONGO_URI))
    parser.add_argument("--db",        default=os.environ.get("DB_NAME",    DEFAULT_DB_NAME))
    parser.add_argument("--clear",     action="store_true", help="Drop existing collections before seeding")
    parser.add_argument("--feeds",     nargs="+", help="Run only specific feeds by name")
    args = parser.parse_args()

    run(args.mongo_uri, args.db, args.clear, args.feeds)
