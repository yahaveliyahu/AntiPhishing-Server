"""
AntiPhishing – Phase 1: Whitelist Seeder
==========================================
Populates MongoDB with known safe/legitimate domains.

The whitelist serves as a fast-path in the lookup pipeline:
    URL comes in
        ↓
    Check whitelist → Found? → Return "safe" immediately (skip all analysis)
        ↓ Not found
    Check blacklist → Found? → Return "malicious"
        ↓ Not found
    Heuristic + ML analysis (Phase 2)

Why a whitelist?
  - Facebook, Google, Ynet etc. will NEVER be phishing sites
  - Checking them against 675k blacklist entries wastes time
  - Whitelisted domains are permanent — they don't need cleanup
  - Also protects against false positives in the blacklist

Usage:
    python scripts/seed_whitelist.py

Environment variables (same as seed_db.py):
    MONGO_URI  - MongoDB connection string
    DB_NAME    - Database name
"""

import os
import sys
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

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
log = logging.getLogger("whitelist")

DEFAULT_MONGO_URI  = "mongodb://localhost:27017"
DEFAULT_DB_NAME    = "antiphishing"
COLLECTION_WHITELIST = "whitelisted_domains"

# ─── Whitelist Data ───────────────────────────────────────────────────────────
# Format: { "domain": "example.com", "category": "...", "description": "..." }
# Only the root domain — subdomains are matched automatically in lookup.py

WHITELIST = [

    # ══════════════════════════════════════════════════════════════
    # SOCIAL MEDIA
    # ══════════════════════════════════════════════════════════════
    {"domain": "facebook.com",      "category": "social_media",   "description": "Facebook"},
    {"domain": "instagram.com",     "category": "social_media",   "description": "Instagram"},
    {"domain": "twitter.com",       "category": "social_media",   "description": "Twitter / X"},
    {"domain": "x.com",             "category": "social_media",   "description": "X (Twitter)"},
    {"domain": "linkedin.com",      "category": "social_media",   "description": "LinkedIn"},
    {"domain": "tiktok.com",        "category": "social_media",   "description": "TikTok"},
    {"domain": "snapchat.com",      "category": "social_media",   "description": "Snapchat"},
    {"domain": "pinterest.com",     "category": "social_media",   "description": "Pinterest"},
    {"domain": "reddit.com",        "category": "social_media",   "description": "Reddit"},
    {"domain": "tumblr.com",        "category": "social_media",   "description": "Tumblr"},
    {"domain": "whatsapp.com",      "category": "social_media",   "description": "WhatsApp"},
    {"domain": "telegram.org",      "category": "social_media",   "description": "Telegram"},
    {"domain": "discord.com",       "category": "social_media",   "description": "Discord"},
    {"domain": "threads.net",       "category": "social_media",   "description": "Threads"},

    # ══════════════════════════════════════════════════════════════
    # SEARCH ENGINES
    # ══════════════════════════════════════════════════════════════
    {"domain": "google.com",        "category": "search_engine",  "description": "Google"},
    {"domain": "google.co.il",      "category": "search_engine",  "description": "Google Israel"},
    {"domain": "bing.com",          "category": "search_engine",  "description": "Microsoft Bing"},
    {"domain": "yahoo.com",         "category": "search_engine",  "description": "Yahoo"},
    {"domain": "duckduckgo.com",    "category": "search_engine",  "description": "DuckDuckGo"},
    {"domain": "yandex.com",        "category": "search_engine",  "description": "Yandex"},
    {"domain": "baidu.com",         "category": "search_engine",  "description": "Baidu"},

    # ══════════════════════════════════════════════════════════════
    # EMAIL PROVIDERS
    # ══════════════════════════════════════════════════════════════
    {"domain": "gmail.com",         "category": "email",          "description": "Gmail"},
    {"domain": "mail.google.com",   "category": "email",          "description": "Gmail Web"},
    {"domain": "outlook.com",       "category": "email",          "description": "Microsoft Outlook"},
    {"domain": "hotmail.com",       "category": "email",          "description": "Hotmail"},
    {"domain": "live.com",          "category": "email",          "description": "Microsoft Live"},
    {"domain": "yahoo.com",         "category": "email",          "description": "Yahoo Mail"},
    {"domain": "protonmail.com",    "category": "email",          "description": "ProtonMail"},
    {"domain": "icloud.com",        "category": "email",          "description": "Apple iCloud Mail"},
    {"domain": "walla.co.il",       "category": "email",          "description": "Walla Mail (Israel)"},

    # ══════════════════════════════════════════════════════════════
    # TECH GIANTS
    # ══════════════════════════════════════════════════════════════
    {"domain": "microsoft.com",     "category": "tech",           "description": "Microsoft"},
    {"domain": "apple.com",         "category": "tech",           "description": "Apple"},
    {"domain": "amazon.com",        "category": "tech",           "description": "Amazon"},
    {"domain": "amazon.co.il",      "category": "tech",           "description": "Amazon Israel"},
    {"domain": "netflix.com",       "category": "tech",           "description": "Netflix"},
    {"domain": "spotify.com",       "category": "tech",           "description": "Spotify"},
    {"domain": "adobe.com",         "category": "tech",           "description": "Adobe"},
    {"domain": "zoom.us",           "category": "tech",           "description": "Zoom"},
    {"domain": "dropbox.com",       "category": "tech",           "description": "Dropbox"},
    {"domain": "github.com",        "category": "tech",           "description": "GitHub"},
    {"domain": "stackoverflow.com", "category": "tech",           "description": "Stack Overflow"},
    {"domain": "wordpress.com",     "category": "tech",           "description": "WordPress"},

    # ══════════════════════════════════════════════════════════════
    # GOOGLE SERVICES
    # ══════════════════════════════════════════════════════════════
    {"domain": "youtube.com",       "category": "google_services","description": "YouTube"},
    {"domain": "maps.google.com",   "category": "google_services","description": "Google Maps"},
    {"domain": "drive.google.com",  "category": "google_services","description": "Google Drive"},
    {"domain": "docs.google.com",   "category": "google_services","description": "Google Docs"},
    {"domain": "play.google.com",   "category": "google_services","description": "Google Play"},
    {"domain": "accounts.google.com","category":"google_services","description": "Google Accounts"},
    {"domain": "googletagmanager.com","category":"google_services","description": "Google Tag Manager"},
    {"domain": "googleapis.com",    "category": "google_services","description": "Google APIs"},
    {"domain": "gstatic.com",       "category": "google_services","description": "Google Static CDN"},
    {"domain": "googlevideo.com",   "category": "google_services","description": "Google Video CDN"},

    # ══════════════════════════════════════════════════════════════
    # MICROSOFT SERVICES
    # ══════════════════════════════════════════════════════════════
    {"domain": "office.com",        "category": "microsoft",      "description": "Microsoft Office"},
    {"domain": "office365.com",     "category": "microsoft",      "description": "Microsoft Office 365"},
    {"domain": "microsoftonline.com","category": "microsoft",     "description": "Microsoft Online Login"},
    {"domain": "azure.com",         "category": "microsoft",      "description": "Microsoft Azure"},
    {"domain": "sharepoint.com",    "category": "microsoft",      "description": "Microsoft SharePoint"},
    {"domain": "teams.microsoft.com","category": "microsoft",     "description": "Microsoft Teams"},
    {"domain": "skype.com",         "category": "microsoft",      "description": "Skype"},
    {"domain": "windowsupdate.com", "category": "microsoft",      "description": "Windows Update"},

    # ══════════════════════════════════════════════════════════════
    # BANKING & FINANCE (ISRAEL)
    # ══════════════════════════════════════════════════════════════
    {"domain": "bankhapoalim.co.il","category": "banking_il",     "description": "Bank Hapoalim Israel"},
    {"domain": "bankleumi.co.il",   "category": "banking_il",     "description": "Bank Leumi Israel"},
    {"domain": "mizrahi-tefahot.co.il","category":"banking_il",   "description": "Mizrahi Tefahot Bank"},
    {"domain": "discountbank.co.il","category": "banking_il",     "description": "Discount Bank Israel"},
    {"domain": "fibi.co.il",        "category": "banking_il",     "description": "First International Bank Israel"},
    {"domain": "max.co.il",         "category": "banking_il",     "description": "Max Credit Cards Israel"},
    {"domain": "cal.co.il",         "category": "banking_il",     "description": "Cal Credit Cards Israel"},
    {"domain": "isracard.co.il",    "category": "banking_il",     "description": "Isracard"},
    {"domain": "otsar-hahayal.co.il","category":"banking_il",     "description": "Otsar Hahayal Bank"},
    {"domain": "pelecard.com",      "category": "banking_il",     "description": "Pelecard Payment"},
    {"domain": "paybox.co.il",      "category": "banking_il",     "description": "Paybox Israel"},
    {"domain": "bit.co.il",         "category": "banking_il",     "description": "Bit Payment App Israel"},

    # ══════════════════════════════════════════════════════════════
    # BANKING & FINANCE (GLOBAL)
    # ══════════════════════════════════════════════════════════════
    {"domain": "paypal.com",        "category": "banking_global", "description": "PayPal"},
    {"domain": "paypal.me",         "category": "banking_global", "description": "PayPal.me"},
    {"domain": "stripe.com",        "category": "banking_global", "description": "Stripe Payments"},
    {"domain": "visa.com",          "category": "banking_global", "description": "Visa"},
    {"domain": "mastercard.com",    "category": "banking_global", "description": "Mastercard"},
    {"domain": "americanexpress.com","category":"banking_global", "description": "American Express"},
    {"domain": "chase.com",         "category": "banking_global", "description": "Chase Bank"},
    {"domain": "bankofamerica.com", "category": "banking_global", "description": "Bank of America"},
    {"domain": "wellsfargo.com",    "category": "banking_global", "description": "Wells Fargo"},

    # ══════════════════════════════════════════════════════════════
    # ISRAELI NEWS & MEDIA
    # ══════════════════════════════════════════════════════════════
    {"domain": "ynet.co.il",        "category": "news_il",        "description": "Ynet News Israel"},
    {"domain": "haaretz.co.il",     "category": "news_il",        "description": "Haaretz Israel"},
    {"domain": "maariv.co.il",      "category": "news_il",        "description": "Maariv Israel"},
    {"domain": "calcalist.co.il",   "category": "news_il",        "description": "Calcalist Israel"},
    {"domain": "walla.co.il",       "category": "news_il",        "description": "Walla Israel"},
    {"domain": "nrg.co.il",         "category": "news_il",        "description": "NRG Israel"},
    {"domain": "sport5.co.il",      "category": "news_il",        "description": "Sport5 Israel"},
    {"domain": "kan.org.il",        "category": "news_il",        "description": "Kan Israeli Broadcasting"},
    {"domain": "reshet.tv",         "category": "news_il",        "description": "Reshet TV Israel"},
    {"domain": "keshet12.com",      "category": "news_il",        "description": "Keshet 12 Israel"},
    {"domain": "13tv.co.il",        "category": "news_il",        "description": "Channel 13 Israel"},
    {"domain": "now14.co.il",       "category": "news_il",        "description": "Channel 14 Israel"},

    # ══════════════════════════════════════════════════════════════
    # GLOBAL NEWS MEDIA
    # ══════════════════════════════════════════════════════════════
    {"domain": "bbc.com",           "category": "news_global",    "description": "BBC"},
    {"domain": "bbc.co.uk",         "category": "news_global",    "description": "BBC UK"},
    {"domain": "cnn.com",           "category": "news_global",    "description": "CNN"},
    {"domain": "nytimes.com",       "category": "news_global",    "description": "New York Times"},
    {"domain": "reuters.com",       "category": "news_global",    "description": "Reuters"},
    {"domain": "theguardian.com",   "category": "news_global",    "description": "The Guardian"},
    {"domain": "washingtonpost.com","category": "news_global",    "description": "Washington Post"},
    {"domain": "foxnews.com",       "category": "news_global",    "description": "Fox News"},
    {"domain": "apnews.com",        "category": "news_global",    "description": "AP News"},

    # ══════════════════════════════════════════════════════════════
    # ISRAELI GOVERNMENT & SERVICES
    # ══════════════════════════════════════════════════════════════
    {"domain": "gov.il",            "category": "government_il",  "description": "Israeli Government Portal"},
    {"domain": "btl.gov.il",        "category": "government_il",  "description": "Bituach Leumi (National Insurance)"},
    {"domain": "misrad-hapnim.gov.il","category":"government_il", "description": "Ministry of Interior Israel"},
    {"domain": "taxes.gov.il",      "category": "government_il",  "description": "Israel Tax Authority"},
    {"domain": "iaa.gov.il",        "category": "government_il",  "description": "Israel Airports Authority"},
    {"domain": "piba.gov.il",       "category": "government_il",  "description": "Israel Population Authority"},
    {"domain": "health.gov.il",     "category": "government_il",  "description": "Israel Ministry of Health"},
    {"domain": "mof.gov.il",        "category": "government_il",  "description": "Israel Ministry of Finance"},
    {"domain": "police.gov.il",     "category": "government_il",  "description": "Israel Police"},
    {"domain": "army.idf.il",       "category": "government_il",  "description": "IDF Israel"},

    # ══════════════════════════════════════════════════════════════
    # ISRAELI HMO / HEALTH
    # ══════════════════════════════════════════════════════════════
    {"domain": "clalit.co.il",      "category": "health_il",      "description": "Clalit Health Services"},
    {"domain": "maccabi4u.co.il",   "category": "health_il",      "description": "Maccabi Healthcare"},
    {"domain": "meuhedet.co.il",    "category": "health_il",      "description": "Meuhedet HMO"},
    {"domain": "leumit.co.il",      "category": "health_il",      "description": "Leumit Health Services"},

    # ══════════════════════════════════════════════════════════════
    # ISRAELI E-COMMERCE & SHOPPING
    # ══════════════════════════════════════════════════════════════
    {"domain": "zap.co.il",         "category": "ecommerce_il",   "description": "Zap Price Comparison Israel"},
    {"domain": "ivory.co.il",       "category": "ecommerce_il",   "description": "Ivory Tech Israel"},
    {"domain": "ksp.co.il",         "category": "ecommerce_il",   "description": "KSP Electronics Israel"},
    {"domain": "bug.co.il",         "category": "ecommerce_il",   "description": "Bug Electronics Israel"},
    {"domain": "superpharm.co.il",  "category": "ecommerce_il",   "description": "Super-Pharm Israel"},
    {"domain": "shufersal.co.il",   "category": "ecommerce_il",   "description": "Shufersal Supermarket Israel"},
    {"domain": "rami-levy.co.il",   "category": "ecommerce_il",   "description": "Rami Levy Supermarket"},
    {"domain": "yad2.co.il",        "category": "ecommerce_il",   "description": "Yad2 Classifieds Israel"},
    {"domain": "westwing.co.il",    "category": "ecommerce_il",   "description": "Westwing Israel"},

    # ══════════════════════════════════════════════════════════════
    # GLOBAL E-COMMERCE
    # ══════════════════════════════════════════════════════════════
    {"domain": "ebay.com",          "category": "ecommerce",      "description": "eBay"},
    {"domain": "aliexpress.com",    "category": "ecommerce",      "description": "AliExpress"},
    {"domain": "etsy.com",          "category": "ecommerce",      "description": "Etsy"},
    {"domain": "booking.com",       "category": "ecommerce",      "description": "Booking.com"},
    {"domain": "airbnb.com",        "category": "ecommerce",      "description": "Airbnb"},
    {"domain": "uber.com",          "category": "ecommerce",      "description": "Uber"},
    {"domain": "wolt.com",          "category": "ecommerce",      "description": "Wolt"},
    {"domain": "10bis.co.il",       "category": "ecommerce_il",   "description": "10bis Food Delivery Israel"},

    # ══════════════════════════════════════════════════════════════
    # CDN & INFRASTRUCTURE (commonly appear in URLs)
    # ══════════════════════════════════════════════════════════════
    {"domain": "cloudflare.com",    "category": "cdn",            "description": "Cloudflare"},
    {"domain": "cloudfront.net",    "category": "cdn",            "description": "Amazon CloudFront CDN"},
    {"domain": "akamai.com",        "category": "cdn",            "description": "Akamai CDN"},
    {"domain": "fastly.com",        "category": "cdn",            "description": "Fastly CDN"},
    {"domain": "jsdelivr.net",      "category": "cdn",            "description": "jsDelivr CDN"},
    {"domain": "unpkg.com",         "category": "cdn",            "description": "UNPKG CDN"},
    {"domain": "cdnjs.cloudflare.com","category":"cdn",           "description": "Cloudflare CDNJS"},
    {"domain": "s3.amazonaws.com",  "category": "cdn",            "description": "Amazon S3"},
    {"domain": "amazonaws.com",     "category": "cdn",            "description": "Amazon AWS"},
    {"domain": "twimg.com",         "category": "cdn",            "description": "Twitter Image CDN"},
    {"domain": "fbcdn.net",         "category": "cdn",            "description": "Facebook CDN"},
    {"domain": "fbsbx.com",         "category": "cdn",            "description": "Facebook Static CDN"},

    # ══════════════════════════════════════════════════════════════
    # TELECOM (ISRAEL)
    # ══════════════════════════════════════════════════════════════
    {"domain": "bezeq.co.il",       "category": "telecom_il",     "description": "Bezeq Israel Telecom"},
    {"domain": "hot.net.il",        "category": "telecom_il",     "description": "HOT Israel"},
    {"domain": "cellcom.co.il",     "category": "telecom_il",     "description": "Cellcom Israel"},
    {"domain": "partner.co.il",     "category": "telecom_il",     "description": "Partner Communications Israel"},
    {"domain": "012.net.il",        "category": "telecom_il",     "description": "012 Telecom Israel"},
    {"domain": "rami.co.il",        "category": "telecom_il",     "description": "Rami Levy Communications"},

    # ══════════════════════════════════════════════════════════════
    # EDUCATION
    # ══════════════════════════════════════════════════════════════
    {"domain": "wikipedia.org",     "category": "education",      "description": "Wikipedia"},
    {"domain": "academia.edu",      "category": "education",      "description": "Academia.edu"},
    {"domain": "coursera.org",      "category": "education",      "description": "Coursera"},
    {"domain": "udemy.com",         "category": "education",      "description": "Udemy"},
    {"domain": "huji.ac.il",        "category": "education_il",   "description": "Hebrew University Jerusalem"},
    {"domain": "tau.ac.il",         "category": "education_il",   "description": "Tel Aviv University"},
    {"domain": "technion.ac.il",    "category": "education_il",   "description": "Technion Israel"},
    {"domain": "bgu.ac.il",         "category": "education_il",   "description": "Ben-Gurion University"},
    {"domain": "weizmann.ac.il",    "category": "education_il",   "description": "Weizmann Institute"},
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def extract_domain(raw: str) -> str | None:
    raw = raw.strip().lower()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlparse(raw).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host or None
    except Exception:
        return None


# ─── MongoDB ──────────────────────────────────────────────────────────────────

def get_db(mongo_uri: str, db_name: str):
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        log.info(f"Connected to MongoDB at {mongo_uri}")
    except ConnectionFailure:
        sys.exit(f"Cannot connect to MongoDB at {mongo_uri}")
    return client[db_name]


def ensure_indexes(db):
    db[COLLECTION_WHITELIST].create_index(
        [("domain", ASCENDING)], unique=True
    )
    db[COLLECTION_WHITELIST].create_index(
        [("category", ASCENDING)]
    )
    log.info("Whitelist indexes ensured")


def seed_whitelist(db):
    now = datetime.now(timezone.utc)
    ops = []

    for entry in WHITELIST:
        domain = extract_domain(entry["domain"])
        if not domain:
            continue
        ops.append(UpdateOne(
            {"domain": domain},
            {"$set": {
                "domain":      domain,
                "category":    entry.get("category", "general"),
                "description": entry.get("description", ""),
                "updated_at":  now,
            }, "$setOnInsert": {"created_at": now}},
            upsert=True,
        ))

    if not ops:
        log.warning("No whitelist entries to insert")
        return

    try:
        result = db[COLLECTION_WHITELIST].bulk_write(ops, ordered=False)
        inserted = result.upserted_count
        updated  = result.modified_count
    except BulkWriteError as bwe:
        inserted = bwe.details.get("nUpserted", 0)
        updated  = bwe.details.get("nModified", 0)

    total = db[COLLECTION_WHITELIST].count_documents({})
    log.info("=" * 60)
    log.info(f"Whitelist seeding complete")
    log.info(f"  New entries inserted : {inserted}")
    log.info(f"  Existing updated     : {updated}")
    log.info(f"  Total in whitelist   : {total} domains")
    log.info("=" * 60)

    # Print breakdown by category
    pipeline = [{"$group": {"_id": "$category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}]
    log.info("Breakdown by category:")
    for row in db[COLLECTION_WHITELIST].aggregate(pipeline):
        log.info(f"  {row['_id']:<25} {row['count']} domains")


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mongo_uri = os.environ.get("MONGO_URI", DEFAULT_MONGO_URI)
    db_name   = os.environ.get("DB_NAME",   DEFAULT_DB_NAME)

    db = get_db(mongo_uri, db_name)
    ensure_indexes(db)
    seed_whitelist(db)