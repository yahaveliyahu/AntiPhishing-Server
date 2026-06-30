"""
domain_age.py
=============
Checks how old a domain is using WHOIS lookup.

Used by app.py as a POST-PROCESSING boost on top of the ML model score.

Why domain age matters:
    Phishing domains are almost always newly registered — attackers create
    them hours or days before launching an attack, then abandon them after
    takedown. Legitimate businesses have domains registered years ago.

How it works:
    - ML model returns a confidence score (0-100%)
    - Flask calls get_domain_age_boost(domain, ml_confidence)
    - If domain is < 7 days old → strong boost toward malicious
    - If domain is < 30 days old → moderate boost
    - If domain is > 1 year old → small reduction (more likely safe)
    - Result is the adjusted confidence score

Installation:
    pip install python-whois

Usage in app.py:
    from domain_age import get_age_adjusted_confidence
"""

import os
import re
import logging
from datetime import datetime, timezone
from functools import lru_cache

log = logging.getLogger(__name__)

# ── Try to import whois library ───────────────────────────────────────────────
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    log.warning("python-whois not installed. Run: pip install python-whois")


# ── Cache domain ages to avoid repeated WHOIS lookups ─────────────────────────
# In-memory cache — survives for the lifetime of the Flask process
_age_cache = {}
CACHE_MAX_SIZE = 10000


def get_domain_age_days(domain: str) -> int | None:
    """
    Returns the age of a domain in days, or None if WHOIS lookup fails.

    Caches results to avoid repeated lookups for the same domain.
    Returns None if:
      - python-whois is not installed
      - WHOIS lookup times out or fails
      - Domain has privacy protection (WHOIS data hidden)
      - Domain is an IP address
    """
    if not WHOIS_AVAILABLE:
        return None

    # Skip IP addresses
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return None

    # Strip www and subdomains — get registrable domain
    parts = domain.split('.')
    if len(parts) >= 2:
        registrable = '.'.join(parts[-2:])
    else:
        registrable = domain

    # Check cache
    if registrable in _age_cache:
        return _age_cache[registrable]

    try:
        w = whois.whois(registrable)

        # Extract creation date — can be a list or single value
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            _age_cache[registrable] = None
            return None

        # Make timezone-aware if needed
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now  = datetime.now(timezone.utc)
        age  = (now - creation).days

        # Cache result (limit cache size)
        if len(_age_cache) < CACHE_MAX_SIZE:
            _age_cache[registrable] = age

        return age

    except Exception as e:
        log.debug(f"WHOIS failed for {registrable}: {e}")
        if len(_age_cache) < CACHE_MAX_SIZE:
            _age_cache[registrable] = None
        return None


def get_age_adjusted_confidence(
    domain: str,
    ml_confidence: float,
    timeout_seconds: int = 5
) -> tuple[float, str | None]:
    """
    Adjusts the ML model's malicious confidence score based on domain age.

    Args:
        domain:          The domain name to check (e.g. "evil.com")
        ml_confidence:   ML model's malicious probability (0.0 to 1.0)
        timeout_seconds: Max seconds to wait for WHOIS response

    Returns:
        (adjusted_confidence, age_explanation)
        adjusted_confidence: float 0.0-1.0
        age_explanation: human-readable string or None if age unknown
    """
    age_days = get_domain_age_days(domain)

    if age_days is None:
        # Cannot determine age — return ML score unchanged
        return ml_confidence, None

    # ── Apply age-based adjustment ────────────────────────────────────────────

    if age_days < 3:
        # Domain registered in last 3 days — extremely suspicious
        # Almost no legitimate business launches and immediately sends links
        boost        = 0.40
        explanation  = f"Domain registered only {age_days} day(s) ago — extremely new domains are almost always phishing"

    elif age_days < 7:
        # Less than 1 week old
        boost        = 0.30
        explanation  = f"Domain registered {age_days} days ago — very new domains are high-risk"

    elif age_days < 30:
        # Less than 1 month old
        boost        = 0.20
        explanation  = f"Domain registered {age_days} days ago — newly registered domains are commonly used in phishing"

    elif age_days < 90:
        # Less than 3 months old
        boost        = 0.10
        explanation  = f"Domain registered {age_days} days ago — relatively new domain"

    elif age_days > 365:
        # Domain is over 1 year old — slight reduction in suspicion
        boost        = -0.05
        explanation  = None  # Not worth showing to user — just a minor signal

    else:
        # 90-365 days — neutral
        boost        = 0.0
        explanation  = None

    # Apply boost — clamp to 0.0-1.0
    adjusted = max(0.0, min(1.0, ml_confidence + boost))

    log.info(f"Domain age for {domain}: {age_days} days → "
             f"confidence {ml_confidence:.2f} → {adjusted:.2f} (boost: {boost:+.2f})")

    return adjusted, explanation


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not WHOIS_AVAILABLE:
        print("python-whois not installed. Run: pip install python-whois")
        exit(1)

    test_domains = [
        "google.com",
        "paypal.com",
        "github.com",
        "wikipedia.org",
    ]

    print("Domain Age Test")
    print("-" * 50)
    for domain in test_domains:
        age = get_domain_age_days(domain)
        adjusted, explanation = get_age_adjusted_confidence(domain, 0.3)
        age_str = f"{age} days ({age//365} years)" if age else "unknown"
        print(f"{domain:<25} age: {age_str}")
        if explanation:
            print(f"  → {explanation}")
