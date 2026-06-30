"""
feature_extractor.py
====================
Python mirror of the Kotlin LexicalAnalyzer.
Takes a raw URL string and returns a dictionary of 54 numerical features.

Philosophy: every feature is computed honestly from the URL structure.
No overrides, no artificial resets, no shortcuts.
The model learns entirely from the real patterns of safe vs malicious URLs.
"""

import re
import math
import tldextract
from urllib.parse import urlparse

# ── Known brands ──────────────────────────────────────────────────────────────
KNOWN_BRANDS = [
    "paypal", "google", "facebook", "apple", "amazon", "microsoft",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "ebay", "bank", "bankhapoalim", "bankleumi", "poalim", "leumi",
    "yahoo", "dropbox", "icloud", "wellsfargo", "chase", "barclays"
]

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "fun", "icu",
    "gq", "ml", "cf", "tk", "ga",
    "buzz", "rest", "work", "link", "click", "download",
    "zip", "mov", "pw", "cc", "su", "to", "ws"
}

SENSITIVE_TLDS = {
    "secure", "security", "login", "signin", "verify", "account",
    "support", "help", "update", "confirm", "banking", "payment",
    "deals", "offer", "free", "win", "gift", "bonus"
}

HIGH_RISK_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "logon", "log-on",
    "verify", "verification", "validate", "account-verify",
    "secure", "security", "update", "confirm", "confirmation",
    "suspend", "suspended", "unlock", "reactivate", "reactivation",
    "billing", "invoice", "payment", "checkout", "reset-password",
    "password-reset", "credential", "webscr", "cmd=", "dispatch="
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "alert", "warning", "attention",
    "limited", "expire", "expired", "action-required", "act-now",
    "free", "winner", "won", "prize", "gift", "reward",
    "bonus", "congratulations", "claim", "lucky", "selected"
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "ow.ly", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc", "is.gd", "buff.ly",
    "soo.gd", "bc.vc", "t.co", "goo.gl", "youtu.be",
    "bl.ink", "snip.ly", "clck.ru", "qr.ae", "po.st"
}

KNOWN_REDIRECTORS = [
    "google.com/url", "googleweblight.com",
    "t.co/", "bit.ly/", "tinyurl.com/", "t.ly/", "ow.ly/",
    "rb.gy/", "cutt.ly/", "shorturl.at/", "tiny.cc/",
    "is.gd/", "buff.ly/", "soo.gd/", "bc.vc/"
]

DANGEROUS_EXTENSIONS = [".exe", ".apk", ".bat", ".cmd", ".scr",
                        ".vbs", ".ps1", ".jar", ".msi", ".dmg"]
SAFE_EXTENSIONS      = [".pdf", ".docx", ".xlsx", ".jpg", ".jpeg",
                        ".png", ".txt", ".zip"]

NORMALIZATION_MAP = {
    'ⓐ':'a','ⓑ':'b','ⓒ':'c','ⓓ':'d','ⓔ':'e','ⓕ':'f','ⓖ':'g',
    'ⓗ':'h','ⓘ':'i','ⓙ':'j','ⓚ':'k','ⓛ':'l','ⓜ':'m','ⓝ':'n',
    'ⓞ':'o','ⓟ':'p','ⓠ':'q','ⓡ':'r','ⓢ':'s','ⓣ':'t','ⓤ':'u',
    'ⓥ':'v','ⓦ':'w','ⓧ':'x','ⓨ':'y','ⓩ':'z',
}

DANGEROUS_UNICODE = [(0x200B,0x200D),(0x202A,0x202E),
                     (0x2060,0x2064),(0xFEFF,0xFEFF),(0x00AD,0x00AD)]

# ── Helpers ───────────────────────────────────────────────────────────────────

def shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    return -sum((c/len(s))*math.log2(c/len(s)) for c in freq.values())

def longest_consonant_run(s):
    vowels = set('aeiou')
    max_r = cur = 0
    for ch in s.lower():
        if ch.isalpha() and ch not in vowels:
            cur += 1; max_r = max(max_r, cur)
        elif ch.isalpha():
            cur = 0
    return max_r

def longest_vowel_run(s):
    vowels = set('aeiou')
    max_r = cur = 0
    for ch in s.lower():
        if ch.isalpha() and ch in vowels:
            cur += 1; max_r = max(max_r, cur)
        elif ch.isalpha():
            cur = 0
    return max_r

def levenshtein(a, b):
    if abs(len(a)-len(b)) > 3: return 99
    dp = [[0]*(len(b)+1) for _ in range(len(a)+1)]
    for i in range(len(a)+1): dp[i][0] = i
    for j in range(len(b)+1): dp[0][j] = j
    for i in range(1,len(a)+1):
        for j in range(1,len(b)+1):
            dp[i][j] = dp[i-1][j-1] if a[i-1]==b[j-1] else 1+min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1])
    return dp[len(a)][len(b)]

def check_visual_spoofing(domain_name):
    """Check if domain or any of its parts looks like a brand with 1-2 char substitutions."""
    # Check each dot-separated part separately — catches paypa1 in paypa1.secure-login.xyz
    parts_to_check = [domain_name.lower()]
    # Also check hyphen-separated parts — catches secure-paypa1
    for part in domain_name.lower().replace('-', '.').split('.'):
        if len(part) >= 4:  # skip very short parts
            parts_to_check.append(part)

    for part in parts_to_check:
        n = part
        for o, r in [('0','o'),('1','l'),('1','i'),('3','e'),('4','a'),
                     ('5','s'),('6','b'),('7','t'),('9','g'),('$','s'),
                     ('rn','m'),('cl','d'),('vv','w'),('ii','n')]:
            n = n.replace(o, r)
        for brand in KNOWN_BRANDS:
            if n == brand: return 1
            if levenshtein(part, brand) == 1: return 1
            if levenshtein(n, brand) <= 1: return 1
    return 0

def hidden_unicode_count(url):
    count = 0
    for ch in url:
        code = ord(ch)
        if any(s <= code <= e for s,e in DANGEROUS_UNICODE):
            count += 1
    return count

def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://','https://','ftp://','javascript:','data:')):
        url = 'http://' + url
    return url


# ── Main ──────────────────────────────────────────────────────────────────────

def extract_features(raw_url):
    url = normalize_url(raw_url)
    url_lower = url.lower()

    try:
        parsed   = urlparse(url)
        scheme   = parsed.scheme.lower() if parsed.scheme else ''
        host     = (parsed.hostname or '').lower().rstrip('.')
        path     = parsed.path or ''
        query    = parsed.query or ''
        fragment = parsed.fragment or ''
        port     = parsed.port or -1
    except Exception:
        scheme = host = path = query = fragment = ''
        port = -1

    ext       = tldextract.extract(url)
    domain    = ext.domain.lower()       # e.g. "paypal"
    tld       = ext.suffix.lower()       # e.g. "com"
    subdomain = ext.subdomain.lower()    # e.g. "secure.login"
    registrable = f"{domain}.{tld}" if tld else domain

    # ── 1. URL STRUCTURE ──────────────────────────────────────────

    url_length        = len(raw_url)
    path_depth        = len([p for p in path.split('/') if p])
    query_param_count = len(query.split('&')) if query else 0

    # ── 2. DOMAIN ANALYSIS ───────────────────────────────────────

    is_ip_address = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else 0

    # Strip www — it is not a meaningful subdomain
    sub_clean = subdomain
    if sub_clean == 'www': sub_clean = ''
    elif sub_clean.startswith('www.'): sub_clean = sub_clean[4:]

    subdomain_count         = len([s for s in sub_clean.split('.') if s]) if sub_clean else 0
    subdomain_string_length = len(sub_clean)

    # Brand position analysis — the most important structural signal
    # Safe:     brand IS the registrable domain  (paypal.com)
    # Phishing: brand is in the subdomain        (paypal.evil.com)
    brand_is_registrable = 1 if any(registrable.startswith(b+'.') for b in KNOWN_BRANDS) else 0
    brand_in_subdomain   = 0
    brands_in_subdomain  = 0
    if not brand_is_registrable:
        for b in KNOWN_BRANDS:
            if sub_clean == b or sub_clean.startswith(b+'.') or ('.'+b+'.') in sub_clean:
                brand_in_subdomain = 1
                brands_in_subdomain += 1

    visual_spoof = check_visual_spoofing(host)  # check full host including subdomains

    domain_length          = len(domain)
    hyphen_count           = host.count('-')
    digit_count_in_domain  = sum(1 for c in domain if c.isdigit())
    digit_count_in_host    = sum(1 for c in host if c.isdigit())
    alpha_count            = sum(1 for c in host if c.isalpha())
    alpha_ratio            = alpha_count / len(host) if host else 1.0
    special_chars_in_host  = sum(1 for c in host if not c.isalnum() and c not in '.-')
    domain_entropy         = shannon_entropy(domain)
    max_consonant_run      = longest_consonant_run(domain)
    max_vowel_run          = longest_vowel_run(domain)

    brand_fragmented = 0
    if not brand_is_registrable:
        for b in KNOWN_BRANDS:
            if re.search('[.\\-]'.join(list(b)), host):
                brand_fragmented = 1
                break

    # ── 3. KEYWORDS ───────────────────────────────────────────────

    high_risk_keyword_count = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in url_lower)
    urgency_keyword_count   = sum(1 for kw in URGENCY_KEYWORDS   if kw in url_lower)

    # Brand in path is only suspicious if brand is NOT the real domain
    brand_in_path = 0
    if not brand_is_registrable:
        for b in KNOWN_BRANDS:
            if b in (path+query).lower():
                brand_in_path = 1
                break

    path_lower = path.lower()
    fake_extension_in_path = sum(
        1 for ext_ in ['.php','.html','.aspx','.jsp']
        if ext_ in path_lower and path_lower.index(ext_) < len(path_lower)-len(ext_)
    )

    # ── 4. CHARACTER ANALYSIS ─────────────────────────────────────

    has_at_symbol          = 1 if '@' in url else 0
    hidden_char_count      = hidden_unicode_count(url)
    has_double_slash       = 1 if '//' in path else 0
    percent_encoded_count  = url.count('%')
    has_non_standard_port  = 1 if port > 0 and port not in [80,443,8080,8443] else 0

    # ── 5. TLD & PROTOCOL ────────────────────────────────────────

    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    sensitive_tld     = 1 if tld in SENSITIVE_TLDS  else 0
    is_https          = 1 if scheme == 'https' else 0
    is_punycode       = 1 if 'xn--' in host else 0

    # ── 6. ADVANCED PATTERNS ─────────────────────────────────────

    is_redirector = 1 if any(r in url_lower for r in KNOWN_REDIRECTORS) else 0
    is_shortener  = 1 if any(host == s or host.endswith('.'+s)
                             for s in KNOWN_SHORTENERS) else 0

    brand_repeat_count = max(
        (url_lower.count(b) for b in KNOWN_BRANDS), default=0
    )

    dot_count      = url.count('.')
    domain_in_path = 1 if re.search(r'(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', path) else 0
    url_in_query   = 1 if re.search(r'(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', query) else 0
    has_non_ascii_host = 1 if any(ord(c) > 127 for c in host) else 0

    # ── 7. INJECTION & ENCODING ───────────────────────────────────

    has_double_extension = int(any(
        (s+d) in path_lower
        for d in DANGEROUS_EXTENSIONS for s in SAFE_EXTENSIONS
    ))
    has_null_byte            = 1 if '%00' in url or '\x00' in url else 0
    has_control_chars        = 1 if any(c in url for c in ['%09','%0A','%0D','\t','\n','\r']) else 0
    has_double_encoding      = 1 if re.search(r'%25[0-9A-Fa-f]{2}', url) else 0
    has_backslash            = 1 if '\\' in url else 0
    has_credentials_pattern  = 1 if re.search(r'https?://[^@\s]+:[^@\s]+@', url) else 0
    self_repeat_count        = (path+query).count(host) if len(host) > 4 else 0

    norm_host = ''.join(NORMALIZATION_MAP.get(c,c) for c in host)
    has_normalization_spoof = 1 if norm_host != host and any(b in norm_host for b in KNOWN_BRANDS) else 0

    has_path_traversal     = 1 if ('../' in path or '..\\' in path or
                                    '%2E%2E%2F' in url or '%2E%2E/' in url) else 0
    has_sensitive_fragment = 1 if any(k in fragment.lower() for k in
                                      ['http://','https://','www.','access_token=',
                                       'id_token=','token=','password=','passwd=','pwd=']) else 0
    original_host       = parsed.hostname or ''
    has_mixed_case_host = 1 if (any(c.isupper() for c in original_host) and
                                 any(c.islower() for c in original_host)) else 0
    has_non_ascii_tld   = 1 if any(ord(c) > 127 for c in tld) else 0

    # ── Compute raw lexical score ─────────────────────────────────

    score = 0
    if url_length > 200:      score += 15
    elif url_length > 100:    score += 8
    elif url_length > 75:     score += 3
    if path_depth >= 6:       score += 10
    elif path_depth >= 4:     score += 5
    if query_param_count >= 10: score += 10
    elif query_param_count >= 5: score += 5
    if is_ip_address:         score += 20
    if subdomain_count >= 4:  score += 20
    elif subdomain_count >= 3: score += 12
    elif subdomain_count == 2: score += 5
    if brand_in_subdomain:    score += 25
    if visual_spoof:          score += 20
    if domain_length > 30:    score += 12
    elif domain_length > 20:  score += 6
    if hyphen_count >= 4:     score += 15
    elif hyphen_count >= 2:   score += 8
    elif hyphen_count == 1:   score += 3
    if digit_count_in_domain >= 3: score += 8
    if high_risk_keyword_count >= 3: score += 20
    elif high_risk_keyword_count == 2: score += 12
    elif high_risk_keyword_count == 1: score += 6
    if urgency_keyword_count >= 2: score += 12
    elif urgency_keyword_count == 1: score += 5
    if brand_in_path:         score += 15
    if fake_extension_in_path > 0: score += 8
    if has_at_symbol:         score += 25
    if hidden_char_count > 0: score += 50
    if has_double_slash:      score += 10
    if percent_encoded_count >= 15: score += 20
    elif percent_encoded_count >= 6: score += 10
    elif percent_encoded_count >= 3: score += 5
    if alpha_ratio < 0.5 and len(host) > 5: score += 12
    if special_chars_in_host > 0: score += 15
    if domain_entropy > 4.0:  score += 15
    elif domain_entropy > 3.5: score += 8
    if max_consonant_run >= 5: score += 10
    if max_vowel_run >= 4:    score += 10
    elif max_vowel_run >= 3:  score += 5
    if brand_fragmented:      score += 18
    if is_suspicious_tld:     score += 12
    if scheme == 'http':      score += 8
    if scheme == 'data':      score += 40
    if scheme == 'javascript': score += 50
    if has_non_standard_port: score += 10
    if is_punycode:           score += 22
    if is_redirector:         score += 15
    if is_shortener:          score += 18
    if brand_repeat_count >= 3: score += 18
    elif brand_repeat_count == 2: score += 8
    if dot_count >= 8:        score += 15
    elif dot_count >= 5:      score += 8
    if sensitive_tld:         score += 20
    if domain_in_path:        score += 20
    if subdomain_string_length > 40: score += 12
    elif subdomain_string_length > 20: score += 5
    if has_non_ascii_host:    score += 25
    if url_in_query:          score += 20
    if has_double_extension:  score += 30
    if has_null_byte:         score += 35
    if has_control_chars:     score += 30
    if has_double_encoding:   score += 25
    if has_backslash:         score += 20
    if has_credentials_pattern: score += 30
    if self_repeat_count >= 2: score += 15
    if has_normalization_spoof: score += 28
    if has_path_traversal:    score += 18
    if has_sensitive_fragment: score += 20
    if has_mixed_case_host:   score += 8
    if has_non_ascii_tld:     score += 25

    lexical_risk_score = min(score, 100)

    obvious_killer_count = sum([
        has_at_symbol,
        1 if hidden_char_count > 0 else 0,
        1 if scheme == 'data' else 0,
        1 if scheme == 'javascript' else 0,
        has_double_extension,
        has_null_byte,
        has_control_chars,
        has_double_encoding,
        has_credentials_pattern,
        has_normalization_spoof,
        has_non_ascii_tld,
    ])

    # Deep subdomain abuse — many subdomains + brand + no HTTPS
    # Catches: secure.login.paypal.verify.account.evil.com
    deep_subdomain_abuse = 1 if (
        subdomain_count >= 4 and
        brand_in_subdomain and
        not brand_is_registrable and
        not is_https
    ) else 0

    # Brand hijack with keywords — brand in wrong place + high-risk words
    brand_hijack_with_keywords = 1 if (
        brand_in_subdomain and
        not brand_is_registrable and
        high_risk_keyword_count >= 2
    ) else 0

    # ── Composite phishing signal ─────────────────────────────────
    # Fires when classic phishing structural patterns are detected

    is_classic_phishing = 1 if (
        (brand_in_subdomain and not brand_is_registrable) or
        (visual_spoof and not brand_is_registrable) or
        (subdomain_count >= 3 and high_risk_keyword_count >= 1) or
        (is_suspicious_tld and high_risk_keyword_count >= 2) or
        (brand_fragmented and not brand_is_registrable) or
        (is_punycode and not brand_is_registrable) or
        (sensitive_tld and not brand_is_registrable) or
        (subdomain_count >= 4 and not brand_is_registrable) or
        (high_risk_keyword_count >= 3 and not brand_is_registrable and not is_https) or
        (is_suspicious_tld and subdomain_count >= 2) or
        (brand_in_subdomain and high_risk_keyword_count >= 2)
    ) else 0

    # ── Return all 54 features ────────────────────────────────────

    return {
        "url_length":               url_length,
        "path_depth":               path_depth,
        "query_param_count":        query_param_count,
        "is_ip_address":            is_ip_address,
        "subdomain_count":          subdomain_count,
        "domain_length":            domain_length,
        "hyphen_count":             hyphen_count,
        "digit_count_in_domain":    digit_count_in_domain,
        "has_at_symbol":            has_at_symbol,
        "hidden_char_count":        hidden_char_count,
        "has_double_slash":         has_double_slash,
        "percent_encoded_count":    percent_encoded_count,
        "alpha_ratio":              round(alpha_ratio, 4),
        "special_chars_in_host":    special_chars_in_host,
        "domain_entropy":           round(domain_entropy, 4),
        "max_consonant_run":        max_consonant_run,
        "max_vowel_run":            max_vowel_run,
        "high_risk_keyword_count":  high_risk_keyword_count,
        "urgency_keyword_count":    urgency_keyword_count,
        "brand_in_subdomain":       brand_in_subdomain,
        "brands_in_subdomain":          brands_in_subdomain,
        "deep_subdomain_abuse":         deep_subdomain_abuse,
        "brand_hijack_with_keywords":   brand_hijack_with_keywords,
        "brand_in_path":            brand_in_path,
        "is_suspicious_tld":        is_suspicious_tld,
        "is_https":                 is_https,
        "has_non_standard_port":    has_non_standard_port,
        "digit_count_in_host":      digit_count_in_host,
        "visual_spoof_detected":    visual_spoof,
        "lexical_risk_score":       lexical_risk_score,
        "obvious_killer_count":     obvious_killer_count,
        "is_punycode":              is_punycode,
        "is_redirector":            is_redirector,
        "is_shortener":             is_shortener,
        "brand_repeat_count":       brand_repeat_count,
        "dot_count":                dot_count,
        "sensitive_tld":            sensitive_tld,
        "domain_in_path":           domain_in_path,
        "subdomain_string_length":  subdomain_string_length,
        "has_non_ascii_host":       has_non_ascii_host,
        "url_in_query":             url_in_query,
        "has_double_extension":     has_double_extension,
        "has_null_byte":            has_null_byte,
        "has_control_chars":        has_control_chars,
        "has_double_encoding":      has_double_encoding,
        "has_backslash":            has_backslash,
        "has_credentials_pattern":  has_credentials_pattern,
        "self_repeat_count":        self_repeat_count,
        "has_normalization_spoof":  has_normalization_spoof,
        "has_path_traversal":       has_path_traversal,
        "has_sensitive_fragment":   has_sensitive_fragment,
        "has_mixed_case_host":      has_mixed_case_host,
        "has_non_ascii_tld":        has_non_ascii_tld,
        "fake_extension_in_path":   fake_extension_in_path,
        "brand_fragmented":         brand_fragmented,
        "brand_is_registrable":     brand_is_registrable,
        "is_classic_phishing":      is_classic_phishing,
    }


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        ("https://www.google.com",                                 "SAFE"),
        ("https://www.paypal.com/signin",                          "SAFE"),
        ("https://www.amazon.com/dp/B08N5WRWNW",                  "SAFE"),
        ("https://accounts.google.com/signin/v2/identifier",       "SAFE"),
        ("https://www.bankhapoalim.co.il/he/private/accounts",     "SAFE"),
        ("http://paypa1.secure-login.verify.xyz/account/update",   "MALICIOUS"),
        ("http://secure.login.paypal.verify.account.evil.com/b",   "MALICIOUS"),
        ("http://xn--pypal-4ve.com/login",                         "MALICIOUS"),
        ("http://amazon-secure-login.verify.top/account/billing",  "MALICIOUS"),
        ("http://user@127.0.0.1/login",                            "MALICIOUS"),
        ("http://192.168.1.1/paypal/login/verify",                 "MALICIOUS"),
        ("http://bit.ly/3xK92mZ",                                  "MALICIOUS"),
    ]

    print(f"{'Expected':<12} {'reg':<5} {'sub':<5} {'classic':<9} {'score':<7} {'https':<7} {'kw':<5} URL")
    print("-" * 95)
    for url, expected in tests:
        f = extract_features(url)
        print(f"{expected:<12} "
              f"{f['brand_is_registrable']:<5} "
              f"{f['brand_in_subdomain']:<5} "
              f"{f['is_classic_phishing']:<9} "
              f"{f['lexical_risk_score']:<7} "
              f"{f['is_https']:<7} "
              f"{f['high_risk_keyword_count']:<5} "
              f"{url[:45]}")