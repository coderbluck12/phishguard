"""
Lexical and Structural URL Feature Extractor for Machine Learning.
Extracts 18 numerical and statistical features per URL.
"""
import re
import math
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_TOKENS = [
    "login", "verify", "account", "banking", "update", "secure",
    "wallet", "password", "confirm", "support", "billing", "token",
    "action", "service", "appleid", "paypal", "netflix", "chase"
]

def shannon_entropy(string: str) -> float:
    """Calculates the Shannon entropy of a string (higher = more randomized/obfuscated)."""
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p, 2) for p in prob])
    return round(entropy, 4)

def extract_ml_features(raw_url: str) -> list:
    """
    Extracts a deterministic 18-element feature vector:
    1. url_length
    2. domain_length
    3. is_ip_host (1 or 0)
    4. count_dots
    5. count_hyphens
    6. count_at_symbols
    7. count_question_marks
    8. count_percentage
    9. count_equal_signs
    10. count_slash
    11. count_digits
    12. ratio_digits_to_length
    13. count_subdomains
    14. is_https (1 or 0)
    15. url_entropy
    16. domain_entropy
    17. count_suspicious_tokens
    18. has_punycode (1 or 0)
    """
    url = raw_url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query

    ext = tldextract.extract(url)
    domain_full = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # 1. Lengths
    url_length = len(url)
    domain_length = len(hostname)

    # 2. IP Host
    is_ip = 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) else 0

    # 3. Delimiters & Character counts
    dots = url.count(".")
    hyphens = url.count("-")
    at_sym = url.count("@")
    question_marks = url.count("?")
    percentages = url.count("%")
    equals = url.count("=")
    slashes = url.count("/")
    digits = sum(c.isdigit() for c in url)
    digit_ratio = round(digits / max(url_length, 1), 4)

    # 4. Subdomains
    subdomain_parts = [p for p in ext.subdomain.split(".") if p]
    subdomain_count = len(subdomain_parts)

    # 5. HTTPS
    is_https = 1 if parsed.scheme == "https" else 0

    # 6. Entropies
    url_ent = shannon_entropy(url)
    dom_ent = shannon_entropy(hostname)

    # 7. Suspicious Keywords
    token_hits = sum(1 for tok in SUSPICIOUS_TOKENS if tok in url.lower())

    # 8. Punycode
    punycode = 1 if "xn--" in hostname else 0

    return [
        url_length,
        domain_length,
        is_ip,
        dots,
        hyphens,
        at_sym,
        question_marks,
        percentages,
        equals,
        slashes,
        digits,
        digit_ratio,
        subdomain_count,
        is_https,
        url_ent,
        dom_ent,
        token_hits,
        punycode
    ]

FEATURE_NAMES = [
    "url_length", "domain_length", "is_ip_host", "count_dots", "count_hyphens",
    "count_at_symbols", "count_question_marks", "count_percentage", "count_equal_signs",
    "count_slash", "count_digits", "digit_ratio", "subdomain_count", "is_https",
    "url_entropy", "domain_entropy", "count_suspicious_tokens", "has_punycode"
]
