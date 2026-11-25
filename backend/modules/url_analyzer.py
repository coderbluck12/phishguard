"""
URL Structure & Reputation Analyzer
Unshortens redirect chains, detects IP-based hosts, dangerous characters,
abnormal port numbers, and obfuscation.
"""
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List
import requests

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "banking", "update",
    "password", "confirm", "wallet", "support", "security", "token", "claim",
    "recovery", "alert", "validate", "suspended", "action-required"
]

def analyze_url_structure(raw_url: str) -> Dict[str, Any]:
    """
    Parses and inspects URL anatomy for evasion and manipulation tactics.
    """
    clean_url = raw_url.strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query
    findings = []
    penalty = 0

    # 1. IP address hostname check (e.g. http://192.168.1.1/login)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip_address = bool(re.match(ip_pattern, hostname))
    if is_ip_address:
        penalty += 40
        findings.append("Direct IP address used as hostname instead of a registered domain.")

    # 2. '@' Symbol trick (browser credentials delimiter, e.g. legitimate.com@evil.com)
    has_at_symbol = "@" in clean_url
    if has_at_symbol:
        penalty += 40
        findings.append("URL contains '@' symbol, which ignores preceding text and redirects to the subsequent host.")

    # 3. Excessive URL length (phishing URLs frequently exceed 75 characters)
    url_length = len(clean_url)
    if url_length > 100:
        penalty += 15
        findings.append(f"Abnormally long URL ({url_length} characters) typical of obfuscation padding.")
    elif url_length > 75:
        penalty += 8

    # 4. Abnormal port numbers (phishers often run on non-standard ports like 8080, 8888, 4444)
    abnormal_port = False
    port_used = parsed.port
    if port_used and port_used not in [80, 443]:
        abnormal_port = True
        penalty += 25
        findings.append(f"Suspicious non-standard network port ({port_used}) specified.")

    # 5. Excessive hyphenation in domain/path
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        penalty += 15
        findings.append(f"Excessive hyphenation ({hyphen_count} hyphens) in domain name.")

    # 6. Detection of sensitive deceptive keywords in path/query
    detected_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in path.lower() or kw in query.lower():
            detected_keywords.append(kw)
    if detected_keywords:
        kw_penalty = min(len(detected_keywords) * 8, 25)
        penalty += kw_penalty
        findings.append(f"Contains high-urgency/phishing keywords: {', '.join(detected_keywords)}")

    # 7. URL Shortener detection
    is_shortened = any(short in hostname for short in SHORTENER_DOMAINS)
    redirect_chain = []
    final_url = clean_url
    if is_shortened:
        penalty += 15
        findings.append(f"URL uses known shortening service ({hostname}) to conceal destination.")
        # Attempt to expand redirect chain safely
        try:
            resp = requests.head(clean_url, allow_redirects=True, timeout=3.0, headers={'User-Agent': 'Mozilla/5.0'})
            final_url = resp.url
            if resp.history:
                redirect_chain = [r.url for r in resp.history] + [resp.url]
                findings.append(f"Redirect chain resolved to: {final_url}")
        except Exception:
            pass

    # 8. Encoded / Hex / % obfuscation
    encoded_chars_count = len(re.findall(r'%[0-9a-fA-F]{2}', clean_url))
    if encoded_chars_count > 5:
        penalty += 15
        findings.append(f"High density of percent-encoded characters ({encoded_chars_count}) indicating evasion.")

    return {
        "original_url": raw_url,
        "clean_url": clean_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "is_ip_address": is_ip_address,
        "has_at_symbol": has_at_symbol,
        "length": url_length,
        "abnormal_port": abnormal_port,
        "port": port_used,
        "detected_keywords": detected_keywords,
        "is_shortened": is_shortened,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "risk_penalty": penalty,
        "findings": findings
    }
