"""
Domain & Typosquatting Analyzer
Detects brand impersonation, Levenshtein distance typosquatting, IDN homoglyphs,
subdomain depth anomalies, and DNS/MX record presence.
"""
import dns.resolver
import tldextract
import whois
from datetime import datetime
from typing import Dict, Any, List

TARGET_BRANDS = {
    "paypal": ["paypa1", "paypai", "pay-pal", "paypal-security", "paypal-update", "paypol"],
    "apple": ["app1e", "apple-id", "appleid-support", "icloud-verify"],
    "google": ["g00gle", "go0gle", "goog1e", "google-support", "account-google"],
    "microsoft": ["micros0ft", "m1crosoft", "micro-soft", "office365-login", "ms-online"],
    "amazon": ["amaz0n", "amazn", "amazon-update", "prime-renewal"],
    "netflix": ["netf1ix", "netflx", "netflix-verify", "netflix-billing"],
    "chase": ["chase-bank", "chase-security", "chase-online"],
    "wellsfargo": ["wells-fargo", "wellsfargo-verify", "wf-online"],
    "bankofamerica": ["bofa", "bankofamerica-login", "bank-of-america"],
    "binance": ["b1nance", "binance-us", "binance-verify"],
    "coinbase": ["c0inbase", "coinbase-pro", "coinbase-wallet"]
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_domain(target_url_or_domain: str) -> Dict[str, Any]:
    """
    Analyzes domain structure, typosquatting risk, DNS MX/A records, and age.
    """
    extracted = tldextract.extract(target_url_or_domain)
    domain_name = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain.lower()
    registered_domain = f"{domain_name}.{suffix}" if suffix else domain_name

    findings = []
    penalty = 0
    impersonated_brand = None
    typosquatting_detected = False

    # 1. Homoglyphs & Punycode (IDN spoofing)
    is_punycode = registered_domain.startswith("xn--") or ".xn--" in registered_domain
    if is_punycode:
        penalty += 35
        findings.append("IDN Punycode detected (xn--): high indicator of homoglyph visual spoofing attack.")

    # 2. Typosquatting / Brand impersonation check
    for brand, variations in TARGET_BRANDS.items():
        # Exact brand match on unauthorized domain
        if brand in domain_name or brand in subdomain:
            if domain_name != brand:
                penalty += 40
                impersonated_brand = brand
                typosquatting_detected = True
                findings.append(f"Domain or subdomain contains brand name '{brand}', indicating targeted impersonation.")
                break

        # Variation check
        for var in variations:
            if var in domain_name or var in subdomain:
                penalty += 45
                impersonated_brand = brand
                typosquatting_detected = True
                findings.append(f"Typosquatted brand pattern detected: '{var}' targeting legitimate '{brand}'.")
                break

        # Levenshtein distance check if domain is close to brand name
        if not typosquatting_detected and len(domain_name) >= 4:
            dist = levenshtein_distance(domain_name, brand)
            if dist == 1 and domain_name != brand:
                penalty += 40
                impersonated_brand = brand
                typosquatting_detected = True
                findings.append(f"Near-exact typosquatting distance (Levenshtein=1) to brand '{brand}'.")
                break

    # 3. Excessive subdomain depth (e.g. login.verification.account.paypal.evil.com)
    subdomain_parts = [p for p in subdomain.split(".") if p]
    if len(subdomain_parts) >= 3:
        penalty += 20
        findings.append(f"Excessive subdomain depth ({len(subdomain_parts)} levels) used to conceal true domain.")

    # Check if a major brand is masqueraded inside subdomains
    for brand in TARGET_BRANDS.keys():
        if brand in subdomain_parts and domain_name != brand:
            penalty += 35
            findings.append(f"Subdomain contains trusted brand '{brand}' while base domain is '{registered_domain}'.")

    # 4. Check DNS Records (A and MX)
    has_dns_a = False
    has_dns_mx = False
    resolved_ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        
        # A records
        try:
            answers = resolver.resolve(registered_domain, 'A')
            resolved_ips = [rdata.to_text() for rdata in answers]
            has_dns_a = bool(resolved_ips)
        except Exception:
            has_dns_a = False

        # MX records
        try:
            mx_answers = resolver.resolve(registered_domain, 'MX')
            has_dns_mx = bool(mx_answers)
        except Exception:
            has_dns_mx = False

    except Exception:
        pass

    if not has_dns_a:
        findings.append("No active DNS A record found; domain may be newly dormant or taken down.")

    # Phishing domains often don't have MX records (only used for web landing)
    if has_dns_a and not has_dns_mx:
        penalty += 10
        findings.append("Domain has active web host (A record) but lacks Mail Exchanger (MX) records.")

    # 5. Domain Age & WHOIS (safe fallback)
    domain_age_days = None
    creation_date_str = None
    try:
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            now = datetime.now()
            domain_age_days = (now - creation_date).days
            creation_date_str = creation_date.strftime("%Y-%m-%d")
            if domain_age_days < 30:
                penalty += 35
                findings.append(f"Newly registered domain (Age: {domain_age_days} days old). >85% of phishing occurs on domains <30 days old.")
            elif domain_age_days < 90:
                penalty += 15
                findings.append(f"Young domain (Age: {domain_age_days} days old).")
    except Exception:
        # Many whois queries timeout or are rate-limited, fail gracefully
        pass

    return {
        "domain": domain_name,
        "suffix": suffix,
        "subdomain": subdomain,
        "registered_domain": registered_domain,
        "is_punycode": is_punycode,
        "impersonated_brand": impersonated_brand,
        "typosquatting_detected": typosquatting_detected,
        "subdomain_depth": len(subdomain_parts),
        "has_dns_a": has_dns_a,
        "has_dns_mx": has_dns_mx,
        "resolved_ips": resolved_ips[:4],
        "domain_age_days": domain_age_days,
        "creation_date": creation_date_str,
        "risk_penalty": penalty,
        "findings": findings
    }
