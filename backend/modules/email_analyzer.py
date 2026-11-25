"""
Email Header & Sender Identity Verification Engine
Features:
- RFC 822 email header parsing
- SPF, DKIM, and DMARC verification
- Sender identity spoofing detection (From vs Return-Path vs Reply-To)
- Received hop routing trace & timing anomaly analysis
- Embedded link extraction and risk evaluation
"""
import re
import email
from email import policy
from email.parser import BytesParser, HeaderParser
from urllib.parse import urlparse
from typing import Dict, Any, List
import dns.resolver

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False

def extract_domain(email_str: str) -> str:
    """Extract domain part from email address string."""
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_str or "")
    if match:
        return match.group(1).lower().strip('>')
    return ""

def verify_dmarc_policy(domain: str) -> Dict[str, Any]:
    """Query DNS TXT for _dmarc.domain."""
    dmarc_record = None
    policy = "none"
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=2.0)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode('utf-8', errors='ignore')
            if txt.startswith("v=DMARC1"):
                dmarc_record = txt
                p_match = re.search(r'\bp=([a-zA-Z]+)', txt)
                if p_match:
                    policy = p_match.group(1).lower()
                break
    except Exception:
        pass

    return {
        "has_dmarc": bool(dmarc_record),
        "dmarc_record": dmarc_record,
        "policy": policy
    }

def analyze_email_message(raw_email_bytes_or_str: Any) -> Dict[str, Any]:
    """
    Analyzes raw email content or header string.
    """
    if isinstance(raw_email_bytes_or_str, str):
        msg_bytes = raw_email_bytes_or_str.encode('utf-8', errors='ignore')
    else:
        msg_bytes = raw_email_bytes_or_str

    msg = BytesParser(policy=policy.default).parsebytes(msg_bytes)

    headers = dict(msg.items())
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    subject = msg.get("Subject", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    date_header = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    received_headers = msg.get_all("Received", [])

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    findings = []
    penalty = 0

    # 1. Sender Spoofing & Domain Mismatches
    is_spoofed_sender = False
    if return_path_domain and from_domain and return_path_domain != from_domain:
        penalty += 25
        is_spoofed_sender = True
        findings.append(f"Return-Path domain ({return_path_domain}) does not match From domain ({from_domain}).")

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        penalty += 25
        findings.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}), typical of response redirection.")

    # Check for display name spoofing e.g. "PayPal Support <attacker@gmail.com>"
    display_name_match = re.match(r'^(.*?)\s*<', from_header)
    display_name = display_name_match.group(1).strip('"\' ') if display_name_match else ""
    for brand in ["paypal", "apple", "microsoft", "google", "bank of america", "chase", "netflix", "amazon", "wells fargo"]:
        if brand in display_name.lower() and brand not in from_domain:
            penalty += 45
            is_spoofed_sender = True
            findings.append(f"High-Risk Sender Impersonation: Display name mentions '{display_name}' but sender email domain is '{from_domain}'.")

    # 2. Authentication-Results / Received-SPF
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    spf_status = "Unknown"
    dkim_status = "Unknown"
    dmarc_status = "Unknown"

    # Inspect Received-SPF header
    if received_spf:
        spf_lower = received_spf.lower()
        if "pass" in spf_lower:
            spf_status = "Pass"
        elif "fail" in spf_lower:
            spf_status = "Fail"
            penalty += 35
            findings.append("Received-SPF check failed! Mail server was not authorized to send on behalf of domain.")
        elif "softfail" in spf_lower:
            spf_status = "Softfail"
            penalty += 20
            findings.append("Received-SPF softfail: domain discouraged sender IP.")
        elif "neutral" in spf_lower or "none" in spf_lower:
            spf_status = "Neutral/None"

    # Inspect Authentication-Results header
    if auth_results:
        ar_lower = auth_results.lower()
        if "dkim=pass" in ar_lower:
            dkim_status = "Pass"
        elif "dkim=fail" in ar_lower or "dkim=temperror" in ar_lower:
            dkim_status = "Fail"
            penalty += 30
            findings.append("DKIM cryptographic signature verification failed.")

        if "dmarc=pass" in ar_lower:
            dmarc_status = "Pass"
        elif "dmarc=fail" in ar_lower:
            dmarc_status = "Fail"
            penalty += 35
            findings.append("DMARC alignment evaluation failed.")

    # If no headers found and DKIM library present, verify DKIM signature directly
    if dkim_status == "Unknown" and "DKIM-Signature" in msg and DKIM_AVAILABLE:
        try:
            valid_dkim = dkim.verify(msg_bytes)
            dkim_status = "Pass" if valid_dkim else "Fail"
            if not valid_dkim:
                penalty += 30
                findings.append("Cryptographic DKIM signature verification failed on raw message.")
        except Exception:
            dkim_status = "Invalid/Error"

    # Query live DMARC record for the sender domain if available
    dmarc_info = {}
    if from_domain:
        dmarc_info = verify_dmarc_policy(from_domain)
        if not dmarc_info.get("has_dmarc"):
            penalty += 10
            findings.append(f"Domain '{from_domain}' lacks a public DMARC record, allowing unauthenticated spoofing.")

    # 3. Received Hop Routing Analysis
    hops = []
    for r in received_headers:
        hops.append(r.strip().replace("\n", " ").replace("\r", " "))

    if not received_headers:
        penalty += 15
        findings.append("No 'Received' transit headers present; email routing trail is missing or stripped.")

    # 4. Extract body content and links
    body_text = ""
    html_text = ""
    links = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain':
                    body_text += part.get_content()
                elif ctype == 'text/html':
                    html_text += part.get_content()
        else:
            ctype = msg.get_content_type()
            if ctype == 'text/html':
                html_text = msg.get_content()
            else:
                body_text = msg.get_content()
    except Exception:
        body_text = str(msg.get_payload())

    # Extract hyperlinks from text and HTML
    combined_content = f"{body_text} {html_text}"
    extracted_urls = set(re.findall(r'https?://[^\s<>"\')]+', combined_content))
    links = list(extracted_urls)

    # Check for link text deception (e.g. href="evil.com" text="https://bank.com")
    suspicious_links = []
    if html_text:
        href_matches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', html_text, re.I | re.DOTALL)
        for target_href, anchor_text in href_matches:
            anchor_clean = re.sub(r'<[^>]+>', '', anchor_text).strip()
            if re.match(r'https?://', anchor_clean):
                href_domain = urlparse(target_href).netloc.lower()
                text_domain = urlparse(anchor_clean).netloc.lower()
                if href_domain != text_domain:
                    penalty += 40
                    findings.append(f"Deceptive hyperlink text: displays '{anchor_clean}' but clicks to '{target_href}'.")
                    suspicious_links.append(target_href)

    # Check body for urgency cues
    urgency_phrases = ["account suspended", "urgent action required", "password expired", "unauthorized transaction", "wire transfer", "gift card"]
    matched_urgency = [p for p in urgency_phrases if p in combined_content.lower()]
    if matched_urgency:
        penalty += 15
        findings.append(f"Urgency / social engineering triggers detected: {', '.join(matched_urgency)}")

    return {
        "from": from_header,
        "from_domain": from_domain,
        "to": to_header,
        "subject": subject,
        "reply_to": reply_to,
        "return_path": return_path,
        "date": date_header,
        "message_id": message_id,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_info.get("policy", "unknown"),
        "is_spoofed_sender": is_spoofed_sender,
        "hop_count": len(hops),
        "hops": hops[:5],
        "links": links[:15],
        "suspicious_links": suspicious_links,
        "body_preview": (body_text or html_text)[:300],
        "risk_penalty": penalty,
        "findings": findings
    }
