"""
SSL Certificate Inspection Module
Connects to host, inspects TLS handshake, checks issuer, expiry, SANs, and self-signed status.
"""
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse

def inspect_ssl_certificate(target: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Inspects SSL/TLS certificate of target hostname or URL.
    Returns certificate validity, issuer, dates, SANs, and risk flags.
    """
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        hostname = target.split("/")[0].split(":")[0]

    # If port is 80 or scheme was HTTP explicitly, flag lack of SSL
    if target.startswith("http://") and not target.startswith("https://"):
        return {
            "has_ssl": False,
            "status": "Insecure (Plain HTTP)",
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": 0,
            "subject_alt_names": [],
            "is_expired": False,
            "is_self_signed": False,
            "risk_score_penalty": 30,
            "finding": "Plaintext HTTP connection. Credentials and data are transmitted unencrypted."
        }

    context = ssl.create_default_context()
    # Allow fallback probe to inspect invalid/self-signed certs safely
    unverified_context = ssl._create_unverified_context()

    cert_info = {}
    is_valid = False
    is_self_signed = False
    is_expired = False
    error_msg = None

    try:
        # First attempt: standard verified TLS
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                is_valid = True
    except ssl.SSLCertVerificationError as e:
        error_msg = f"SSL Verification Failed: {str(e)}"
        # Second attempt: fetch raw cert details even if untrusted/expired
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
        except Exception as inner_e:
            return {
                "has_ssl": False,
                "status": "SSL Handshake Error",
                "error": f"{error_msg} / {str(inner_e)}",
                "risk_score_penalty": 35,
                "finding": "SSL certificate failed verification and could not be retrieved."
            }
    except Exception as e:
        return {
            "has_ssl": False,
            "status": "No SSL / Connection Refused",
            "error": str(e),
            "risk_score_penalty": 25,
            "finding": f"Unable to establish TLS connection: {str(e)}"
        }

    # Extract certificate attributes
    try:
        # Issuer
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        issuer_common_name = issuer_dict.get('commonName', 'Unknown Issuer')
        issuer_org = issuer_dict.get('organizationName', issuer_common_name)

        # Subject
        subject_dict = dict(x[0] for x in cert.get('subject', []))
        subject_common_name = subject_dict.get('commonName', 'Unknown')
        
        # Check self-signed
        if issuer_common_name == subject_common_name and issuer_org == subject_dict.get('organizationName', ''):
            is_self_signed = True

        # Validity dates
        not_before_str = cert.get('notBefore')
        not_after_str = cert.get('notAfter')
        
        valid_from = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc) if not_before_str else None
        valid_until = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc) if not_after_str else None
        
        now = datetime.now(timezone.utc)
        days_remaining = (valid_until - now).days if valid_until else 0
        if days_remaining < 0:
            is_expired = True

        # Subject Alt Names (SAN)
        san_list = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0] == 'DNS']

        # Risk penalty calculation
        penalty = 0
        findings = []
        if not is_valid:
            penalty += 35
            findings.append("Certificate failed trusted root validation.")
        if is_self_signed:
            penalty += 30
            findings.append("Self-signed certificate detected, typical of phishing infrastructure.")
        if is_expired:
            penalty += 25
            findings.append(f"Certificate is expired ({abs(days_remaining)} days ago).")
        elif days_remaining < 7:
            penalty += 10
            findings.append(f"Certificate expiring soon ({days_remaining} days left).")

        # Free Automated cert check (e.g. Let's Encrypt / cPanel) is common on phishing
        is_free_automated_ca = any(ca in issuer_common_name.lower() for ca in ["let's encrypt", "cpanel", "zerossl", "cloud flare"])
        if is_free_automated_ca:
            findings.append(f"Issued by automated CA ({issuer_common_name}); commonly utilized by disposable phishing campaigns.")

        return {
            "has_ssl": True,
            "status": "Valid" if (is_valid and not is_expired and not is_self_signed) else "Suspicious / Invalid",
            "issuer": issuer_org,
            "issuer_common_name": issuer_common_name,
            "subject": subject_common_name,
            "valid_from": valid_from.isoformat() if valid_from else None,
            "valid_until": valid_until.isoformat() if valid_until else None,
            "days_remaining": days_remaining,
            "subject_alt_names": san_list[:10],
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "is_free_automated_ca": is_free_automated_ca,
            "risk_score_penalty": penalty,
            "finding": "; ".join(findings) if findings else "SSL certificate is valid and issued by a recognized CA."
        }
    except Exception as parse_err:
        return {
            "has_ssl": True,
            "status": "Parsing Error",
            "error": str(parse_err),
            "risk_score_penalty": 15,
            "finding": f"SSL connection established but certificate metadata could not be fully parsed: {str(parse_err)}"
        }
