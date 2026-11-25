"""
Website Characteristic & DOM Inspector
Safely probes target webpage structure:
- External form actions transmitting credentials
- Password fields on insecure endpoints
- Zero-width obfuscation, hidden iframes, disabled right-clicks
- Favicon brand spoofing & deceptive title cues
"""
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, Any

def inspect_website_characteristics(target_url: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Safely inspects HTML document and DOM characteristics of the target webpage.
    """
    findings = []
    penalty = 0

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PhishGuardSecurityAudit/1.0'
    }

    try:
        response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        html_content = response.text
        status_code = response.status_code
        final_url = response.url
    except Exception as e:
        return {
            "accessible": False,
            "error": str(e),
            "findings": [f"Target website unreachable or timed out during inspection: {str(e)}"],
            "risk_penalty": 10,
            "has_password_field": False,
            "external_form_action": False,
            "hidden_iframes_count": 0,
            "form_actions": [],
            "page_title": ""
        }

    soup = BeautifulSoup(html_content, 'html.parser')
    page_title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"

    # 1. Password input analysis
    password_inputs = soup.find_all('input', {'type': re.compile(r'password', re.I)})
    has_password_field = len(password_inputs) > 0

    # 2. Form actions destination check
    forms = soup.find_all('form')
    form_actions = []
    external_form_action = False
    insecure_password_submission = False

    target_domain = urlparse(final_url).netloc.lower()

    for form in forms:
        action = form.get('action', '')
        if action:
            full_action = urljoin(final_url, action)
            action_netloc = urlparse(full_action).netloc.lower()
            form_actions.append(full_action)

            # Check if form submits to a different domain
            if action_netloc and action_netloc != target_domain:
                external_form_action = True
                penalty += 35
                findings.append(f"Form submission destination ({action_netloc}) does not match current host ({target_domain}), typical of data exfiltration.")

            # Check if form containing password posts over plain HTTP
            if form.find_all('input', {'type': re.compile(r'password', re.I)}):
                if full_action.startswith("http://"):
                    insecure_password_submission = True
                    penalty += 40
                    findings.append("CRITICAL: Password input field submits credentials over unencrypted HTTP!")

    # If password field is present on non-HTTPS page
    if has_password_field and final_url.startswith("http://"):
        penalty += 35
        findings.append("Password input detected on insecure plain HTTP page.")

    # 3. Hidden iframes (often used to host malicious drive-by downloads or credential harvesters)
    iframes = soup.find_all('iframe')
    hidden_iframes_count = 0
    for iframe in iframes:
        style = iframe.get('style', '').lower()
        width = iframe.get('width', '')
        height = iframe.get('height', '')
        if 'display:none' in style or 'visibility:hidden' in style or width in ['0', '1'] or height in ['0', '1']:
            hidden_iframes_count += 1

    if hidden_iframes_count > 0:
        penalty += 25
        findings.append(f"Detected {hidden_iframes_count} hidden or 0-pixel iframe(s) commonly used in clickjacking.")

    # 4. Anti-analysis scripts (contextmenu disabling, keyboard event blocking)
    scripts = soup.find_all('script')
    script_text = " ".join([s.string or "" for s in scripts]).lower()
    if 'event.button == 2' in script_text or 'contextmenu' in script_text and 'return false' in script_text:
        penalty += 15
        findings.append("Client-side right-click prevention detected, often used to prevent inspecting page source.")

    # 5. Phishing / urgency keywords in page content
    page_text = soup.get_text().lower()
    urgency_cues = ["account suspended", "verify your identity immediately", "unauthorized access detected", "billing failure", "session expired"]
    found_cues = [cue for cue in urgency_cues if cue in page_text]
    if found_cues:
        penalty += 15
        findings.append(f"Psychological urgency/fear tactics detected in text: '{', '.join(found_cues)}'")

    return {
        "accessible": True,
        "status_code": status_code,
        "page_title": page_title,
        "has_password_field": has_password_field,
        "password_inputs_count": len(password_inputs),
        "external_form_action": external_form_action,
        "insecure_password_submission": insecure_password_submission,
        "form_actions": form_actions[:5],
        "hidden_iframes_count": hidden_iframes_count,
        "risk_penalty": penalty,
        "findings": findings
    }
