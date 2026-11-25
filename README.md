# PhishGuard: AI-Powered Phishing URL, Email & Website Detection Platform

PhishGuard is an advanced, production-grade cybersecurity platform designed to detect social engineering attacks, credential harvesting campaigns, typosquatted web assets, and forged emails.

---

## 🚀 Key Features Implemented

1. **URL Analysis & Reputation Checking**
   - Direct IP host detection (`http://192.168.1.1/login`), `@` delimiter evasion, URL length thresholding, and non-standard network ports.
   - Known shortener resolution (`bit.ly`, `tinyurl.com`, `t.co`) to uncover hidden destination redirect hops.

2. **Suspicious Domain Detection**
   - Brand impersonation detection using Levenshtein edit distance & character substitution models against major brands (PayPal, Apple, Google, Microsoft, Chase, Netflix, etc.).
   - Punycode / IDN homoglyph spoofing detection (`xn--`).
   - Deep subdomain depth analysis (e.g. `login.verify.paypal.evil.com`).
   - DNS record evaluation (A and MX records) and domain age estimation.

3. **SSL Certificate Inspection**
   - Direct TLS handshake socket interrogation.
   - Evaluates certificate authority (CA), expiration timestamp, remaining days, self-signed status, and automated/disposable certificate flags (Let's Encrypt / cPanel).
   - Insecure plaintext HTTP warnings.

4. **Email Header Analysis**
   - RFC 822 / MIME parser evaluating all transit hops (`Received` header analysis).
   - Cryptographic DKIM signature evaluation via `dkimpy`.
   - Sender Policy Framework (`Received-SPF`) inspection.
   - DMARC alignment verification and live `_dmarc` DNS policy resolution.

5. **Sender Identity Verification**
   - Detects mismatches between `From`, `Return-Path`, and `Reply-To`.
   - Flags display name spoofing (e.g. `"PayPal Support" <attacker@gmail.com>`).

6. **Website Characteristics & DOM Inspection**
   - Identifies credential harvesting forms posting passwords to external domains or over unencrypted HTTP.
   - Uncovers zero-pixel or hidden iframes used in clickjacking.
   - Identifies client-side right-click prevention scripts and psychological urgency triggers.

7. **Phishing Risk Scoring Engine**
   - Multi-factor calibrated risk index from **0 (Safe)** to **100 (Critical Threat)**.
   - Detailed penalty score breakdown across Threat Intel, Domain Reputation, URL Anatomy, SSL Security, and Web Characteristics.

8. **Threat Intelligence Integration**
   - Curated threat intelligence feeds and URLhaus / OpenPhish local signature mirror.
   - Flags high-abuse TLDs (`.top`, `.xyz`, `.tk`) combined with brand tokens.

9. **Browser-Friendly Web Interface**
   - Modern SOC dashboard built with Tailwind CSS, animated risk gauges, and tabbed workflows for URLs, Emails, and Simulations.

10. **Security Recommendations & Downloadable PDF Reports**
    - Actionable mitigation playbooks for incident responders and end-users.
    - One-click ReportLab PDF generation with technical evidence tables and forensic indicators.

---

## 🛠️ Getting Started

### 1. Requirements
- Python 3.10+
- Dependencies installed via `pip install -r requirements.txt`

### 2. Start the Server
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 3. Open the Dashboard
Navigate to `http://127.0.0.1:8000/` in any web browser.

---

## 🧪 Demonstration & Safe Testing

- **Simulation 1 (Phishing URL)**: Run `http://login-appleid-verify.com/login` in the URL scanner. Yields score **100/100 (CRITICAL PHISHING RISK)** with brand spoofing and plain HTTP warnings.
- **Simulation 2 (Legitimate URL)**: Run `https://wikipedia.org`. Yields score **0/100 (LIKELY LEGITIMATE)** with valid SSL and clean domain reputation.
- **Simulation 3 (Spoofed Email)**: Load `test_samples/phishing_simulation.eml`. Triggers SPF fail, DKIM fail, Return-Path mismatch, and deceptive hyperlink text alerts.
- **Simulation 4 (Legitimate Email)**: Load `test_samples/legitimate_simulation.eml`. Passes SPF, DKIM, and DMARC checks cleanly.
