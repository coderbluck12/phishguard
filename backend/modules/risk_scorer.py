"""
Composite Phishing Risk Scoring Engine & Recommendation Generator
Combines signals from:
1. Trained Machine Learning Classifier (Random Forest + Gradient Boosting)
2. Approach 2: Siamese Visual Layout Matching & Brand Impersonation Discrepancy
3. URL Anatomical Features
4. Domain Typosquatting / Homoglyph Heuristics
5. SSL Certificate Handshake & Expiry Inspection
6. Website DOM / Form Credential Harvesting Inspection
7. Threat Intelligence Blocklist Feeds
"""
from typing import Dict, Any, List

def calculate_composite_risk(
    threat_intel: Dict[str, Any],
    domain_data: Dict[str, Any],
    url_data: Dict[str, Any],
    ssl_data: Dict[str, Any],
    web_data: Dict[str, Any] = None,
    ml_data: Dict[str, Any] = None,
    visual_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Calculates unified phishing risk score (0-100) and actionable mitigations.
    """
    total_score = 0
    all_findings = []
    category_scores = {
        "visual_siamese": 0,
        "ml_classifier": 0,
        "threat_intel": 0,
        "domain_reputation": 0,
        "url_anatomy": 0,
        "ssl_security": 0,
        "website_characteristics": 0
    }

    # 1. Approach 2: Siamese Visual Brand Impersonation (Max 40)
    if visual_data and visual_data.get("evaluated"):
        if visual_data.get("brand_impersonation_detected"):
            category_scores["visual_siamese"] = 40
            all_findings.append(f"[Visual Siamese AI] {visual_data.get('discrepancy_details')}")
        elif visual_data.get("is_visual_layout_match"):
            all_findings.append(f"[Visual Siamese AI] {visual_data.get('discrepancy_details')}")

    # 2. Machine Learning Probability Weighting (Max 30)
    if ml_data and ml_data.get("ml_evaluated"):
        ml_prob = ml_data.get("phishing_probability", 0.0)
        ml_contrib = round(ml_prob * 30)
        category_scores["ml_classifier"] = ml_contrib
        pred = ml_data.get("prediction", "Unknown")
        conf = ml_data.get("confidence_pct", 0)
        all_findings.append(f"[AI Model] Dual-Ensemble (RF+GB) classified target as '{pred}' with {conf}% confidence.")
        for feat in ml_data.get("notable_features", []):
            all_findings.append(f"[AI Feature Attribution] {feat}")

    # 3. Threat Intel (Max 35)
    if threat_intel.get("is_flagged"):
        category_scores["threat_intel"] = 35
        all_findings.append(f"[Threat Intelligence] {threat_intel.get('details')}")

    # 4. Domain / Typosquatting (Max 25)
    domain_pen = domain_data.get("risk_penalty", 0)
    category_scores["domain_reputation"] = min(domain_pen, 25)
    all_findings.extend([f"[Domain] {f}" for f in domain_data.get("findings", [])])

    # 5. URL Structure (Max 20)
    url_pen = url_data.get("risk_penalty", 0)
    category_scores["url_anatomy"] = min(url_pen, 20)
    all_findings.extend([f"[URL] {f}" for f in url_data.get("findings", [])])

    # 6. SSL Inspection (Max 20)
    ssl_pen = ssl_data.get("risk_score_penalty", 0)
    category_scores["ssl_security"] = min(ssl_pen, 20)
    if ssl_data.get("finding"):
        all_findings.append(f"[SSL] {ssl_data.get('finding')}")

    # 7. Website DOM / Form Inspection (Max 25)
    if web_data:
        web_pen = web_data.get("risk_penalty", 0)
        category_scores["website_characteristics"] = min(web_pen, 25)
        all_findings.extend([f"[Web Content] {f}" for f in web_data.get("findings", [])])

    # Raw score summation
    raw_score = sum(category_scores.values())

    # Direct override: If visual Siamese network detected brand impersonation OR threat intel flagged
    if (visual_data and visual_data.get("brand_impersonation_detected")) or threat_intel.get("is_flagged") or (domain_data.get("typosquatting_detected") and not ssl_data.get("has_ssl")):
        total_score = min(max(raw_score, 88), 100)
    else:
        total_score = min(max(raw_score, 0), 100)

    # Classify Risk Level
    if total_score >= 75:
        risk_level = "CRITICAL PHISHING RISK"
        verdict = "MALICIOUS / PHISHING"
        color = "#EF4444" # Vivid Red
    elif total_score >= 50:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS"
        color = "#F97316" # Orange
    elif total_score >= 25:
        risk_level = "MODERATE RISK"
        verdict = "CAUTION ADVISED"
        color = "#FACC15" # Yellow
    else:
        risk_level = "LOW RISK"
        verdict = "LIKELY LEGITIMATE"
        color = "#10B981" # Emerald Green

    # Actionable Recommendations
    recommendations = generate_recommendations(risk_level, all_findings, ssl_data, domain_data, visual_data)

    return {
        "score": total_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "badge_color": color,
        "category_breakdown": category_scores,
        "findings": all_findings,
        "recommendations": recommendations
    }

def generate_recommendations(risk_level: str, findings: List[str], ssl_data: Dict[str, Any], domain_data: Dict[str, Any], visual_data: Dict[str, Any] = None) -> List[str]:
    """Generates precise mitigation guidelines based on analysis results."""
    recs = []

    if visual_data and visual_data.get("brand_impersonation_detected"):
        recs.append(f"CRITICAL VISUAL ALERT: This site visually clones {visual_data.get('matched_brand')} to harvest credentials. Do not input passwords!")

    if "CRITICAL" in risk_level or "SUSPICIOUS" in risk_level:
        recs.append("DO NOT enter any credentials, passwords, or personal payment information on this page.")
        recs.append("Block or quarantine this destination in perimeter firewalls, email gateways, and DNS resolvers.")
        if domain_data.get("impersonated_brand"):
            recs.append(f"Report domain impersonation to the legitimate security team of {domain_data.get('impersonated_brand').upper()}.")
        recs.append("Report the malicious URL to Google Safe Browsing and Netcraft anti-phishing teams.")
    else:
        recs.append("Destination demonstrates normal domain age and certificate validation parameters.")
        recs.append("Continue to verify sender origin when interacting with high-value financial requests.")

    if not ssl_data.get("has_ssl") or ssl_data.get("is_self_signed"):
        recs.append("Avoid browsing over unencrypted HTTP or ignoring browser TLS handshake warnings.")

    return recs
