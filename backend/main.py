"""
PhishGuard FastAPI Application Entry Point
Exposes REST endpoints for URL inspection, Email EML header analysis,
Live Website characteristics probing, Threat Intel lookups, and PDF generation.
"""
import os
from typing import Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.modules.url_analyzer import analyze_url_structure
from backend.modules.domain_analyzer import analyze_domain
from backend.modules.ssl_inspector import inspect_ssl_certificate
from backend.modules.website_inspector import inspect_website_characteristics
from backend.modules.email_analyzer import analyze_email_message
from backend.modules.risk_scorer import calculate_composite_risk
from backend.modules.report_generator import generate_pdf_report
from backend.threat_intel.intelligence import check_threat_intelligence
from backend.ml.predictor import predict_url_phishing_probability, get_model_metrics
from backend.visual_intel.screenshot_engine import capture_screenshot
from backend.visual_intel.siamese_comparator import compare_siamese_layout
from fastapi.responses import FileResponse

app = FastAPI(
    title="PhishGuard Security Platform API",
    description="Advanced Phishing Detection, Email Forensics & Social Engineering Security Engine",
    version="2.0.0"
)

# Enable CORS for browser frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UrlScanRequest(BaseModel):
    url: str
    deep_web_inspection: bool = True

class EmailTextScanRequest(BaseModel):
    raw_email_headers: str

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "system": "PhishGuard AI Detection Core",
        "model_metrics": get_model_metrics()
    }

@app.get("/api/model/metrics")
def model_metrics_endpoint():
    """Returns trained machine learning model metrics, confusion matrix & feature counts."""
    return get_model_metrics()

@app.post("/api/scan/url")
def scan_url(payload: UrlScanRequest):
    """
    Comprehensive URL, Domain, SSL, Website characteristics & Threat Intel Scan.
    """
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    # 1. URL Anatomy
    url_analysis = analyze_url_structure(target_url)
    clean_url = url_analysis["clean_url"]
    hostname = url_analysis["hostname"]

    # 2. Domain & Typosquatting Check
    domain_analysis = analyze_domain(clean_url)

    # 3. SSL Certificate Handshake & Expiry Inspection
    ssl_analysis = inspect_ssl_certificate(clean_url)

    # 4. Threat Intelligence Feed Lookups
    threat_intel = check_threat_intelligence(clean_url)

    # 5. Machine Learning Classifier Evaluation
    ml_analysis = predict_url_phishing_probability(clean_url)

    # 6. Website Characteristics Inspection
    web_analysis = None
    if payload.deep_web_inspection:
        web_analysis = inspect_website_characteristics(clean_url)

    # 7. Approach 2: Visual Screenshot Capture & Siamese Layout Comparator
    screenshot_res = capture_screenshot(clean_url, output_dir=os.path.join(frontend_dir, "screenshots"))
    visual_analysis = None
    if screenshot_res.get("success"):
        visual_analysis = compare_siamese_layout(screenshot_res["screenshot_path"], clean_url)
        visual_analysis["screenshot_url"] = screenshot_res.get("relative_url")
    else:
        visual_analysis = {
            "evaluated": False,
            "error": screenshot_res.get("error"),
            "screenshot_url": None,
            "visual_similarity_score": 0.0,
            "matched_brand": "None",
            "brand_impersonation_detected": False
        }

    # 8. Composite Risk Scoring & Recommendations
    risk_assessment = calculate_composite_risk(
        threat_intel=threat_intel,
        domain_data=domain_analysis,
        url_data=url_analysis,
        ssl_data=ssl_analysis,
        web_data=web_analysis,
        ml_data=ml_analysis,
        visual_data=visual_analysis
    )

    return {
        "target": target_url,
        "clean_url": clean_url,
        "risk_assessment": risk_assessment,
        "visual_analysis": visual_analysis,
        "ml_analysis": ml_analysis,
        "url_analysis": url_analysis,
        "domain_analysis": domain_analysis,
        "ssl_analysis": ssl_analysis,
        "threat_intel": threat_intel,
        "website_analysis": web_analysis
    }

@app.post("/api/scan/email")
async def scan_email_file(file: UploadFile = File(...)):
    """
    Analyzes an uploaded .EML / RFC-822 email file for spoofing, SPF/DKIM/DMARC and malicious links.
    """
    content = await file.read()
    email_analysis = analyze_email_message(content)

    # Calculate overall risk for email
    email_penalty = email_analysis.get("risk_penalty", 0)
    score = min(max(email_penalty, 0), 100)

    if score >= 70:
        risk_level = "CRITICAL PHISHING RISK"
        verdict = "MALICIOUS / SPOOFED EMAIL"
        color = "#DC2626"
    elif score >= 40:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS EMAIL"
        color = "#EA580C"
    elif score >= 20:
        risk_level = "CAUTION ADVISED"
        verdict = "UNVERIFIED SENDER"
        color = "#EAB308"
    else:
        risk_level = "LOW RISK"
        verdict = "AUTHENTICATED / CLEAN"
        color = "#16A34A"

    recs = []
    if email_analysis.get("is_spoofed_sender"):
        recs.append("CRITICAL: Sender display name does not match sending domain. Do not reply or click links.")
    if email_analysis.get("spf_status") == "Fail" or email_analysis.get("dkim_status") == "Fail":
        recs.append("Email failed cryptographic authentication (SPF/DKIM). Treat as forged.")
    if email_analysis.get("suspicious_links"):
        recs.append(f"Contains deceptive links where display text differs from destination ({len(email_analysis.get('suspicious_links'))} found).")
    if not recs:
        recs.append("Sender authentication passed. Exercise normal vigilance with attachments.")

    risk_assessment = {
        "score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "badge_color": color,
        "findings": email_analysis.get("findings", []),
        "recommendations": recs
    }

    return {
        "filename": file.filename,
        "risk_assessment": risk_assessment,
        "email_analysis": email_analysis
    }

@app.post("/api/scan/email-text")
def scan_email_raw_text(payload: EmailTextScanRequest):
    """Analyzes raw pasted email headers and text."""
    email_analysis = analyze_email_message(payload.raw_email_headers)
    email_penalty = email_analysis.get("risk_penalty", 0)
    score = min(max(email_penalty, 0), 100)

    verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 40 else "CLEAN")
    color = "#DC2626" if score >= 70 else ("#EA580C" if score >= 40 else "#16A34A")

    risk_assessment = {
        "score": score,
        "risk_level": verdict,
        "verdict": verdict,
        "badge_color": color,
        "findings": email_analysis.get("findings", []),
        "recommendations": ["Exercise caution before taking action or replying to this sender."]
    }

    return {
        "filename": "raw_headers.txt",
        "risk_assessment": risk_assessment,
        "email_analysis": email_analysis
    }

@app.post("/api/report/pdf")
def export_pdf_report(payload: dict):
    """
    Generates and returns an incident security audit PDF report.
    """
    analysis_type = payload.get("type", "url")
    target = payload.get("target", "Unknown Target")
    risk_result = payload.get("risk_assessment", {})
    extra_details = payload.get("extra_details", {})

    pdf_bytes = generate_pdf_report(analysis_type, target, risk_result, extra_details)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=PhishGuard_Report_{analysis_type}.pdf"}
    )

@app.get("/api/sample-eml/{filename}")
def get_sample_eml(filename: str):
    """Provides sample simulation EML files for demonstration."""
    safe_name = os.path.basename(filename)
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_samples", safe_name))
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Sample not found")
    return FileResponse(path, media_type="message/rfc822", filename=safe_name)

# Mount frontend static directory
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
