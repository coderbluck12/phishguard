"""
PDF Security Audit Report Generator
Creates downloadable, branded incident & forensic reports using ReportLab.
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(analysis_type: str, target: str, risk_result: dict, extra_details: dict) -> bytes:
    """
    Generates a PDF audit report.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )
    heading2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontSize=13,
        leading=16,
        textColor=colors.white,
        alignment=1 # Center
    )

    elements = []

    # Header / Branding
    elements.append(Paragraph("<b>PHISHGUARD AI</b> | Incident & Forensic Threat Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Target Type: {analysis_type.upper()}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceAfter=15))

    # Executive Summary Box
    score = risk_result.get("score", 0)
    verdict = risk_result.get("verdict", "UNKNOWN")
    badge_color = colors.HexColor(risk_result.get("badge_color", "#DC2626"))

    summary_data = [
        [
            Paragraph(f"<b>Target Analyzed:</b><br/>{target}", body_style),
            Paragraph(f"<b>Risk Score:</b><br/><b>{score} / 100</b>", body_style),
            Paragraph(f"<b>Verdict:</b><br/><b>{verdict}</b>", badge_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[280, 110, 140])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), colors.HexColor('#F8FAFC')),
        ('BACKGROUND', (2,0), (2,0), badge_color),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Forensic Findings Section
    elements.append(Paragraph("<b>Forensic Analysis & Behavioral Indicators</b>", heading2_style))
    findings = risk_result.get("findings", [])
    if findings:
        findings_data = [[Paragraph(f"• {f}", body_style)] for f in findings]
    else:
        findings_data = [[Paragraph("• No malicious or suspicious indicators detected during inspection.", body_style)]]

    findings_table = Table(findings_data, colWidths=[530])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(findings_table)
    elements.append(Spacer(1, 15))

    # Specific Forensic Parameters Table
    elements.append(Paragraph("<b>Technical Parameter Inspection</b>", heading2_style))
    param_data = [["Parameter", "Observed Value", "Status"]]

    if analysis_type == "url":
        domain_inf = extra_details.get("domain", {})
        ssl_inf = extra_details.get("ssl", {})
        intel_inf = extra_details.get("threat_intel", {})

        param_data.append(["Registered Domain", str(domain_inf.get("registered_domain")), "Analyzed"])
        param_data.append(["Typosquatting Detected", str(domain_inf.get("typosquatting_detected")), "HIGH RISK" if domain_inf.get("typosquatting_detected") else "Normal"])
        param_data.append(["SSL Status", str(ssl_inf.get("status")), "Valid" if ssl_inf.get("status") == "Valid" else "Caution"])
        param_data.append(["SSL Issuer", str(ssl_inf.get("issuer_common_name") or ssl_inf.get("issuer")), "Inspected"])
        param_data.append(["Threat Feed Flagged", str(intel_inf.get("is_flagged")), "Flagged" if intel_inf.get("is_flagged") else "Clean"])
    elif analysis_type == "email":
        param_data.append(["Sender (From)", str(extra_details.get("from")), "Inspected"])
        param_data.append(["Return-Path", str(extra_details.get("return_path")), "Inspected"])
        param_data.append(["SPF Authentication", str(extra_details.get("spf_status")), extra_details.get("spf_status")])
        param_data.append(["DKIM Authentication", str(extra_details.get("dkim_status")), extra_details.get("dkim_status")])
        param_data.append(["DMARC Policy", str(extra_details.get("dmarc_policy")), "Configured" if extra_details.get("dmarc_policy") != "none" else "Weak"])
        param_data.append(["Sender Spoofing Alert", str(extra_details.get("is_spoofed_sender")), "YES" if extra_details.get("is_spoofed_sender") else "None"])

    param_table = Table(param_data, colWidths=[160, 270, 100])
    param_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(param_table)
    elements.append(Spacer(1, 15))

    # Recommended Security Actions
    elements.append(Paragraph("<b>Security Recommendations & Mitigation Playbook</b>", heading2_style))
    recs = risk_result.get("recommendations", [])
    rec_data = [[Paragraph(f"<b>[ACTION]</b> {r}", body_style)] for r in recs]
    rec_table = Table(rec_data, colWidths=[530])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#EFF6FF')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#BFDBFE')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(rec_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
