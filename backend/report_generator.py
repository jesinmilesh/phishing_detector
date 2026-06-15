# backend/report_generator.py
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from app.config import Config
from backend.recommendation_engine import RecommendationEngine

def format_url_for_pdf(url: str, max_len: int = 50) -> str:
    """Inserts zero-width breaks in long URLs so they wrap gracefully in PDF tables."""
    if len(url) <= max_len:
        return url
    return url.replace('/', '/<font color="grey">&#8203;</font>').replace('?', '?<font color="grey">&#8203;</font>').replace('&', '&<font color="grey">&#8203;</font>')

def generate_pdf_report(scan_data: dict, filename: str = None) -> str:
    """
    Generates a professional enterprise PDF threat analysis report using ReportLab.
    """
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_scan_{scan_data.get('id', 'temp')}_{timestamp}.pdf"
        
    pdf_path = str(Config.REPORTS_DIR / filename)
    
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Theme Palette (SOC dark mode theme colors matching client-side)
    PRIMARY = colors.HexColor("#0f172a")      # Slate 900
    SECONDARY = colors.HexColor("#1e293b")    # Slate 800
    ACCENT_BLUE = colors.HexColor("#0ea5e9")  # Sky 500
    BORDER_COLOR = colors.HexColor("#cbd5e1")
    
    COLOR_PHISHING = colors.HexColor("#ef4444")
    COLOR_SUSPICIOUS = colors.HexColor("#f59e0b")
    COLOR_LEGITIMATE = colors.HexColor("#10b981")
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        textColor=colors.white,
        spaceAfter=4,
        alignment=1
    )
    
    h1_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        borderPadding=2
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    
    body_bold = ParagraphStyle(
        'DocBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    body_white = ParagraphStyle(
        'DocBodyWhite',
        parent=body_style,
        textColor=colors.white
    )
    
    url_style = ParagraphStyle(
        'UrlText',
        parent=body_style,
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )
    
    story = []
    
    # --- BREADCRUMB HEADER BANNER ---
    pred = scan_data.get('prediction', 'Unknown')
    risk_score = scan_data.get('risk_score', 0)
    confidence = scan_data.get('confidence', 1.0)
    
    rec_data = RecommendationEngine.get_recommendations(pred, risk_score, confidence)
    
    if pred == 'Phishing':
        banner_color = COLOR_PHISHING
        banner_txt = "CRITICAL THREAT FLAG: CONFIRMED PHISHING ENGINE SIGNATURE"
    elif pred == 'Suspicious':
        banner_color = COLOR_SUSPICIOUS
        banner_txt = "SECURITY WARNING: HIGH SUSPICION ANOMALIES IDENTIFIED"
    else:
        banner_color = COLOR_LEGITIMATE
        banner_txt = "VERIFIED INTACT: RESOURCE IDENTIFIED AS LEGITIMATE"
        
    header_data = [
        [Paragraph(f"<b>AI SHIELD - THREAT INTELLIGENCE SYSTEM</b>", title_style)],
        [Paragraph(f"<b>{banner_txt}</b>", ParagraphStyle('BannerSub', parent=title_style, fontSize=10, spaceAfter=0))]
    ]
    
    header_table = Table(header_data, colWidths=[7.2*inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), banner_color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
    ]))
    
    story.append(header_table)
    story.append(Spacer(1, 10))
    
    # --- EXECUTIVE REPORT METADATA ---
    report_id = f"REP-{scan_data.get('id', 1):05d}"
    analyst = scan_data.get('username', 'System SOC Node')
    
    overview_data = [
        [Paragraph("<b>Report Identifier:</b>", body_bold), Paragraph(report_id, body_style)],
        [Paragraph("<b>Scanned Resource URL:</b>", body_bold), Paragraph(format_url_for_pdf(scan_data.get('url', '')), url_style)],
        [Paragraph("<b>Scan Timestamp:</b>", body_bold), Paragraph(scan_data.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")), body_style)],
        [Paragraph("<b>Threat Category:</b>", body_bold), Paragraph(f"{rec_data['threat_category']} ({rec_data['threat_level']} SEVERITY)", body_bold)],
        [Paragraph("<b>ML Threat Score:</b>", body_bold), Paragraph(f"<font color='{banner_color.hexval()}'><b>{risk_score}%</b></font> (Model Confidence: {rec_data['confidence_score']}%)", body_bold)],
        [Paragraph("<b>Generated By:</b>", body_bold), Paragraph(analyst, body_style)]
    ]
    
    overview_table = Table(overview_data, colWidths=[1.8*inch, 5.4*inch])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    
    story.append(Paragraph("Executive Summary & Metadata", h1_style))
    story.append(overview_table)
    story.append(Spacer(1, 10))
    
    # --- SECURITY RECOMMENDATIONS ENGINE OUTPUT ---
    story.append(Paragraph("Remediation & Actionable Recommendations", h1_style))
    
    rec_list_paragraphs = []
    for r in rec_data['recommendations']:
        rec_list_paragraphs.append(Paragraph(f"• {r}", body_style))
        
    rec_table_data = [[
        Paragraph(f"<b>Posture Verdict Summary:</b><br/>{rec_data['summary']}", body_bold)
    ]]
    for p in rec_list_paragraphs:
        rec_table_data.append([p])
        
    rec_table = Table(rec_table_data, colWidths=[7.2*inch])
    rec_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 10))
    
    # --- DOMAIN INFORMATION & THREAT INTEL ---
    details = scan_data.get('details', {})
    whois_info = details.get('whois', {})
    ssl_info = details.get('ssl', {})
    dns_info = details.get('dns', {})
    
    intel_story = []
    intel_story.append(Paragraph("Network & Threat Intelligence Feed Correlation", h1_style))
    
    intel_data = [
        [Paragraph("<b>Domain Registrar:</b>", body_bold), Paragraph(whois_info.get('registrar', 'Unknown / Protected'), body_style)],
        [Paragraph("<b>Domain Age (Days):</b>", body_bold), Paragraph(f"{whois_info.get('domain_age_days', -1)} days (Registered: {whois_info.get('creation_date', 'N/A')})", body_style)],
        [Paragraph("<b>SSL Certificate:</b>", body_bold), Paragraph(ssl_info.get('status', 'No SSL Configured'), body_style)],
        [Paragraph("<b>SSL Issuer Authority:</b>", body_bold), Paragraph(ssl_info.get('issuer', 'N/A'), body_style)],
        [Paragraph("<b>SSL Expiration Days:</b>", body_bold), Paragraph(f"{ssl_info.get('days_remaining', -1)} days remaining", body_style)]
    ]
    
    intel_table = Table(intel_data, colWidths=[2.0*inch, 5.2*inch])
    intel_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    intel_story.append(intel_table)
    intel_story.append(Spacer(1, 6))
    
    # DNS Records
    if dns_info:
        dns_records_rows = []
        for r_type in ["A", "MX", "NS"]:
            records = dns_info.get(r_type, [])
            if records:
                dns_records_rows.append([
                    Paragraph(f"<b>DNS {r_type}:</b>", body_bold),
                    Paragraph(", ".join(records[:4]), url_style)
                ])
        if dns_records_rows:
            dns_table = Table(dns_records_rows, colWidths=[2.0*inch, 5.2*inch])
            dns_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
                ('PADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            intel_story.append(dns_table)
            
    story.append(KeepTogether(intel_story))
    
    # --- DISCLAIMER ---
    story.append(Spacer(1, 15))
    disc_text = "<b>Disclaimer:</b> AI Shield generates this threat validation using machine learning classifiers, cryptographic certificates audits, and global threat feed parameters. Content structure is simulated for advisory purposes. Block domains in network devices with care."
    disc_table = Table([[Paragraph(disc_text, ParagraphStyle('Disc', parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor("#64748b")))]], colWidths=[7.2*inch])
    disc_table.setStyle(TableStyle([
        ('LINEABOVE', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(disc_table)
    
    doc.build(story)
    return pdf_path
