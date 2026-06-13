import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from config import Config

def format_url_for_table(url: str, max_len: int = 50) -> str:
    """Inserts zero-width spaces or line breaks to allow long URLs to wrap in PDF tables."""
    if len(url) <= max_len:
        return url
    # Insert spaces or break lines at slash/dot boundaries
    return url.replace('/', '/<font color="grey">&#8203;</font>').replace('?', '?<font color="grey">&#8203;</font>').replace('&', '&<font color="grey">&#8203;</font>')

def generate_pdf_report(scan_data: dict, filename: str = None) -> str:
    """
    Generates a beautifully formatted PDF report for a phishing scan.
    
    Parameters:
      - scan_data: Dictionary containing URL, prediction, risk_score, scan_time, details
      - filename: Optional specific file name. If None, generates dynamically.
      
    Returns:
      The absolute path to the generated PDF.
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
    
    # Custom colors
    PRIMARY = colors.HexColor("#0f172a")      # Slate 900
    SECONDARY = colors.HexColor("#1e293b")    # Slate 800
    ACCENT_BLUE = colors.HexColor("#0ea5e9")  # Sky 500
    
    # Severity colors
    COLOR_PHISHING = colors.HexColor("#ef4444")   # Red 500
    COLOR_SUSPICIOUS = colors.HexColor("#f59e0b") # Amber 500
    COLOR_LEGITIMATE = colors.HexColor("#10b981") # Emerald 500
    
    # Custom styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.white,
        spaceAfter=15,
        alignment=1 # Centered
    )
    
    h1_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=PRIMARY,
        spaceBefore=12,
        spaceAfter=8,
        borderPadding=2
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    
    body_bold = ParagraphStyle(
        'ReportBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    body_white = ParagraphStyle(
        'ReportBodyWhite',
        parent=body_style,
        textColor=colors.white
    )
    
    url_style = ParagraphStyle(
        'UrlStyle',
        parent=body_style,
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )
    
    story = []
    
    # --- HEADER BANNER ---
    pred = scan_data.get('prediction', 'Unknown')
    if pred == 'Phishing':
        banner_color = COLOR_PHISHING
        banner_txt = "CRITICAL THREAT DETECTED: PHISHING SITE"
    elif pred == 'Suspicious':
        banner_color = COLOR_SUSPICIOUS
        banner_txt = "WARNING: SUSPICIOUS ACTIVITY DETECTED"
    else:
        banner_color = COLOR_LEGITIMATE
        banner_txt = "VERIFIED CLEAN: LEGITIMATE DOMAIN"
        
    header_data = [
        [Paragraph(f"<b>AI PHISHING DETECTION SYSTEM</b>", title_style)],
        [Paragraph(f"<b>{banner_txt}</b>", ParagraphStyle('BannerText', parent=title_style, fontSize=12, spaceAfter=0))]
    ]
    
    header_table = Table(header_data, colWidths=[7.2*inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), banner_color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 12),
    ]))
    
    story.append(header_table)
    story.append(Spacer(1, 15))
    
    # --- OVERVIEW TABLE ---
    details = scan_data.get('details', {})
    risk_score = scan_data.get('risk_score', 0)
    
    overview_data = [
        [
            Paragraph("<b>Target URL:</b>", body_bold),
            Paragraph(format_url_for_table(scan_data.get('url', '')), url_style)
        ],
        [
            Paragraph("<b>Scan Timestamp:</b>", body_bold),
            Paragraph(scan_data.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")), body_style)
        ],
        [
            Paragraph("<b>AI Risk Score:</b>", body_bold),
            Paragraph(f"<font color='{banner_color.hexval()}'><b>{risk_score}%</b></font> (Model Confidence: {scan_data.get('confidence', 0.0)*100:.2f}%)", body_bold)
        ],
        [
            Paragraph("<b>Verdict:</b>", body_bold),
            Paragraph(f"<font color='{banner_color.hexval()}'><b>{pred.upper()}</b></font>", body_bold)
        ]
    ]
    
    overview_table = Table(overview_data, colWidths=[1.8*inch, 5.4*inch])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(Paragraph("Scan Metadata Overview", h1_style))
    story.append(overview_table)
    story.append(Spacer(1, 12))
    
    # --- MACHINE LEARNING FEATURE METRICS ---
    features = details.get('features', {})
    if features:
        story.append(Paragraph("URL Structural & Heuristic Indicators", h1_style))
        
        feature_rows = [
            [Paragraph("<b>Feature Identifier</b>", body_bold), Paragraph("<b>Analyzed Value</b>", body_bold), Paragraph("<b>Risk Factor</b>", body_bold)]
        ]
        
        feature_mapping = {
            "url_length": ("URL Length", lambda v: f"{v} characters", lambda v: "Elevated risk if > 75 chars" if v > 75 else "Standard length"),
            "domain_length": ("Domain Length", lambda v: f"{v} characters", lambda v: "Suspiciously long" if v > 24 else "Standard length"),
            "num_dots": ("Number of Dots", lambda v: str(v), lambda v: "High (subdomain nesting)" if v > 3 else "Normal"),
            "num_hyphens": ("Number of Hyphens", lambda v: str(v), lambda v: "High (looks like phishing word linking)" if v > 1 else "Normal"),
            "num_digits": ("Number of Digits", lambda v: str(v), lambda v: "High (typical in spam domains)" if v > 3 else "Normal"),
            "has_ip": ("Presence of IP Address", lambda v: "Yes" if v else "No", lambda v: "CRITICAL: IP used instead of domain!" if v else "Normal (Domain Name Used)"),
            "has_at": ("Presence of '@' Symbol", lambda v: "Yes" if v else "No", lambda v: "HIGH: Obfuscates domain!" if v else "Normal"),
            "has_https": ("HTTPS Encryption", lambda v: "HTTPS Enabled" if v else "No HTTPS", lambda v: "Normal" if v else "HIGH: Lacks secure transmission!"),
            "num_subdomains": ("Subdomains Count", lambda v: str(v), lambda v: "Elevated" if v > 1 else "Normal"),
            "suspicious_keywords": ("Suspicious Keywords", lambda v: str(v), lambda v: f"HIGH: Found {v} brand/login keywords!" if v > 0 else "None detected"),
            "entropy": ("Entropy Score (Randomness)", lambda v: f"{v:.4f}", lambda v: "Very high (likely generated domain)" if v > 4.5 else "Standard randomness"),
            "is_shortener": ("URL Shortener Used", lambda v: "Yes" if v else "No", lambda v: "WARNING: Obfuscated URL redirection" if v else "Normal"),
            "has_redirect": ("Redirects Encountered", lambda v: "Yes" if v else "No", lambda v: "WARNING: Path redirects to another target" if v else "No redirection detected")
        }
        
        for f_key, (name, val_formatter, desc_formatter) in feature_mapping.items():
            if f_key in features:
                val = features[f_key]
                desc = desc_formatter(val)
                
                # Make risk factors red if bad
                if "CRITICAL" in desc or "HIGH" in desc or "WARNING" in desc:
                    desc_p = Paragraph(f"<font color='red'><b>{desc}</b></font>", body_style)
                elif "Elevated" in desc:
                    desc_p = Paragraph(f"<font color='orange'><b>{desc}</b></font>", body_style)
                else:
                    desc_p = Paragraph(desc, body_style)
                    
                feature_rows.append([
                    Paragraph(name, body_style),
                    Paragraph(val_formatter(val), body_style),
                    desc_p
                ])
                
        feature_table = Table(feature_rows, colWidths=[2.2*inch, 1.8*inch, 3.2*inch])
        feature_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('PADDING', (0,0), (-1,-1), 4),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        
        story.append(feature_table)
        story.append(Spacer(1, 12))
        
    # --- DOMAIN INTELLIGENCE ---
    whois_info = details.get('whois', {})
    ssl_info = details.get('ssl', {})
    dns_info = details.get('dns', {})
    
    intel_story = []
    
    if whois_info or ssl_info or dns_info:
        intel_story.append(Paragraph("Threat Intelligence & Cryptographic Validation", h1_style))
        
        # WHOIS & SSL combined details
        intel_data = [
            [Paragraph("<b>Domain Registrar:</b>", body_bold), Paragraph(whois_info.get('registrar', 'Unknown'), body_style)],
            [Paragraph("<b>Domain Age:</b>", body_bold), Paragraph(f"{whois_info.get('domain_age_days', -1)} Days (Created: {whois_info.get('creation_date', 'N/A')})", body_style)],
            [Paragraph("<b>Domain Expiration:</b>", body_bold), Paragraph(str(whois_info.get('expiration_date', 'N/A')), body_style)],
            [Paragraph("<b>SSL Certificate:</b>", body_bold), Paragraph(ssl_info.get('status', 'No Certificate Found'), body_style)],
            [Paragraph("<b>SSL Issuer:</b>", body_bold), Paragraph(ssl_info.get('issuer', 'N/A'), body_style)],
            [Paragraph("<b>SSL Validity:</b>", body_bold), Paragraph(f"Valid to {ssl_info.get('valid_to', 'N/A')} ({ssl_info.get('days_remaining', -1)} days left)", body_style)]
        ]
        
        intel_table = Table(intel_data, colWidths=[2.0*inch, 5.2*inch])
        intel_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        intel_story.append(intel_table)
        intel_story.append(Spacer(1, 8))
        
        # DNS Records
        if dns_info and dns_info.get('A'):
            dns_data = [
                [Paragraph("<b>DNS Record</b>", body_bold), Paragraph("<b>Resolved Values</b>", body_bold)]
            ]
            for r_type in ["A", "MX", "NS", "TXT"]:
                records = dns_info.get(r_type, [])
                if records:
                    val_str = ", ".join(records[:5])  # Max 5 to avoid blowup
                    if len(records) > 5:
                        val_str += f" (+{len(records)-5} more)"
                    dns_data.append([
                        Paragraph(f"<b>{r_type}</b>", body_bold),
                        Paragraph(val_str, url_style)
                    ])
            
            dns_table = Table(dns_data, colWidths=[1.5*inch, 5.7*inch])
            dns_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
                ('PADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            intel_story.append(dns_table)
            
        story.append(KeepTogether(intel_story))
        
    # --- DISCLAIMER ---
    story.append(Spacer(1, 20))
    disc_data = [[
        Paragraph("<b>Disclaimer:</b> This report is generated programmatically using machine learning models and public threat intelligence resources. A verification classification of 'Legitimate' does not guarantee the URL is completely secure, nor does 'Phishing' act as a legal declaration. Exercise security protocols when interacting with flagged items.", ParagraphStyle('DiscText', parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor("#64748b")))
    ]]
    disc_table = Table(disc_data, colWidths=[7.2*inch])
    disc_table.setStyle(TableStyle([
        ('LINEABOVE', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(disc_table)

    # Build the document
    doc.build(story)
    return pdf_path
