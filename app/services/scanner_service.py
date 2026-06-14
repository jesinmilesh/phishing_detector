import re
from datetime import datetime
from app import app, db_manager, predictor, app_logger, security_logger
from app.services.whois_lookup import lookup_whois
from app.services.dns_lookup import lookup_dns
from app.services.ssl_checker import check_ssl
from app.services.report_generator import generate_pdf_report
from app.services.email_service import send_security_alert_email

def run_url_analysis(url: str, user_id: int) -> dict:
    """Executes prediction, WHOIS, DNS, and SSL scanning, logging the scan."""
    # Ensure scheme
    scanned_url = url.strip()
    if not re.match(r'^https?://', scanned_url, re.IGNORECASE):
        scanned_url = "http://" + scanned_url
        
    # 1. Model Prediction (online features included since we are scanning)
    pred_result = predictor.predict(scanned_url, online=True)
    
    # 2. Threat Intel Gather
    whois_res = lookup_whois(scanned_url)
    dns_res = lookup_dns(scanned_url)
    ssl_res = check_ssl(scanned_url)
    
    # 3. Assemble Details
    details = {
        "features": pred_result["features"],
        "whois": whois_res,
        "dns": dns_res,
        "ssl": ssl_res,
        "model_used": pred_result["model_used"]
    }
    
    # Adjust prediction based on threat intel (e.g. no SSL, very young domain)
    risk_score = pred_result["risk_score"]
    prediction = pred_result["prediction"]
    confidence = pred_result["confidence"]
    
    # Custom intelligence adjustments
    # If domain age < 15 days, inflate risk score
    if whois_res["domain_age_days"] != -1 and whois_res["domain_age_days"] < 15:
        risk_score = min(100, risk_score + 15)
    # If no SSL and was suspicious, elevate to Phishing
    if not ssl_res["has_ssl"] and prediction == "Suspicious":
        risk_score = min(100, risk_score + 10)
        
    # Recalculate final verdict
    if risk_score >= 70:
        prediction = "Phishing"
    elif risk_score >= 35:
        prediction = "Suspicious"
    else:
        prediction = "Legitimate"
        
    # Log to SQLite
    scan_id = db_manager.log_scan(
        user_id=user_id,
        url=scanned_url,
        prediction=prediction,
        confidence=confidence,
        risk_score=risk_score,
        details_dict=details
    )
    
    # Create notification
    if prediction in ["Phishing", "Suspicious"]:
        db_manager.add_notification(
            user_id,
            "Threat Detected",
            f"Phishing threat detected! Target URL: {scanned_url[:50]}... Risk Score: {risk_score}%",
            "threat_detected"
        )
    else:
        db_manager.add_notification(
            user_id,
            "Successful Scan",
            f"URL scan completed. Verdict: Legitimate for {scanned_url[:50]}...",
            "scan_success"
        )
    
    # 4. Generate PDF Report right away
    scan_record = {
        "id": scan_id,
        "url": scanned_url,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "details": details
    }
    
    pdf_filename = f"report_scan_{scan_id}.pdf"
    pdf_path = generate_pdf_report(scan_record, pdf_filename)
    
    # Store report record in DB
    db_manager.create_report(scan_id, pdf_path)
    
    app_logger.info(f"URL SCAN | ID: {scan_id} | URL: {scanned_url} | Verdict: {prediction} | Risk: {risk_score}% | User ID: {user_id}")
    if prediction == "Phishing" or risk_score >= 70:
        security_logger.warning(f"HIGH RISK THREAT DETECTED | ID: {scan_id} | URL: {scanned_url} | Verdict: {prediction} | Risk: {risk_score}% | User ID: {user_id}")
        user = db_manager.get_user_by_id(user_id)
        if user:
            send_security_alert_email(
                user["email"],
                user["username"],
                "Critical Phishing Indicator Resolved",
                f"A scan submitted under your credentials identified a critical phishing site risk:<br><strong>Target URL:</strong> {scanned_url}<br><strong>Risk Score:</strong> {risk_score}%<br><strong>Confidence:</strong> {confidence}%"
            )
        
    scan_record["scan_id"] = scan_id
    scan_record["pdf_filename"] = pdf_filename
    return scan_record
