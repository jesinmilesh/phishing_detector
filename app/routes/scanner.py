import os
from datetime import datetime
from flask import request, jsonify, redirect, url_for, session, flash, send_file

from app import app, db_manager, limiter, csrf, error_logger
from app.config import Config
from app.utils.helpers import login_required

from app.services.report_generator import generate_pdf_report
from app.services.scanner_service import run_url_analysis


@app.route('/scan/url', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def scan_url():
    user = db_manager.get_user_by_id(session['user']['id'])
    if user and not user.get('is_verified', 0):
        return jsonify({"success": False, "error": "Email verification required. Please verify your email to unlock scanning tools."}), 403
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({"success": False, "error": "URL cannot be empty"}), 400
        
    try:
        scan_record = run_url_analysis(url, session['user']['id'])
        return jsonify({"success": True, "data": scan_record})
    except Exception as e:
        error_logger.error(f"URL SCAN PAGE EXCEPTION: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Scanning error: {str(e)}"}), 500


# ==========================================
# USER PROFILE & SETTINGS ROUTES
# ==========================================


@app.route('/scan', methods=['POST'])
@limiter.limit("30 per hour")
def api_scan():
    """
    REST API endpoint for scanning a URL.
    Expects: JSON { "url": "..." }
    """
    user_id = 1
    if 'user' in session:
        user_id = session['user']['id']
        
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Bad Request. JSON payload with 'url' key is required."}), 400
        
    url = data['url'].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400
        
    try:
        scan_record = run_url_analysis(url, user_id)
        # Format API response
        return jsonify({
            "status": "success",
            "url": scan_record["url"],
            "verdict": scan_record["prediction"],
            "confidence": scan_record["confidence"],
            "risk_score": scan_record["risk_score"],
            "scan_time": scan_record["scan_time"],
            "intelligence": {
                "whois": scan_record["details"]["whois"],
                "dns": scan_record["details"]["dns"],
                "ssl": scan_record["details"]["ssl"]
            },
            "report_download_api": f"/report/download/{scan_record['scan_id']}"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"}), 500

csrf.exempt(api_scan)


@app.route('/history_api', methods=['GET'])
def api_history():
    """REST API endpoint for scan history."""
    scans = db_manager.get_all_scans(limit=50)
    api_scans = []
    for s in scans:
        api_scans.append({
            "id": s["id"],
            "url": s["url"],
            "prediction": s["prediction"],
            "risk_score": s["risk_score"],
            "confidence": s["confidence"],
            "scan_time": s["scan_time"]
        })
    return jsonify(api_scans)


@app.route('/report/<int:scan_id>', methods=['GET'])
def api_report_details(scan_id):
    """REST API endpoint for report analysis details."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(scan)


@app.route('/report/download/<int:scan_id>')
@login_required
def download_report(scan_id):
    """Downloads the generated PDF report for a scan."""
    report = db_manager.get_report_by_scan_id(scan_id)
    if not report:
        # If record is missing, try generating it now
        scan = db_manager.get_scan(scan_id)
        if not scan:
            flash("Scan record not found.", "danger")
            return redirect(url_for('history_page'))
            
        try:
            pdf_filename = f"report_scan_{scan_id}.pdf"
            pdf_path = generate_pdf_report(scan, pdf_filename)
            db_manager.create_report(scan_id, pdf_path)
            return send_file(pdf_path, as_attachment=True)
        except Exception as e:
            flash(f"Failed to generate report PDF: {str(e)}", "danger")
            return redirect(url_for('history_page'))
            
    pdf_path = report['pdf_path']
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    else:
        scan = db_manager.get_scan(scan_id)
        if not scan:
            flash("Scan record not found.", "danger")
            return redirect(url_for('history_page'))
        try:
            generate_pdf_report(scan, os.path.basename(pdf_path))
            return send_file(pdf_path, as_attachment=True)
        except Exception as e:
            flash(f"Report file was missing and failed to re-generate: {str(e)}", "danger")
            return redirect(url_for('history_page'))



