import os
from datetime import datetime
from flask import render_template, request, jsonify, redirect, url_for, session, flash

from app import app, db_manager, predictor, limiter, csrf
from app.config import Config
from app.utils.helpers import login_required
from app.services.threat_feed import fetch_threat_feed
from app.services.scanner_service import run_url_analysis

from backend.analytics_service import AnalyticsService
from backend.history_service import HistoryService
from backend.recommendation_engine import RecommendationEngine

analytics_service = AnalyticsService()
history_service = HistoryService()

@app.route('/')
def index():
    # Unauthenticated visitors go to landing page; logged-in users go to scanner
    if 'user' not in session:
        try:
            db_manager.increment_visit_count()
        except Exception:
            pass
        return render_template('landing.html')
    user = db_manager.get_user_by_id(session['user']['id'])
    stats = db_manager.get_scan_statistics()
    recent_scans = db_manager.get_all_scans(limit=10)
    threats = fetch_threat_feed(limit=7)
    
    total = stats['total_scans']
    det_rate = (((stats['phishing_count'] + stats['suspicious_count']) / total) * 100) if total > 0 else 0.0
    stats['detection_rate'] = round(det_rate, 2)
    
    return render_template(
        'index.html', 
        user=user, 
        stats=stats, 
        recent_scans=recent_scans, 
        threats=threats
    )

@app.route('/scanner')
@login_required
def scanner():
    user = db_manager.get_user_by_id(session['user']['id'])
    stats = db_manager.get_scan_statistics()
    recent_scans = db_manager.get_all_scans(limit=10)
    threats = fetch_threat_feed(limit=7)
    
    total = stats['total_scans']
    det_rate = (((stats['phishing_count'] + stats['suspicious_count']) / total) * 100) if total > 0 else 0.0
    stats['detection_rate'] = round(det_rate, 2)
    
    return render_template(
        'index.html', 
        user=user, 
        stats=stats, 
        recent_scans=recent_scans, 
        threats=threats
    )

@app.route('/dashboard')
@login_required
def dashboard():
    stats = db_manager.get_scan_statistics()
    recent_scans = db_manager.get_all_scans(limit=10)
    threats = fetch_threat_feed(limit=7)
    
    # Calculate detection rate (phishing + suspicious) / total
    total = stats['total_scans']
    if total > 0:
        det_rate = ((stats['phishing_count'] + stats['suspicious_count']) / total) * 100
    else:
        det_rate = 0.0
        
    stats['detection_rate'] = round(det_rate, 2)
    user = db_manager.get_user_by_id(session['user']['id'])
    
    return render_template(
        'dashboard.html', 
        stats=stats, 
        recent_scans=recent_scans,
        threats=threats,
        user=user
    )

@app.route('/history')
@login_required
def history_page():
    if request.args.get('format') == 'json' or request.headers.get('Accept') == 'application/json':
        search_query = request.args.get('search', '').strip()
        prediction = request.args.get('prediction', 'all')
        sort_by = request.args.get('sort', 'date_desc')
        try:
            page = int(request.args.get('page', 1))
        except ValueError:
            page = 1
        try:
            per_page = int(request.args.get('per_page', 10))
        except ValueError:
            per_page = 10
            
        data = db_manager.query_scan_history(
            user_id=session['user']['id'],
            search_query=search_query,
            prediction_filter=prediction,
            sort_by=sort_by,
            page=page,
            per_page=per_page
        )
        return jsonify(data)
        
    scans = db_manager.get_all_scans(limit=100, user_id=session['user']['id'])
    stats = db_manager.get_scan_statistics(user_id=session['user']['id'])
    return render_template('reports.html', scans=scans, stats=stats)

@app.route('/api/visit-count', methods=['GET'])
def get_visit_count_api():
    try:
        count = db_manager.get_visit_count()
        return jsonify({'visits': count})
    except Exception as e:
        return jsonify({'visits': 0, 'error': str(e)}), 500

@app.route('/api/contact', methods=['POST'])
def contact_submit():
    try:
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        subject = data.get('subject', '').strip()
        message = data.get('message', '').strip()
        
        if not name or not email or not message:
            return jsonify({'success': False, 'error': 'Name, email, and message are required.'}), 400
            
        success = db_manager.add_contact_message(name, email, subject, message)
        if success:
            # Send email notification to admin support mailbox
            try:
                from app.services.email_service import send_contact_email
                send_contact_email(name, email, subject, message)
            except Exception as email_err:
                print(f"[CONTACT EMAIL ERROR] Failed to send email: {str(email_err)}")
                
            return jsonify({'success': True, 'message': 'Thank you! Your message has been sent successfully.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save contact message.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/reports')
@login_required
def reports_page():
    return redirect(url_for('history_page'))

@app.route('/analytics')
@login_required
def analytics_page():
    pref = db_manager.get_user_preferences(session['user']['id']) or {}
    user = db_manager.get_user_by_id(session['user']['id'])
    data = analytics_service.get_platform_analytics(user_id=session['user']['id'])
    return render_template('analytics.html', user=user, data=data, pref=pref)

@app.route('/scan_history')
@login_required
def scan_history_page():
    pref = db_manager.get_user_preferences(session['user']['id']) or {}
    user = db_manager.get_user_by_id(session['user']['id'])
    
    search_query = request.args.get('search', '').strip()
    prediction = request.args.get('prediction', 'all')
    sort_by = request.args.get('sort', 'date_desc')
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
        
    data = db_manager.query_scan_history(
        user_id=session['user']['id'],
        search_query=search_query,
        prediction_filter=prediction,
        sort_by=sort_by,
        page=page,
        per_page=15
    )
    return render_template('scan_history.html', user=user, data=data, pref=pref, search_query=search_query, prediction=prediction, sort_by=sort_by)

@app.route('/report_detail/<int:scan_id>')
@login_required
def report_detail_page(scan_id):
    pref = db_manager.get_user_preferences(session['user']['id']) or {}
    user = db_manager.get_user_by_id(session['user']['id'])
    
    scan = history_service.get_scan_details(scan_id, user_id=session['user']['id'])
    if not scan:
        flash("Scan record not found or access denied.", "danger")
        return redirect(url_for('scan_history_page'))
        
    return render_template('report_detail.html', user=user, scan=scan, pref=pref)

@app.route('/api/history/delete/<int:scan_id>', methods=['POST'])
@login_required
def api_delete_scan(scan_id):
    try:
        success = history_service.delete_scan_record(scan_id, user_id=session['user']['id'])
        # Log event in activity
        try:
            conn = db_manager.get_connection()
            conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                         ("delete_scan", session['user']['id'], f"Deleted scan ID {scan_id}"))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/clear', methods=['POST'])
@login_required
def api_clear_history():
    try:
        success = history_service.clear_all_history(user_id=session['user']['id'])
        # Log event in activity
        try:
            conn = db_manager.get_connection()
            conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                         ("clear_history", session['user']['id'], "Cleared all scan history"))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/export')
@login_required
def api_export_history():
    try:
        csv_data = history_service.export_history_csv(user_id=session['user']['id'])
        # Log event in activity
        try:
            conn = db_manager.get_connection()
            conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                         ("export_history", session['user']['id'], "Exported history in CSV format"))
            conn.commit()
            conn.close()
        except Exception:
            pass
            
        from flask import Response
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=scan_history_export_{datetime.now().strftime('%Y%m%d')}.csv"}
        )
    except Exception as e:
        flash(f"Failed to export CSV: {str(e)}", "danger")
        return redirect(url_for('scan_history_page'))

@app.route('/api/reports/generate', methods=['POST'])
@login_required
def api_generate_report():
    try:
        data = request.get_json() or {}
        report_type = data.get('report_type', 'Executive Summary')
        date_range = int(data.get('date_range', 30))
        output_format = data.get('format', 'pdf')
        
        # Get latest scan for this user
        latest_scans = db_manager.get_all_scans(limit=1, user_id=session['user']['id'])
        if not latest_scans:
            return jsonify({'success': False, 'error': 'No scan history exists to build a report.'}), 400
            
        scan_record = latest_scans[0]
        from backend.report_generator import generate_pdf_report as backend_gen_pdf
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_batch_{scan_record['id']}_{timestamp}.pdf"
        scan_record['username'] = session['user']['username']
        
        pdf_path = backend_gen_pdf(scan_record, filename)
        db_manager.create_report(scan_record['id'], pdf_path)
        
        # Log event
        try:
            conn = db_manager.get_connection()
            conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                         ("generate_report", session['user']['id'], f"Generated {report_type} report in {output_format}"))
            conn.commit()
            conn.close()
        except Exception:
            pass
            
        return jsonify({
            'success': True,
            'message': f'{report_type} report created successfully!',
            'filename': filename
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
