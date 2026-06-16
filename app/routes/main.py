import os
from datetime import datetime
from flask import render_template, request, jsonify, redirect, url_for, session, flash, send_file

from app import app, db_manager, predictor, limiter, csrf, error_logger
from app.config import Config
from app.utils.helpers import login_required
from app.services.threat_feed import fetch_threat_feed
from app.services.scanner_service import run_url_analysis

from app.services.analytics_service import AnalyticsService
from app.services.history_service import HistoryService
from app.services.recommendation_engine import RecommendationEngine

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
    try:
        pref = db_manager.get_user_preferences(session['user']['id']) or {}
    except Exception as e:
        error_logger.error(f"Error fetching user preferences in analytics: {e}")
        pref = {}
        
    try:
        user = db_manager.get_user_by_id(session['user']['id'])
    except Exception as e:
        error_logger.error(f"Error fetching user profile in analytics: {e}")
        user = {"id": session['user']['id'], "username": session['user']['username'], "role": session['user'].get('role', 'analyst')}
        
    data = analytics_service.get_platform_analytics(user_id=session['user']['id'])
    return render_template('analytics.html', user=user, data=data, pref=pref)

@app.route('/scan_history')
@login_required
def scan_history_page():
    try:
        pref = db_manager.get_user_preferences(session['user']['id']) or {}
    except Exception as e:
        error_logger.error(f"Error fetching user preferences in scan history: {e}")
        pref = {}
        
    try:
        user = db_manager.get_user_by_id(session['user']['id'])
    except Exception as e:
        error_logger.error(f"Error fetching user profile in scan history: {e}")
        user = {"id": session['user']['id'], "username": session['user']['username'], "role": session['user'].get('role', 'analyst')}
    
    search_query = request.args.get('search', '').strip()
    prediction = request.args.get('prediction', 'all')
    sort_by = request.args.get('sort', 'date_desc')
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
        
    try:
        data = db_manager.query_scan_history(
            user_id=session['user']['id'],
            search_query=search_query,
            prediction_filter=prediction,
            sort_by=sort_by,
            page=page,
            per_page=15
        )
    except Exception as e:
        error_logger.error(f"Error querying scan history: {e}")
        data = {
            'scans': [],
            'total_items': 0,
            'total_pages': 0,
            'current_page': page,
            'per_page': 15
        }
        
    return render_template('scan_history.html', user=user, data=data, pref=pref, search_query=search_query, prediction=prediction, sort_by=sort_by)

@app.route('/report_detail/<int:scan_id>')
@login_required
def report_detail_page(scan_id):
    try:
        pref = db_manager.get_user_preferences(session['user']['id']) or {}
    except Exception as e:
        error_logger.error(f"Error fetching user preferences in report detail: {e}")
        pref = {}
        
    try:
        user = db_manager.get_user_by_id(session['user']['id'])
    except Exception as e:
        error_logger.error(f"Error fetching user profile in report detail: {e}")
        user = {"id": session['user']['id'], "username": session['user']['username'], "role": session['user'].get('role', 'analyst')}
    
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
        
        # Get scans for this user
        scans = db_manager.get_all_scans(limit=1000, user_id=session['user']['id'])
        if not scans:
            return jsonify({'success': False, 'error': 'No scan history exists to build a report.'}), 400
            
        # Filter based on date_range
        import datetime as dt
        now = dt.datetime.now()
        filtered_scans = []
        for s in scans:
            try:
                # scan_time format: "YYYY-MM-DD HH:MM:SS"
                scan_date = dt.datetime.strptime(s['scan_time'], "%Y-%m-%d %H:%M:%S")
                if (now - scan_date).days <= date_range:
                    filtered_scans.append(s)
            except Exception:
                filtered_scans.append(s)
                
        # If no scans in the range, fall back to all scans
        if not filtered_scans:
            filtered_scans = scans[:10]  # default fallback to latest 10
            
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format == 'csv':
            import csv
            import io
            from flask import Response
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Report ID', 'Target Resource URL', 'Threat Level', 'Risk Score', 'Scan Date/Time', 'Created By'])
            
            for s in filtered_scans:
                writer.writerow([
                    s['id'],
                    s['url'],
                    s['prediction'],
                    f"{s['risk_score']}%",
                    s['scan_time'],
                    session['user']['username']
                ])
                
            # Log event in activity
            try:
                conn = db_manager.get_connection()
                conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                             ("generate_report", session['user']['id'], f"Generated {report_type} CSV report"))
                conn.commit()
                conn.close()
            except Exception:
                pass
                
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers["Content-Disposition"] = f"attachment; filename=ai_shield_report_{report_type.lower().replace(' ', '_')}_{timestamp}.csv"
            return response
            
        elif output_format == 'json':
            import json
            from flask import Response
            
            export_data = []
            for s in filtered_scans:
                export_data.append({
                    'id': s['id'],
                    'url': s['url'],
                    'prediction': s['prediction'],
                    'risk_score': s['risk_score'],
                    'scan_time': s['scan_time'],
                    'analyst': session['user']['username'],
                    'details': s.get('details', {})
                })
                
            # Log event in activity
            try:
                conn = db_manager.get_connection()
                conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                             ("generate_report", session['user']['id'], f"Generated {report_type} JSON report"))
                conn.commit()
                conn.close()
            except Exception:
                pass
                
            json_str = json.dumps(export_data, indent=4)
            response = Response(json_str, mimetype='application/json')
            response.headers["Content-Disposition"] = f"attachment; filename=ai_shield_report_{report_type.lower().replace(' ', '_')}_{timestamp}.json"
            return response
            
        else: # Default: pdf
            # Get latest scan record to use for PDF report details
            scan_record = filtered_scans[0]
            from app.services.report_generator import generate_pdf_report as backend_gen_pdf
            
            filename = f"report_batch_{scan_record['id']}_{timestamp}.pdf"
            scan_record['username'] = session['user']['username']
            
            pdf_path = backend_gen_pdf(scan_record, filename)
            db_manager.create_report(scan_record['id'], pdf_path)
            
            # Log event
            try:
                conn = db_manager.get_connection()
                conn.execute("INSERT INTO analytics (event_type, user_id, details) VALUES (?, ?, ?)",
                             ("generate_report", session['user']['id'], f"Generated {report_type} PDF report"))
                conn.commit()
                conn.close()
            except Exception:
                pass
                
            return send_file(pdf_path, as_attachment=True, download_name=filename)
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
