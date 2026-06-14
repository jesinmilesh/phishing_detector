import os
from flask import render_template, request, jsonify, redirect, url_for, session, flash

from app import app, db_manager, predictor, limiter, csrf
from app.config import Config
from app.utils.helpers import login_required
from app.services.threat_feed import fetch_threat_feed
from app.services.scanner_service import run_url_analysis

@app.route('/')
def index():
    # Unauthenticated visitors go to landing page; logged-in users go to scanner
    if 'user' not in session:
        return render_template('landing.html')
    user = db_manager.get_user_by_id(session['user']['id'])
    return render_template('index.html', user=user)

@app.route('/scanner')
@login_required
def scanner():
    user = db_manager.get_user_by_id(session['user']['id'])
    return render_template('index.html', user=user)

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
    return render_template('reports.html', scans=scans)
