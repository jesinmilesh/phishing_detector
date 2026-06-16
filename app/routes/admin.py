# app/routes/admin.py
import os
import threading
from datetime import datetime
from flask import render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.utils import secure_filename

from app import app, db_manager, limiter, csrf
from app.config import Config
from app.utils.helpers import login_required

# MLOps Thread State
training_lock = threading.Lock()
training_in_progress = False
training_status = "Idle"
training_error = None
training_start_time = None

def run_training_async():
    global training_in_progress, training_status, training_error, training_start_time
    with training_lock:
        training_in_progress = True
        training_status = "Deduplicating and preparing datasets..."
        training_error = None
        training_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        from ml.training.train import train_and_evaluate_models
        
        # 1. Automatic Retraining
        training_status = "Training and evaluating candidate models (Random Forest, Gradient Boosting, XGBoost, LightGBM, Logistic Regression)..."
        best_name, best_metrics = train_and_evaluate_models()
        
        # 2. Complete status update
        training_status = f"Completed successfully! Selected {best_name} (F1: {best_metrics['f1_score']:.4f})"
    except Exception as e:
        training_status = "Failed"
        training_error = str(e)
    finally:
        with training_lock:
            training_in_progress = False

@app.route('/admin/ml')
@login_required
def admin_ml_dashboard():
    # Role checking
    user = db_manager.get_user_by_id(session['user']['id'])
    if not user or user.get('role') != 'admin':
        flash("Access denied. Administrator privileges required.", "danger")
        return redirect(url_for('index'))

    pref = db_manager.get_preferences_by_user_id(session['user']['id']) or {}
    models = db_manager.get_model_versions()
    active_model = db_manager.get_active_model()
    
    # Calculate dataset stats
    dataset_files = []
    total_records = 0
    datasets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'datasets')
    if os.path.exists(datasets_dir):
        for f in os.listdir(datasets_dir):
            if f.endswith('.csv'):
                p = os.path.join(datasets_dir, f)
                size_kb = round(os.path.getsize(p) / 1024, 2)
                try:
                    # quick estimate row count
                    with open(p, 'r', encoding='utf-8', errors='ignore') as f_in:
                        rows = sum(1 for _ in f_in) - 1
                except Exception:
                    rows = "Unknown"
                dataset_files.append({"name": f, "size_kb": size_kb, "rows": rows})
                if isinstance(rows, int):
                    total_records += rows
                    
    global training_in_progress, training_status, training_error, training_start_time
    
    return render_template(
        'admin_ml.html',
        user=user,
        pref=pref,
        models=models,
        active_model=active_model,
        dataset_files=dataset_files,
        total_records=total_records,
        training_state={
            "in_progress": training_in_progress,
            "status": training_status,
            "error": training_error,
            "started_at": training_start_time
        }
    )

@app.route('/admin/ml/activate/<int:version>', methods=['POST'])
@login_required
def admin_activate_model(version):
    user = db_manager.get_user_by_id(session['user']['id'])
    if not user or user.get('role') != 'admin':
        return jsonify({"success": False, "error": "Access denied"}), 403

    success = db_manager.set_active_model(version)
    if success:
        flash(f"Successfully activated model version {version}.", "success")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to update database registry"})

@app.route('/admin/ml/retrain', methods=['POST'])
@login_required
def admin_trigger_retraining():
    user = db_manager.get_user_by_id(session['user']['id'])
    if not user or user.get('role') != 'admin':
        return jsonify({"success": False, "error": "Access denied"}), 403

    global training_in_progress
    if training_in_progress:
        return jsonify({"success": False, "error": "Retraining is already in progress."}), 400

    # Start training in background thread
    t = threading.Thread(target=run_training_async)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "message": "ML model retraining started in the background."})

@app.route('/admin/ml/status', methods=['GET'])
@login_required
def admin_ml_status():
    user = db_manager.get_user_by_id(session['user']['id'])
    if not user or user.get('role') != 'admin':
        return jsonify({"success": False, "error": "Access denied"}), 403

    global training_in_progress, training_status, training_error, training_start_time
    return jsonify({
        "in_progress": training_in_progress,
        "status": training_status,
        "error": training_error,
        "started_at": training_start_time
    })

@app.route('/admin/ml/upload-dataset', methods=['POST'])
@login_required
def admin_upload_dataset():
    user = db_manager.get_user_by_id(session['user']['id'])
    if not user or user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('admin_ml_dashboard'))

    if 'dataset_file' not in request.files:
        flash("No file part provided.", "danger")
        return redirect(url_for('admin_ml_dashboard'))

    file = request.files['dataset_file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('admin_ml_dashboard'))

    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        # Append unique timestamp to prevent collisions
        base, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"{base}_{timestamp}{ext}"
        
        datasets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'datasets')
        os.makedirs(datasets_dir, exist_ok=True)
        file_path = os.path.join(datasets_dir, unique_name)
        
        # Safe save
        file.save(file_path)
        
        # Quick check CSV columns validation
        try:
            import pandas as pd
            df = pd.read_csv(file_path, nrows=5)
            df.columns = [col.lower().strip() for col in df.columns]
            has_url = any(col in df.columns for col in ['url', 'url_string', 'link', 'address'])
            has_label = any(col in df.columns for col in ['label', 'class', 'target', 'phish', 'phishing', 'is_phishing'])
            
            if not (has_url and has_label):
                os.remove(file_path)
                flash("Validation failed: CSV must contain 'url' and 'label' columns (or common synonyms).", "danger")
                return redirect(url_for('admin_ml_dashboard'))
        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            flash(f"Failed to parse CSV file: {str(e)}", "danger")
            return redirect(url_for('admin_ml_dashboard'))

        flash(f"Successfully uploaded dataset '{unique_name}'. Retraining is recommended to integrate new samples.", "success")
    else:
        flash("Invalid file format. Only CSV files are allowed.", "danger")

    return redirect(url_for('admin_ml_dashboard'))
