import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
import logging
from logging.handlers import RotatingFileHandler

from app.config import Config
from database.db_manager import DatabaseManager
from ml.prediction.predict import PhishingPredictor

# Set template and static folders explicitly to point to root directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))
app.config.from_object(Config)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Flask 3.x compatibility patch for Flask-Mail
import flask
import werkzeug.utils
flask.safe_join = werkzeug.utils.safe_join
from flask_mail import Mail

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Database Manager
db_manager = DatabaseManager()

# Initialize ML Predictor
predictor = PhishingPredictor()

# Initialize Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[Config.RATE_LIMIT]
)

# Setup loggers
os.makedirs('logs', exist_ok=True)

def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

app_logger = setup_logger('app_logger', 'logs/app.log')
error_logger = setup_logger('error_logger', 'logs/errors.log', logging.ERROR)
security_logger = setup_logger('security_logger', 'logs/security.log')
email_logger = setup_logger('email_logger', 'logs/email.log')
registration_logger = setup_logger('registration_logger', 'logs/registration.log', logging.DEBUG)

# Error handler and security headers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    security_logger.warning(f"CSRF FAILURE | Path: {request.path} | IP: {request.remote_addr} | Msg: {e.description}")
    if request.path.startswith('/scan/'):
        return jsonify({"success": False, "error": f"CSRF security token invalid: {e.description}"}), 400
    flash("Security token verification failed. Please refresh and try again.", "danger")
    return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self';"
    )
    return response

# Import routes to register them
from app.routes import auth, profile, scanner, main
