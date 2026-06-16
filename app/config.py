import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from env/.env
load_dotenv(BASE_DIR / 'env' / '.env')

class Config:
    BASE_DIR = BASE_DIR
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber_security_soc_secret_key_998811')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    PORT = int(os.environ.get('PORT', 5000))
    
    # Database configuration
    DB_DIR = BASE_DIR / 'database'
    DB_DIR.mkdir(exist_ok=True)
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_DIR / 'phishing.db'}"
    DATABASE_PATH = str(DB_DIR / 'phishing.db')
    
    # Models configuration
    MODEL_DIR = BASE_DIR / 'ml' / 'models'
    MODEL_DIR.mkdir(exist_ok=True)
    MODEL_PATH = str(MODEL_DIR / 'phishing_model.pkl')
    
    # Reports configuration
    REPORTS_DIR = BASE_DIR / 'reports' / 'generated'
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Uploads configuration (for QR codes and screenshots)
    UPLOAD_DIR = BASE_DIR / 'static' / 'uploads'
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'eml'}
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB limit
    
    # Security Configuration
    RATE_LIMIT = "100 per hour"
    CSRF_ENABLED = True
    
    # Threat Intel Feeds configuration (Simulated URL blacklist or standard APIs)
    THREAT_FEED_URLS = [
        "https://openphish.com/feed.txt",
        "https://phishstats.info/phish_score.txt"
    ]
    
    # Email SMTP configuration (Legacy fallback for diagnostic routes in auth.py)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '').strip()
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '').replace(' ', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@ai-shield.local').strip()

    # Resend API Configuration
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '').strip()

    # Application URL Configuration
    # APP_BASE_URL is used to build external URLs (e.g. in verification emails).
    # Set this in your .env to your actual domain (e.g. https://yourdomain.com)
    APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5000').rstrip('/')
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'http')
    # SERVER_NAME must only be set if you need url_for(_external=True) to work.
    # When not deployed on a known domain, leave empty and use APP_BASE_URL instead.
    _server_name = os.environ.get('SERVER_NAME', '')
    if _server_name:
        SERVER_NAME = _server_name


