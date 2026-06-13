import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env
load_dotenv(BASE_DIR / '.env')

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
    MODEL_DIR = BASE_DIR / 'models'
    MODEL_DIR.mkdir(exist_ok=True)
    MODEL_PATH = str(MODEL_DIR / 'phishing_model.pkl')
    
    # Reports configuration
    REPORTS_DIR = BASE_DIR / 'reports' / 'generated'
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Uploads configuration (for QR codes and screenshots)
    UPLOAD_DIR = BASE_DIR / 'static' / 'uploads'
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'eml'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    
    # Security Configuration
    RATE_LIMIT = "100 per hour"
    CSRF_ENABLED = True
    
    # Threat Intel Feeds configuration (Simulated URL blacklist or standard APIs)
    THREAT_FEED_URLS = [
        "https://openphish.com/feed.txt",
        "https://phishstats.info/phish_score.txt"
    ]
    
    # Email SMTP configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@ai-shield.local')

