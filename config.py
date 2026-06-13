import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent

class Config:
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
