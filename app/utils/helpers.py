import os
from flask import session, flash, redirect, url_for
from app import db_manager
from app.config import Config

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

# Helper function to parse user agent
def parse_user_agent(ua_string):
    if not ua_string:
        return "Unknown Device", "Unknown Browser", "Unknown OS"
    ua_lower = ua_string.lower()
    
    # OS
    os_name = "Unknown OS"
    if "windows" in ua_lower:
        os_name = "Windows"
    elif "macintosh" in ua_lower or "mac os" in ua_lower:
        os_name = "macOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
        
    # Browser
    browser_name = "Unknown Browser"
    if "chrome" in ua_lower or "chromium" in ua_lower:
        if "edg" in ua_lower:
            browser_name = "Edge"
        elif "opr" in ua_lower or "opera" in ua_lower:
            browser_name = "Opera"
        else:
            browser_name = "Chrome"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser_name = "Safari"
    elif "firefox" in ua_lower:
        browser_name = "Firefox"
    elif "msie" in ua_lower or "trident" in ua_lower:
        browser_name = "Internet Explorer"
        
    # Device Name
    device_name = "Desktop PC"
    if "iphone" in ua_lower:
        device_name = "iPhone"
    elif "ipad" in ua_lower:
        device_name = "iPad"
    elif "android" in ua_lower:
        if "mobile" in ua_lower:
            device_name = "Android Phone"
        else:
            device_name = "Android Tablet"
    elif "macintosh" in ua_lower:
        device_name = "Apple Mac"
    elif "windows" in ua_lower:
        device_name = "Windows PC"
        
    return device_name, browser_name, os_name

# Helper to mock/lookup IP location
def get_approx_location(ip):
    if ip in ['127.0.0.1', 'localhost', '::1']:
        return "Local Loopback (SOC Intranet)"
    cities = [
        "San Francisco, US", "New York, US", "London, UK", "Frankfurt, DE",
        "Tokyo, JP", "Sydney, AU", "Singapore, SG", "Toronto, CA",
        "Paris, FR", "Amsterdam, NL", "Bengaluru, IN", "Mumbai, IN"
    ]
    import hashlib
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return cities[h % len(cities)]

# TOTP Custom Implementation (RFC 6238)
def verify_totp(secret_b32, code, time_step=30, window=1):
    import hmac
    import hashlib
    import base64
    import struct
    import time
    
    secret_b32 = secret_b32.strip().replace(" ", "")
    missing_padding = len(secret_b32) % 8
    if missing_padding:
        secret_b32 += '=' * (8 - missing_padding)
    try:
        key = base64.b32decode(secret_b32, casefold=True)
    except Exception:
        return False
        
    now = int(time.time() / time_step)
    for w in range(-window, window + 1):
        counter = now + w
        msg = struct.pack(">Q", counter)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        val = ((hmac_hash[offset] & 0x7F) << 24 |
               (hmac_hash[offset + 1] & 0xFF) << 16 |
               (hmac_hash[offset + 2] & 0xFF) << 8 |
               (hmac_hash[offset + 3] & 0xFF))
        val = val % 1000000
        if f"{val:06d}" == str(code).strip():
            return True
    return False

# Login Required Decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Authorization required. Please log in.", "danger")
            return redirect(url_for('login'))
        
        # Verify session token validity
        session_token = session.get('session_token')
        if not session_token or not db_manager.is_session_valid(session_token):
            session.clear()
            flash("Session expired or terminated. Please log in again.", "danger")
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function
