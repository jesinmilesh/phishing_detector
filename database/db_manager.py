import sqlite3
import json
from datetime import datetime
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash

class DatabaseManager:
    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes tables for Users, Scans, and Reports."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                role TEXT DEFAULT 'analyst',
                is_verified INTEGER DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP
            )
        ''')
        
        # Ensure existing user table has columns
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN verification_token TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
        except sqlite3.OperationalError:
            pass
            
        # Create Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details_json TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # Create Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                pdf_path TEXT NOT NULL,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Create Newsletter table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS newsletter (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check if an admin user exists, if not, create a default one
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()['count'] == 0:
            admin_pwd_hash = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, is_verified) VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@threatintel.local", admin_pwd_hash, "admin", 1)
            )
        
        conn.commit()
        conn.close()

    # User operations
    def create_user(self, username, email, password, role='analyst'):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            pwd_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, email, pwd_hash, role)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def get_user_by_username(self, username):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def get_user_by_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def authenticate_user(self, username, password):
        user = self.get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            return user
        return None

    # Scan operations
    def log_scan(self, user_id, url, prediction, confidence, risk_score, details_dict):
        conn = self.get_connection()
        cursor = conn.cursor()
        details_json = json.dumps(details_dict)
        cursor.execute('''
            INSERT INTO scans (user_id, url, prediction, confidence, risk_score, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, url, prediction, confidence, risk_score, details_json))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def get_scan(self, scan_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = cursor.fetchone()
        conn.close()
        if scan:
            scan_dict = dict(scan)
            scan_dict['details'] = json.loads(scan_dict['details_json']) if scan_dict['details_json'] else {}
            return scan_dict
        return None

    def get_all_scans(self, limit=100, user_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if user_id:
            cursor.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY scan_time DESC LIMIT ?",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT scans.*, users.username FROM scans LEFT JOIN users ON scans.user_id = users.id ORDER BY scan_time DESC LIMIT ?",
                (limit,)
            )
        scans = cursor.fetchall()
        conn.close()
        
        result = []
        for s in scans:
            sd = dict(s)
            sd['details'] = json.loads(sd['details_json']) if sd['details_json'] else {}
            result.append(sd)
        return result

    def get_scan_statistics(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        stats['total_scans'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE prediction = 'Phishing'")
        stats['phishing_count'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE prediction = 'Suspicious'")
        stats['suspicious_count'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE prediction = 'Legitimate'")
        stats['legitimate_count'] = cursor.fetchone()['count']
        
        # Daily scans distribution (last 7 days)
        cursor.execute('''
            SELECT DATE(scan_time) as date, COUNT(*) as count,
            SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END) as legitimate
            FROM scans
            GROUP BY DATE(scan_time)
            ORDER BY DATE(scan_time) DESC
            LIMIT 7
        ''')
        stats['daily_scans'] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return stats

    # Report operations
    def create_report(self, scan_id, pdf_path):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reports (scan_id, pdf_path) VALUES (?, ?)",
            (scan_id, pdf_path)
        )
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return report_id

    def get_report_by_scan_id(self, scan_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,))
        report = cursor.fetchone()
        conn.close()
        return dict(report) if report else None

    def get_report(self, report_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        report = cursor.fetchone()
        conn.close()
        return dict(report) if report else None

    # Verification and Reset operations
    def set_user_verification_token(self, user_id, token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verification_token = ?, is_verified = 0 WHERE id = ?", (token, user_id))
        conn.commit()
        conn.close()

    def verify_user_email(self, token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE verification_token = ?", (token,))
        user = cursor.fetchone()
        if user:
            cursor.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user['id'],))
            conn.commit()
            conn.close()
            user_dict = dict(user)
            user_dict['is_verified'] = 1
            user_dict['verification_token'] = None
            return user_dict
        conn.close()
        return None

    def get_user_by_email(self, email):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def set_user_reset_token(self, email, token, expiry):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?", (token, expiry, email))
        conn.commit()
        conn.close()

    def get_user_by_reset_token(self, token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def reset_user_password(self, user_id, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        pwd_hash = generate_password_hash(password)
        cursor.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?", (pwd_hash, user_id))
        conn.commit()
        conn.close()

    # Newsletter subscription
    def add_newsletter_subscriber(self, email):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO newsletter (email) VALUES (?)", (email,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def get_newsletter_subscribers(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM newsletter")
        subscribers = [row['email'] for row in cursor.fetchall()]
        conn.close()
        return subscribers
