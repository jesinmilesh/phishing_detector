import sqlite3
import json
from datetime import datetime
from app.config import Config
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
        """Initializes tables for Users, Scans, Reports, and User Management System."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Enable Foreign Keys support
        cursor.execute("PRAGMA foreign_keys = ON")
        
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

        # Create Profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                user_id INTEGER PRIMARY KEY,
                full_name TEXT DEFAULT '',
                phone_number TEXT DEFAULT '',
                country TEXT DEFAULT '',
                timezone TEXT DEFAULT '',
                bio TEXT DEFAULT '',
                avatar_path TEXT DEFAULT '',
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                account_status TEXT DEFAULT 'Active',
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Create User Preferences table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INTEGER PRIMARY KEY,
                theme TEXT DEFAULT 'system',
                language TEXT DEFAULT 'en',
                default_view TEXT DEFAULT 'dashboard',
                notification_pref TEXT DEFAULT 'all',
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Create Security Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_settings (
                user_id INTEGER PRIMARY KEY,
                two_factor_enabled INTEGER DEFAULT 0,
                two_factor_secret TEXT DEFAULT '',
                login_alerts_enabled INTEGER DEFAULT 1,
                data_sharing_enabled INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Create Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Create Active Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                device_name TEXT DEFAULT 'Unknown Device',
                browser TEXT DEFAULT 'Unknown Browser',
                os TEXT DEFAULT 'Unknown OS',
                ip_address TEXT DEFAULT 'Unknown IP',
                location TEXT DEFAULT 'Unknown Location',
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        # Create Scan History table (duplicate/shadow of scans for user compliance)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
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
        
        # Trigger to sync scans -> scan_history
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS sync_scans_to_history AFTER INSERT ON scans
            BEGIN
                INSERT OR IGNORE INTO scan_history (id, user_id, url, prediction, confidence, risk_score, scan_time, details_json)
                VALUES (new.id, new.user_id, new.url, new.prediction, new.confidence, new.risk_score, new.scan_time, new.details_json);
            END;
        ''')
        
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS sync_scans_delete AFTER DELETE ON scans
            BEGIN
                DELETE FROM scan_history WHERE id = old.id;
            END;
        ''')
        
        cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS sync_scans_update AFTER UPDATE ON scans
            BEGIN
                UPDATE scan_history SET
                    user_id = new.user_id,
                    url = new.url,
                    prediction = new.prediction,
                    confidence = new.confidence,
                    risk_score = new.risk_score,
                    scan_time = new.scan_time,
                    details_json = new.details_json
                WHERE id = old.id;
            END;
        ''')
        
        # Sync any existing scans records to scan_history
        cursor.execute("INSERT OR IGNORE INTO scan_history SELECT * FROM scans")
        
        # Check if an admin user exists, if not, create a default one
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()['count'] == 0:
            admin_pwd_hash = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, is_verified) VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@threatintel.local", admin_pwd_hash, "admin", 1)
            )
        
        # Perform dynamic migration/checks for existing users who need profiles, preferences, security settings
        cursor.execute("SELECT id FROM users")
        user_ids = [row['id'] for row in cursor.fetchall()]
        for uid in user_ids:
            # Check profile
            cursor.execute("SELECT 1 FROM profiles WHERE user_id = ?", (uid,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO profiles (user_id) VALUES (?)", (uid,))
            # Check preferences
            cursor.execute("SELECT 1 FROM user_preferences WHERE user_id = ?", (uid,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO user_preferences (user_id) VALUES (?)", (uid,))
            # Check security_settings
            cursor.execute("SELECT 1 FROM security_settings WHERE user_id = ?", (uid,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO security_settings (user_id) VALUES (?)", (uid,))

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
            user_id = cursor.lastrowid
            
            # Insert default profile, preferences, and security settings
            cursor.execute("INSERT INTO profiles (user_id) VALUES (?)", (user_id,))
            cursor.execute("INSERT INTO user_preferences (user_id) VALUES (?)", (user_id,))
            cursor.execute("INSERT INTO security_settings (user_id) VALUES (?)", (user_id,))
            
            conn.commit()
            return user_id
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

    # Profile operations
    def get_profile_by_user_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id as user_id, u.username, u.email, u.created_at, u.role, u.is_verified,
                   p.full_name, p.phone_number, p.country, p.timezone, p.bio, p.avatar_path,
                   p.last_login, p.account_status
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = ?
        ''', (user_id,))
        profile = cursor.fetchone()
        conn.close()
        return dict(profile) if profile else None

    def update_profile(self, user_id, full_name, phone_number, country, timezone, bio):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE profiles
            SET full_name = ?, phone_number = ?, country = ?, timezone = ?, bio = ?
            WHERE user_id = ?
        ''', (full_name, phone_number, country, timezone, bio, user_id))
        conn.commit()
        conn.close()
        return True

    def update_avatar(self, user_id, avatar_path):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE profiles
            SET avatar_path = ?
            WHERE user_id = ?
        ''', (avatar_path, user_id))
        conn.commit()
        conn.close()
        return True

    def update_last_login(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            UPDATE profiles
            SET last_login = ?
            WHERE user_id = ?
        ''', (now, user_id))
        conn.commit()
        conn.close()
        return True

    # User Preferences operations
    def get_preferences_by_user_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user_id,))
        pref = cursor.fetchone()
        conn.close()
        return dict(pref) if pref else None

    def update_preferences(self, user_id, theme, language, default_view, notification_pref):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_preferences
            SET theme = ?, language = ?, default_view = ?, notification_pref = ?
            WHERE user_id = ?
        ''', (theme, language, default_view, notification_pref, user_id))
        conn.commit()
        conn.close()
        return True

    # Security Settings operations
    def get_security_settings_by_user_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_settings WHERE user_id = ?", (user_id,))
        sec = cursor.fetchone()
        conn.close()
        return dict(sec) if sec else None

    def update_security_settings(self, user_id, two_factor_enabled, two_factor_secret, login_alerts_enabled, data_sharing_enabled):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE security_settings
            SET two_factor_enabled = ?, two_factor_secret = ?, login_alerts_enabled = ?, data_sharing_enabled = ?
            WHERE user_id = ?
        ''', (two_factor_enabled, two_factor_secret, login_alerts_enabled, data_sharing_enabled, user_id))
        conn.commit()
        conn.close()
        return True

    def update_password(self, user_id, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        pwd_hash = generate_password_hash(password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pwd_hash, user_id))
        conn.commit()
        conn.close()
        return True

    # Active Sessions operations
    def create_session(self, user_id, session_token, device_name, browser, os, ip_address, location):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO active_sessions (user_id, session_token, device_name, browser, os, ip_address, location)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, session_token, device_name, browser, os, ip_address, location))
        conn.commit()
        conn.close()
        return True

    def get_active_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_sessions WHERE user_id = ? ORDER BY last_active DESC", (user_id,))
        sessions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return sessions

    def delete_session(self, session_token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        conn.close()
        return True

    def delete_all_sessions_except(self, user_id, session_token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE user_id = ? AND session_token != ?", (user_id, session_token))
        conn.commit()
        conn.close()
        return True

    def delete_all_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True

    def is_session_valid(self, session_token):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM active_sessions WHERE session_token = ?", (session_token,))
        valid = cursor.fetchone() is not None
        conn.close()
        return valid

    # Notifications operations
    def add_notification(self, user_id, title, message, type_):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (?, ?, ?, ?)
        ''', (user_id, title, message, type_))
        conn.commit()
        conn.close()
        return True

    def get_notifications_by_user_id(self, user_id, limit=50, unread_only=False):
        conn = self.get_connection()
        cursor = conn.cursor()
        if unread_only:
            cursor.execute('''
                SELECT * FROM notifications 
                WHERE user_id = ? AND is_read = 0 
                ORDER BY created_at DESC LIMIT ?
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM notifications 
                WHERE user_id = ? 
                ORDER BY created_at DESC LIMIT ?
            ''', (user_id, limit))
        notifications = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return notifications

    def mark_notification_as_read(self, notification_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE notifications
            SET is_read = 1
            WHERE id = ? AND user_id = ?
        ''', (notification_id, user_id))
        conn.commit()
        conn.close()
        return True

    def mark_all_notifications_as_read(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
        return True

    def delete_notification(self, notification_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM notifications
            WHERE id = ? AND user_id = ?
        ''', (notification_id, user_id))
        conn.commit()
        conn.close()
        return True

    def delete_all_notifications(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM notifications
            WHERE user_id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
        return True

    def get_unread_notification_count(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,))
        count = cursor.fetchone()['count']
        conn.close()
        return count

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

    def delete_scan(self, scan_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        conn.commit()
        conn.close()
        return True

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

    def query_scan_history(self, user_id, search_query='', prediction_filter='all', sort_by='date_desc', page=1, per_page=10):
        """Advanced query method for searching, filtering, sorting and paginating scans."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM scan_history WHERE user_id = ?"
        params = [user_id]
        
        if search_query:
            query += " AND url LIKE ?"
            params.append(f"%{search_query}%")
            
        if prediction_filter != 'all':
            query += " AND prediction = ?"
            params.append(prediction_filter)
            
        # Sort mapping
        sorts = {
            'date_desc': 'ORDER BY scan_time DESC',
            'date_asc': 'ORDER BY scan_time ASC',
            'risk_desc': 'ORDER BY risk_score DESC',
            'risk_asc': 'ORDER BY risk_score ASC',
            'url_asc': 'ORDER BY url ASC',
            'url_desc': 'ORDER BY url DESC'
        }
        query += " " + sorts.get(sort_by, 'ORDER BY scan_time DESC')
        
        # Get total count for pagination before limit/offset
        count_query = f"SELECT COUNT(*) as count FROM ({query})"
        cursor.execute(count_query, params)
        total_items = cursor.fetchone()['count']
        
        # Pagination limit and offset
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        scans = cursor.fetchall()
        conn.close()
        
        result = []
        for s in scans:
            sd = dict(s)
            sd['details'] = json.loads(sd['details_json']) if sd['details_json'] else {}
            result.append(sd)
            
        total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1
        return {
            'scans': result,
            'total_items': total_items,
            'total_pages': total_pages,
            'current_page': page,
            'per_page': per_page
        }

    def get_scan_statistics(self, user_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        if user_id:
            cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = ?", (user_id,))
            stats['total_scans'] = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND prediction = 'Phishing'", (user_id,))
            stats['phishing_count'] = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND prediction = 'Suspicious'", (user_id,))
            stats['suspicious_count'] = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND prediction = 'Legitimate'", (user_id,))
            stats['legitimate_count'] = cursor.fetchone()['count']
            
            # Daily scans distribution (last 7 days) for specific user
            cursor.execute('''
                SELECT DATE(scan_time) as date, COUNT(*) as count,
                SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing,
                SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END) as legitimate
                FROM scans
                WHERE user_id = ?
                GROUP BY DATE(scan_time)
                ORDER BY DATE(scan_time) DESC
                LIMIT 7
            ''', (user_id,))
            stats['daily_scans'] = [dict(row) for row in cursor.fetchall()]
        else:
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

    def delete_report(self, report_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        # Verify the report belongs to the user via scan_id -> user_id
        cursor.execute('''
            SELECT r.id, r.pdf_path FROM reports r
            JOIN scans s ON r.scan_id = s.id
            WHERE r.id = ? AND s.user_id = ?
        ''', (report_id, user_id))
        report = cursor.fetchone()
        if report:
            pdf_path = report['pdf_path']
            cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
            conn.close()
            # Try to physically delete pdf file
            import os
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass
            return True
        conn.close()
        return False

    def query_reports(self, user_id, search_query='', risk_filter='all'):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT r.id as report_id, r.pdf_path, r.generated_at, s.url, s.prediction, s.risk_score, s.id as scan_id
            FROM reports r
            JOIN scans s ON r.scan_id = s.id
            WHERE s.user_id = ?
        '''
        params = [user_id]
        
        if search_query:
            query += " AND s.url LIKE ?"
            params.append(f"%{search_query}%")
            
        if risk_filter != 'all':
            query += " AND s.prediction = ?"
            params.append(risk_filter)
            
        query += " ORDER BY r.generated_at DESC"
        
        cursor.execute(query, params)
        reports = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return reports

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

    # Account Deletion (GDPR-compliant Cascade Delete)
    def delete_user_account(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Note: Active sessions, notifications, profiles, user_preferences, security_settings, and scans
        # are cascaded either via ON DELETE CASCADE or foreign key triggers. Let's explicitly delete reports first.
        cursor.execute('''
            SELECT r.pdf_path FROM reports r
            JOIN scans s ON r.scan_id = s.id
            WHERE s.user_id = ?
        ''', (user_id,))
        reports = cursor.fetchall()
        for r in reports:
            try:
                import os
                if os.path.exists(r['pdf_path']):
                    os.remove(r['pdf_path'])
            except Exception:
                pass
                
        # Delete user (this cascades to profiles, user_preferences, security_settings, notifications, active_sessions, scans)
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        conn.close()
        return True

    # Download Account Data (GDPR Export JSON)
    def get_all_user_data(self, user_id):
        profile = self.get_profile_by_user_id(user_id)
        if not profile:
            return None
            
        prefs = self.get_preferences_by_user_id(user_id)
        sec = self.get_security_settings_by_user_id(user_id)
        scans = self.get_all_scans(limit=1000, user_id=user_id)
        
        # Clean scans data to serialize
        serialized_scans = []
        for s in scans:
            serialized_scans.append({
                'url': s['url'],
                'prediction': s['prediction'],
                'confidence': s['confidence'],
                'risk_score': s['risk_score'],
                'scan_time': s['scan_time'],
                'details': s['details']
            })
            
        sessions = self.get_active_sessions(user_id)
        serialized_sessions = []
        for sess in sessions:
            serialized_sessions.append({
                'device_name': sess['device_name'],
                'browser': sess['browser'],
                'os': sess['os'],
                'ip_address': sess['ip_address'],
                'location': sess['location'],
                'last_active': sess['last_active']
            })
            
        notifications = self.get_notifications_by_user_id(user_id, limit=500)
        serialized_notifications = []
        for n in notifications:
            serialized_notifications.append({
                'title': n['title'],
                'message': n['message'],
                'type': n['type'],
                'is_read': n['is_read'],
                'created_at': n['created_at']
            })

        return {
            'account_info': {
                'username': profile['username'],
                'email': profile['email'],
                'created_at': profile['created_at'],
                'role': profile['role'],
                'is_verified': profile['is_verified']
            },
            'profile': {
                'full_name': profile['full_name'],
                'phone_number': profile['phone_number'],
                'country': profile['country'],
                'timezone': profile['timezone'],
                'bio': profile['bio'],
                'account_status': profile['account_status']
            },
            'preferences': {
                'theme': prefs['theme'] if prefs else 'system',
                'language': prefs['language'] if prefs else 'en',
                'default_view': prefs['default_view'] if prefs else 'dashboard',
                'notification_pref': prefs['notification_pref'] if prefs else 'all'
            },
            'security_settings': {
                'two_factor_enabled': sec['two_factor_enabled'] if sec else 0,
                'login_alerts_enabled': sec['login_alerts_enabled'] if sec else 1,
                'data_sharing_enabled': sec['data_sharing_enabled'] if sec else 1
            },
            'scan_history': serialized_scans,
            'active_sessions': serialized_sessions,
            'notifications': serialized_notifications
        }
