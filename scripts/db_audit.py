import os
import sqlite3
import json
from datetime import datetime

DATABASE_PATH = "database/phishing.db"

def run_audit():
    print("=== STARTING DATABASE SCHEMA AND DATA AUDIT ===")
    if not os.path.exists(DATABASE_PATH):
        print(f"[-] Database file not found at {DATABASE_PATH}!")
        return False

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Check all required tables exist
    required_tables = {
        "users": ["id", "username", "email", "password_hash", "created_at", "role", "is_verified", "verification_token", "reset_token", "reset_token_expiry"],
        "scans": ["id", "user_id", "url", "prediction", "confidence", "risk_score", "scan_time", "details_json"],
        "reports": ["id", "scan_id", "pdf_path", "generated_at"],
        "newsletter": ["id", "email", "subscribed_at"],
        "profiles": ["user_id", "full_name", "phone_number", "country", "timezone", "bio", "avatar_path", "last_login", "account_status"],
        "user_preferences": ["user_id", "theme", "language", "default_view", "notification_pref"],
        "security_settings": ["user_id", "two_factor_enabled", "two_factor_secret", "login_alerts_enabled", "data_sharing_enabled"],
        "notifications": ["id", "user_id", "title", "message", "type", "is_read", "created_at"],
        "active_sessions": ["id", "user_id", "session_token", "device_name", "browser", "os", "ip_address", "location", "last_active"],
        "scan_history": ["id", "user_id", "url", "prediction", "confidence", "risk_score", "scan_time", "details_json"],
        "contact_messages": ["id", "name", "email", "subject", "message", "created_at"],
        "site_stats": ["key", "value"],
        "analytics": ["id", "event_type", "user_id", "details", "timestamp"],
        "model_registry": ["version", "model_path", "accuracy", "precision", "recall", "f1_score", "roc_auc", "training_date", "dataset_version", "is_active", "metrics_json"],
        "datasets": ["id", "filename", "file_path", "file_size_kb", "row_count", "upload_time", "uploaded_by"]
    }

    schema_errors = 0
    
    # Check tables and columns
    for table, columns in required_tables.items():
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if not cursor.fetchone():
            print(f"[!] Missing table: {table}")
            schema_errors += 1
            continue
            
        cursor.execute(f"PRAGMA table_info({table})")
        existing_cols = {row[1] for row in cursor.fetchall()}
        for col in columns:
            if col not in existing_cols:
                print(f"[!] Table '{table}' is missing column: {col}")
                schema_errors += 1

    # 2. Check foreign key integrity
    cursor.execute("PRAGMA foreign_key_check")
    fk_violations = cursor.fetchall()
    if fk_violations:
        print(f"[!] Foreign key violations found: {len(fk_violations)}")
        for v in fk_violations:
            print(f"    Table: {v[0]}, RowId: {v[1]}, Target: {v[2]}, FKey Index: {v[3]}")
        schema_errors += len(fk_violations)
    else:
        print("[+] Foreign key constraints are valid.")

    # 3. Check for orphaned records
    # Profiles without users
    cursor.execute("SELECT p.user_id FROM profiles p LEFT JOIN users u ON p.user_id = u.id WHERE u.id IS NULL")
    orphaned_profiles = cursor.fetchall()
    if orphaned_profiles:
        print(f"[!] Found {len(orphaned_profiles)} orphaned profiles.")
        for row in orphaned_profiles:
            print(f"    Profile user_id: {row['user_id']}")
        # Repair: Delete orphaned profiles
        cursor.execute("DELETE FROM profiles WHERE user_id NOT IN (SELECT id FROM users)")
        conn.commit()
        print("[+] Cleaned up orphaned profiles.")
        
    # Preferences without users
    cursor.execute("SELECT p.user_id FROM user_preferences p LEFT JOIN users u ON p.user_id = u.id WHERE u.id IS NULL")
    orphaned_prefs = cursor.fetchall()
    if orphaned_prefs:
        print(f"[!] Found {len(orphaned_prefs)} orphaned user preferences.")
        # Repair: Delete orphaned preferences
        cursor.execute("DELETE FROM user_preferences WHERE user_id NOT IN (SELECT id FROM users)")
        conn.commit()
        print("[+] Cleaned up orphaned user preferences.")
        
    # Security settings without users
    cursor.execute("SELECT s.user_id FROM security_settings s LEFT JOIN users u ON s.user_id = u.id WHERE u.id IS NULL")
    orphaned_sec = cursor.fetchall()
    if orphaned_sec:
        print(f"[!] Found {len(orphaned_sec)} orphaned security settings.")
        # Repair: Delete orphaned settings
        cursor.execute("DELETE FROM security_settings WHERE user_id NOT IN (SELECT id FROM users)")
        conn.commit()
        print("[+] Cleaned up orphaned security settings.")

    # Scans without users (note: user_id can be NULL if user was deleted, but scan history might be orphaned)
    # Since foreign key is ON DELETE SET NULL, scans with user_id that doesn't exist should be NULL.
    # Let's verify if there are user_ids that are not NULL and do not exist.
    cursor.execute("SELECT s.id, s.user_id FROM scans s LEFT JOIN users u ON s.user_id = u.id WHERE s.user_id IS NOT NULL AND u.id IS NULL")
    orphaned_scans = cursor.fetchall()
    if orphaned_scans:
        print(f"[!] Found {len(orphaned_scans)} scans with non-existent user_ids.")
        for row in orphaned_scans:
            cursor.execute("UPDATE scans SET user_id = NULL WHERE id = ?", (row['id'],))
        conn.commit()
        print("[+] Standardized orphaned scans user_ids to NULL.")

    conn.close()
    
    if schema_errors == 0:
        print("[+] DATABASE SCHEMAS ARE 100% CORRECT AND VALIDATED.")
        return True
    else:
        print(f"[-] Database audit complete. Found {schema_errors} schema issues.")
        return False

if __name__ == "__main__":
    run_audit()
