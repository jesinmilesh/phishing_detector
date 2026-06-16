# app/services/history_service.py
import csv
import io
import json
import os
import sqlite3
from datetime import datetime
from app.config import Config
from app.services.recommendation_engine import RecommendationEngine

class HistoryService:
    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_scan_details(self, scan_id: int, user_id: int = None) -> dict:
        """
        Retrieves detailed metadata for a single scan, verifying user permissions.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM scans WHERE id = ?"
        params = [scan_id]
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
            
        cursor.execute(query, params)
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {}
            
        scan_dict = dict(row)
        scan_dict['details'] = json.loads(scan_dict['details_json']) if scan_dict['details_json'] else {}
        
        # Generate recommendations dynamically
        scan_dict['recommendations'] = RecommendationEngine.get_recommendations(
            scan_dict['prediction'],
            scan_dict['risk_score'],
            scan_dict['confidence']
        )
        return scan_dict

    def delete_scan_record(self, scan_id: int, user_id: int) -> bool:
        """
        Deletes a single scan from history (and physically removes associated PDF reports).
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get associated report pdf path
        cursor.execute("""
            SELECT r.pdf_path FROM reports r 
            JOIN scans s ON r.scan_id = s.id 
            WHERE s.id = ? AND s.user_id = ?
        """, (scan_id, user_id))
        report_row = cursor.fetchone()
        
        if report_row:
            pdf_path = report_row['pdf_path']
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass
                
        # Delete scan (Cascade triggers will delete the report and scan_history row)
        cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        conn.commit()
        conn.close()
        return True

    def clear_all_history(self, user_id: int) -> bool:
        """
        Clears all scan history and PDFs for a specific analyst user.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT r.pdf_path FROM reports r
            JOIN scans s ON r.scan_id = s.id
            WHERE s.user_id = ?
        """, (user_id,))
        rows = cursor.fetchall()
        
        for row in rows:
            pdf_path = row['pdf_path']
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass
                
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True

    def export_history_csv(self, user_id: int) -> str:
        """
        Exports the entire scan history for a user into a CSV formatted string.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, url, prediction, confidence, risk_score, scan_time 
            FROM scans 
            WHERE user_id = ? 
            ORDER BY scan_time DESC
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(["Scan ID", "Scanned URL", "Verdict/Prediction", "Confidence Score", "Risk Score (%)", "Timestamp"])
        
        # Write rows
        for row in rows:
            writer.writerow([
                row['id'],
                row['url'],
                row['prediction'],
                f"{row['confidence'] * 100:.1f}%",
                row['risk_score'],
                row['scan_time']
            ])
            
        return output.getvalue()
