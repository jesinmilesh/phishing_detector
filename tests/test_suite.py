import os
import sys
import unittest
import sqlite3
import json
from datetime import datetime

# Add project root to path to resolve imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config
from database.db_manager import DatabaseManager
from ml.feature_extraction.feature_extractor import extract_features, get_feature_names
from app import app, db_manager

class TestFeatureExtractor(unittest.TestCase):
    def test_lexical_features(self):
        url = "http://paypal-security-alert.xyz/login.php"
        features = extract_features(url, online=False)
        
        self.assertEqual(features['has_ip'], 0)
        self.assertEqual(features['is_shortener'], 0)
        self.assertTrue(features['url_length'] > 20)
        self.assertTrue(features['suspicious_keywords'] >= 1) # 'paypal', 'security', 'login'
        self.assertEqual(features['num_hyphens'], 2)
        
    def test_ip_address_detection(self):
        url = "http://192.168.1.105/paypal/login.php"
        features = extract_features(url, online=False)
        self.assertEqual(features['has_ip'], 1)

    def test_shortener_detection(self):
        url = "https://bit.ly/3XyZ8"
        features = extract_features(url, online=False)
        self.assertEqual(features['is_shortener'], 1)

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.test_db = "database/test_phishing.db"
        # Delete if existing
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass
        self.db = DatabaseManager(self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except OSError:
                pass

    def test_user_creation_and_auth(self):
        # Create user
        user_id = self.db.create_user("testanalyst", "test@analyst.com", "mypass123")
        self.assertIsNotNone(user_id)
        
        # Test authentication
        auth_success = self.db.authenticate_user("testanalyst", "mypass123")
        self.assertIsNotNone(auth_success)
        self.assertEqual(auth_success['username'], "testanalyst")
        
        # Test auth failure
        auth_fail = self.db.authenticate_user("testanalyst", "wrongpass")
        self.assertIsNone(auth_fail)

    def test_log_scan_and_retrieve(self):
        details = {
            "features": {"url_length": 45, "has_ip": 0},
            "whois": {"domain_age_days": 100},
            "dns": {"has_dns": 1},
            "ssl": {"has_ssl": 1}
        }
        
        scan_id = self.db.log_scan(
            user_id=1,
            url="http://testsite.com",
            prediction="Legitimate",
            confidence=0.95,
            risk_score=10,
            details_dict=details
        )
        self.assertIsNotNone(scan_id)
        
        # Get scan
        scan = self.db.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan['url'], "http://testsite.com")
        self.assertEqual(scan['prediction'], "Legitimate")
        self.assertEqual(scan['risk_score'], 10)
        self.assertEqual(scan['details']['whois']['domain_age_days'], 100)

class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF in tests for ease of API mocking
        self.client = app.test_client()

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome Back', response.data)

    def test_register_page_loads(self):
        response = self.client.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register Node', response.data)

    def test_rest_api_scan_endpoint(self):
        # CSRF is exempt for /scan, and testing is enabled
        payload = {"url": "http://phish-paypal-verify-alert.net/webscr"}
        response = self.client.post('/scan', 
                                   data=json.dumps(payload),
                                   content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        res_data = json.loads(response.data)
        self.assertEqual(res_data['status'], 'success')
        self.assertEqual(res_data['url'], "http://phish-paypal-verify-alert.net/webscr")
        self.assertIn(res_data['verdict'], ['Phishing', 'Suspicious', 'Legitimate'])

    def test_api_history_endpoint(self):
        response = self.client.get('/history_api')
        self.assertEqual(response.status_code, 200)
        res_data = json.loads(response.data)
        self.assertTrue(isinstance(res_data, list))

    def test_profile_requires_login(self):
        response = self.client.get('/profile')
        self.assertEqual(response.status_code, 302) # Redirect to login

    def test_profile_and_preferences_lifecycle(self):
        # Register user
        username = "testprofileuser"
        email = "profile@test.com"
        password = "testpassword123"
        
        self.client.post('/register', data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password
        })
        
        # Log in
        login_response = self.client.post('/login', data={
            "username": username,
            "password": password
        })
        self.assertEqual(login_response.status_code, 302)
        
        # Access profile
        profile_response = self.client.get('/profile')
        self.assertEqual(profile_response.status_code, 200)
        self.assertIn(b'ANALYST PROFILE CONTROL CONSOLE', profile_response.data)
        
        # Update profile details
        update_data = {
            "full_name": "Test Analyst Name",
            "phone_number": "+1234567890",
            "country": "Switzerland",
            "timezone": "Europe/Paris",
            "bio": "Expert in hunting zero-day phishing campaigns."
        }
        update_res = self.client.put('/profile/update', 
                                    data=json.dumps(update_data), 
                                    content_type='application/json')
        self.assertEqual(update_res.status_code, 200)
        self.assertTrue(json.loads(update_res.data)['success'])
        
        # Update preferences
        pref_data = {
            "theme": "dark",
            "language": "en",
            "default_view": "scanner",
            "security_alerts": True,
            "threat_notifications": False
        }
        pref_res = self.client.put('/preferences', 
                                  data=json.dumps(pref_data), 
                                  content_type='application/json')
        self.assertEqual(pref_res.status_code, 200)
        self.assertTrue(json.loads(pref_res.data)['success'])

        # Check notifications endpoint
        notif_res = self.client.get('/notifications')
        self.assertEqual(notif_res.status_code, 200)
        self.assertTrue(json.loads(notif_res.data)['success'])

if __name__ == '__main__':
    unittest.main()
