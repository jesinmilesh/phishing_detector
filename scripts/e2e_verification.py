import sys
import os
import requests
import sqlite3

# Simple E2E validation script
BASE_URL = "http://127.0.0.1:5000"

print("[*] Starting E2E Verification Suite...")

# Create session
session = requests.Session()

# 1. Check landing page loads
try:
    res = session.get(f"{BASE_URL}/")
    print(f"[+] Landing page status: {res.status_code}")
    assert res.status_code == 200, "Landing page did not return 200"
except Exception as e:
    print(f"[-] Failed to access landing page: {e}")
    sys.exit(1)

# 2. Check scanners page redirects to login when unauthenticated
res = session.get(f"{BASE_URL}/scanner", allow_redirects=False)
print(f"[+] Authenticated page redirect status: {res.status_code}")
assert res.status_code == 302, "Expected 302 redirect for unauthenticated access"

# 3. Register a new user
import random
username = f"analyst_{random.randint(1000, 9999)}"
email = f"{username}@test.com"
password = "TestPassword123!"

# First get registration page to extract CSRF token
res = session.get(f"{BASE_URL}/register")
csrf_token = None
for line in res.text.split('\n'):
    if 'name="csrf_token"' in line or 'name="csrf-token"' in line:
        import re
        match = re.search(r'value="([^"]+)"', line)
        if match:
            csrf_token = match.group(1)
            break

print(f"[+] Extracted CSRF token: {csrf_token}")

reg_data = {
    "csrf_token": csrf_token,
    "username": username,
    "email": email,
    "password": password,
    "confirm_password": password
}

res = session.post(f"{BASE_URL}/register", data=reg_data, allow_redirects=True)
print(f"[+] Registration POST status: {res.status_code}")
print(f"[+] Registration Final URL: {res.url}")
if "verification link has been sent" not in res.text and "Account created" not in res.text:
    print(f"[-] Registration failed! HTML content of response:\n{res.text[:1000]}")
assert "verification link has been sent" in res.text or "Account created" in res.text, "Registration page response did not indicate verification link sent"
print(f"[+] Registered user: {username} ({email}) successfully!")

# 4. Fetch the verification token from the database manually to simulate clicking verify link
db_path = "database/phishing.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("SELECT id, is_verified, verification_token FROM users WHERE username=?", (username,))
user_row = cursor.fetchone()
assert user_row is not None, "Registered user not found in database!"
user_id = user_row['id']
token = user_row['verification_token']
print(f"[+] User ID: {user_id}, Current is_verified status: {user_row['is_verified']}, Verification Token: {token}")

# Verify the email address using the token
res = session.get(f"{BASE_URL}/verify-email?token={token}")
print(f"[+] Verification GET status: {res.status_code}")
assert "Node Verified" in res.text or "Activated" in res.text, "Email verification page failed"
print("[+] User email successfully verified!")

# Double check database state
cursor.execute("SELECT is_verified FROM users WHERE username=?", (username,))
user_row_updated = cursor.fetchone()
print(f"[+] Updated is_verified status in DB: {user_row_updated['is_verified']}")
assert user_row_updated['is_verified'] == 1, "User is_verified flag was not set to 1"
conn.close()

# 5. Log in
# Get login page first for CSRF
res = session.get(f"{BASE_URL}/login")
csrf_token = None
for line in res.text.split('\n'):
    if 'name="csrf_token"' in line:
        import re
        match = re.search(r'value="([^"]+)"', line)
        if match:
            csrf_token = match.group(1)
            break

login_data = {
    "csrf_token": csrf_token,
    "username": username,
    "password": password
}

res = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)
print(f"[+] Login POST status: {res.status_code}")
assert "SCANNERS" in res.text or "dashboard" in res.url, "Login failed to redirect to scanners dashboard"
print("[+] Login authentication successful!")

# 6. Execute URL scan
# Get CSRF for scanning
res = session.get(f"{BASE_URL}/scanner")
csrf_token = None
for line in res.text.split('\n'):
    if 'name="csrf-token"' in line:
        import re
        match = re.search(r'content="([^"]+)"', line)
        if match:
            csrf_token = match.group(1)
            break

print(f"[+] Scanner CSRF token: {csrf_token}")

scan_url_payload = {
    "url": "http://paypal-verification-update.com/webscr/login"
}
res = session.post(
    f"{BASE_URL}/scan/url",
    data=scan_url_payload,
    headers={"X-CSRFToken": csrf_token}
)
print(f"[+] URL Scan POST status: {res.status_code}")
scan_result = res.json()
print(f"[+] Scan Results: {scan_result}")
assert scan_result["success"] is True, "URL Scan was unsuccessful"
assert "prediction" in scan_result["data"], "Prediction missing from scan results"
print(f"[+] URL Verdict: {scan_result['data']['prediction']} | Risk Score: {scan_result['data']['risk_score']}%")

# 7. Execute Visual Spoofing Screenshot check
screenshot_payload = {
    "url": "https://paypal.secure-login-update.com"
}
res = session.post(
    f"{BASE_URL}/scan/screenshot",
    data=screenshot_payload,
    headers={"X-CSRFToken": csrf_token}
)
print(f"[+] Visual Spoofing POST status: {res.status_code}")
ss_result = res.json()
print(f"[+] Visual Spoofing Results: {ss_result}")
assert ss_result["success"] is True, "Visual Spoofing scan was unsuccessful"
print(f"[+] Spoofing Risk: {ss_result['data']['spoofing_risk']} | Similarity Score: {ss_result['data']['similarity_score']}%")

# 8. Retrieve dashboard stats
res = session.get(f"{BASE_URL}/dashboard")
print(f"[+] Dashboard status: {res.status_code}")
assert "dailyScansCanvas" in res.text, "Dashboard page did not load successfully"
print("[+] SOC Dashboard loaded successfully!")

# 9. Verify History API
res = session.get(f"{BASE_URL}/history?format=json")
print(f"[+] History JSON API status: {res.status_code}")
history_data = res.json()
print(f"[+] Number of scans in history: {len(history_data.get('scans', []))}")
assert len(history_data.get('scans', [])) > 0, "Scan history is empty"
print("[+] Scan history returned successfully!")

print("\n[+] E2E VERIFICATION COMPLETED SUCCESSFULLY! ALL SYSTEM MODULES OPERATIONAL!")
sys.exit(0)
