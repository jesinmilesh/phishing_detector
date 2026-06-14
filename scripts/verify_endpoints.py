import sys
import os
import requests
import json
import time
import hmac
import hashlib
import base64
import struct

# Helper to generate TOTP code locally
def get_totp_token(secret):
    secret = secret.replace(" ", "")
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    
    key = base64.b32decode(secret, casefold=True)
    intervals_no = int(time.time() // 30)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h_num = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{h_num:06d}"

def extract_csrf_token(html_text):
    for line in html_text.split("\n"):
        if 'name="csrf-token"' in line or 'name="csrf_token"' in line:
            parts = line.split('content="')
            if len(parts) > 1:
                return parts[1].split('"')[0]
            parts = line.split('value="')
            if len(parts) > 1:
                return parts[1].split('"')[0]
    return ""

def run_verification():
    print("=== STARTING USER PROFILE & 2FA INTEGRATION TEST ===")
    
    base_url = "http://127.0.0.1:5000"
    session = requests.Session()
    
    ts = int(time.time())
    username = f"analyst_{ts}"
    email = f"analyst_{ts}@ai-shield.local"
    password = "TestPassWord99!"
    
    # 1. Fetch Register page and extract CSRF token
    print("\n[+] Fetching registration form...")
    reg_get = session.get(f"{base_url}/register")
    reg_csrf = extract_csrf_token(reg_get.text)
    print(f"[+] Extracted Register CSRF: {reg_csrf}")
    
    # Register the test user
    print(f"[+] Registering test analyst: {username} ({email})...")
    reg_res = session.post(f"{base_url}/register", data={
        "csrf_token": reg_csrf,
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password
    }, allow_redirects=False)
    
    print(f"[*] Register Status: {reg_res.status_code}")
    if reg_res.status_code != 302:
        print("[-] Registration failed. Response:")
        print(reg_res.text[:1000])
        return False
    print("[+] Registration successful.")
    
    # 2. Fetch Login page and extract CSRF token
    print("\n[+] Fetching login form...")
    login_get = session.get(f"{base_url}/login")
    login_csrf = extract_csrf_token(login_get.text)
    print(f"[+] Extracted Login CSRF: {login_csrf}")
    
    # Authenticate
    print("[+] Logging in as test analyst...")
    login_res = session.post(f"{base_url}/login", data={
        "csrf_token": login_csrf,
        "username": username,
        "password": password
    }, allow_redirects=False)
    
    print(f"[*] Login Status: {login_res.status_code}")
    if login_res.status_code != 302:
        print("[-] Login failed. Response:")
        print(login_res.text[:1000])
        return False
    
    redirect_location = login_res.headers.get('Location')
    print(f"[+] Login successful. Redirecting to: {redirect_location}")
    
    # Access profile to get session CSRF token
    print("\n[+] Accessing /profile settings console...")
    profile_res = session.get(f"{base_url}/profile")
    print(f"[*] Profile Status: {profile_res.status_code}")
    if profile_res.status_code != 200:
        print("[-] Profile access failed. Response:")
        print(profile_res.text[:1000])
        return False
    
    csrf_token = extract_csrf_token(profile_res.text)
    if not csrf_token:
        print("[-] Could not find CSRF token on profile page.")
        return False
    print(f"[+] Extracted Session CSRF Token: {csrf_token}")
    
    headers = {
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json"
    }
    
    # 3. Update Profile Details
    print("\n[+] Updating profile details...")
    update_data = {
        "full_name": "Verification Analyst",
        "phone_number": "+1 (555) 999-0000",
        "country": "Switzerland",
        "timezone": "Europe/London",
        "bio": "Integration verify bot."
    }
    up_res = session.put(f"{base_url}/profile/update", json=update_data, headers=headers)
    print(f"[*] Response: {up_res.text}")
    if not up_res.json().get('success'):
        print("[-] Profile update failed.")
        return False
    
    # 4. Update Preferences
    print("\n[+] Updating user display preferences...")
    pref_data = {
        "theme": "dark",
        "language": "en",
        "default_view": "scanner",
        "security_alerts": True,
        "threat_notifications": True
    }
    pref_res = session.put(f"{base_url}/preferences", json=pref_data, headers=headers)
    print(f"[*] Response: {pref_res.text}")
    if not pref_res.json().get('success'):
        print("[-] Preferences update failed.")
        return False
 
    # 5. Initiate 2FA Setup
    print("\n[+] Initiating Two-Factor Authentication setup...")
    setup_res = session.post(f"{base_url}/profile/2fa/setup", headers=headers)
    setup_data = setup_res.json()
    print(f"[*] Response: {json.dumps(setup_data)}")
    if not setup_data.get('success'):
        print("[-] 2FA Setup initiation failed.")
        return False
    
    secret_key = setup_data.get('secret')
    print(f"[+] Secret: {secret_key}")
    
    # 6. Generate TOTP code and Verify Setup
    print("\n[+] Generating local TOTP token...")
    totp_code = get_totp_token(secret_key)
    print(f"[+] Generated OTP Code: {totp_code}")
    
    verify_res = session.post(f"{base_url}/profile/2fa/verify", json={"otp_code": totp_code}, headers=headers)
    print(f"[*] Response: {verify_res.text}")
    if not verify_res.json().get('success'):
        print("[-] 2FA verification failed.")
        return False
    print("[+] 2FA successfully enabled on analyst account.")
    
    # 7. Test 2FA Login Flow
    print("\n[+] Logging out...")
    session.get(f"{base_url}/logout")
    session.cookies.clear()
    
    # Fetch Login page again to get a fresh CSRF token
    print("\n[+] Fetching login form (2FA authentication)...")
    login_get = session.get(f"{base_url}/login")
    login_csrf = extract_csrf_token(login_get.text)
    
    print("[+] Logging in with active 2FA (Step 1)...")
    login_step1 = session.post(f"{base_url}/login", data={
        "csrf_token": login_csrf,
        "username": username,
        "password": password
    }, allow_redirects=False)
    
    print(f"[*] Step 1 Response Status: {login_step1.status_code}")
    if login_step1.status_code != 302 or "/login/2fa" not in login_step1.headers.get('Location', ''):
        print("[-] Did not redirect to /login/2fa. MFA flow broken.")
        return False
    print("[+] Redirected to /login/2fa. Session token is locked.")
    
    # Fetch the 2FA verify page to get its CSRF token
    print("\n[+] Fetching 2FA verification form...")
    verify_2fa_get = session.get(f"{base_url}/login/2fa")
    verify_csrf = extract_csrf_token(verify_2fa_get.text)
    print(f"[+] Extracted 2FA Verify CSRF: {verify_csrf}")
    
    # Access profile now -> should be blocked/redirected
    profile_blocked_res = session.get(f"{base_url}/profile", allow_redirects=False)
    print(f"[*] Unverified Profile Access Status: {profile_blocked_res.status_code}")
    if profile_blocked_res.status_code != 302:
        print("[-] Unverified session allowed to bypass 2FA lock!")
        return False
    print("[+] Unverified session access blocked successfully.")
    
    # 8. Submit OTP code to authorize session (Step 2)
    print("\n[+] Generating new local TOTP token for authorization...")
    totp_code = get_totp_token(secret_key)
    print(f"[+] Generated OTP Code: {totp_code}")
    
    login_step2 = session.post(f"{base_url}/login/2fa", data={
        "csrf_token": verify_csrf,
        "otp_code": totp_code
    }, allow_redirects=False)
    
    print(f"[*] Step 2 Response Status: {login_step2.status_code}")
    if login_step2.status_code != 302:
        print("[-] MFA verification failed.")
        return False
    print("[+] MFA verification successful. Node session authorized.")
    
    # Access profile now -> should succeed
    profile_ok_res = session.get(f"{base_url}/profile")
    print(f"[*] Verified Profile Access Status: {profile_ok_res.status_code}")
    if profile_ok_res.status_code != 200:
        print("[-] Profile access failed after 2FA validation.")
        return False
    print("[+] Profile accessed successfully after 2FA authorization.")
    
    # Extract fresh csrf_token from the profile page
    csrf_token = extract_csrf_token(profile_ok_res.text)
    headers = {
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json"
    }
 
    # 9. Clean up: Disable 2FA
    print("\n[+] Disabling Two-Factor Authentication...")
    disable_res = session.post(f"{base_url}/profile/2fa/disable", json={"password": password}, headers=headers)
    print(f"[*] Response: {disable_res.text}")
    if not disable_res.json().get('success'):
        print("[-] Failed to disable 2FA.")
        return False
    
    # 10. Clean up: Delete account
    print("\n[+] Terminating test analyst account (Danger Zone)...")
    delete_res = session.delete(f"{base_url}/account", json={"password": password}, headers=headers)
    print(f"[*] Response: {delete_res.text}")
    if not delete_res.json().get('success'):
        print("[-] Failed to delete account.")
        return False
    print("[+] Account terminated. Database cleaned successfully.")
    
    print("\n=== ALL INTEGRATION VERIFICATIONS PASSED SUCCESSFULLY ===")
    return True

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
