import sys
import os
import time
# Add e:\Phishing to sys.path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment configuration manually if needed, or just let config.py load it
from app.config import Config
from app.services.email_service import send_smtp_email, send_security_alert_email

def test():
    print("=== SMTP EMAIL SERVICE INTEGRATION TEST ===")
    print(f"MAIL_SERVER: {Config.MAIL_SERVER}")
    print(f"MAIL_PORT: {Config.MAIL_PORT}")
    print(f"MAIL_USERNAME: {Config.MAIL_USERNAME}")
    print(f"MAIL_DEFAULT_SENDER: {Config.MAIL_DEFAULT_SENDER}")
    
    start_time = time.time()
    print("\n[+] Attempting to send security alert test email...")
    
    # Try sending a test email to the sender's own email address
    success = send_security_alert_email(
        user_email="jesinmilesh@gmail.com",
        username="SecurityAnalyst",
        alert_type="Integration Test Run",
        details="This is an automated system diagnostics test verification email for the AI Shield platform."
    )
    
    duration = time.time() - start_time
    print(f"[*] Call duration: {duration:.2f} seconds")
    
    if success:
        print("[+] SUCCESS: The email service was able to connect to SMTP and transmit the email successfully!")
    else:
        print("[-] FAILURE: The email service failed to transmit the email.")

if __name__ == "__main__":
    test()
