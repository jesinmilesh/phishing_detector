import sys
import os
import time

# Add e:\Phishing to sys.path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from app.config import Config
from app.services.email_service import send_smtp_email_sync, validate_smtp_config

def test():
    print("=== SMTP EMAIL SERVICE INTEGRATION TEST ===")
    print(f"MAIL_SERVER: {Config.MAIL_SERVER}")
    print(f"MAIL_PORT: {Config.MAIL_PORT}")
    print(f"MAIL_USERNAME: {Config.MAIL_USERNAME}")
    print(f"MAIL_DEFAULT_SENDER: {Config.MAIL_DEFAULT_SENDER}")
    
    # Pre-validate credentials and print config errors/warnings
    warnings = validate_smtp_config()
    
    start_time = time.time()
    print("\n[+] Attempting to send test email synchronously...")
    
    # Run within Flask application context
    with app.app_context():
        # Try sending a test email to the sender's own email address or default recipient
        recipient = ""
        
        test_subject = "AI Shield System Diagnostics Test"
        test_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>System Diagnostics</title>
            <style>
                body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; padding: 20px; }
                .container { max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid #0ea5e9; border-radius: 8px; padding: 25px; }
                h1 { color: #0ea5e9; }
                .footer { font-size: 11px; color: #64748b; margin-top: 30px; border-top: 1px solid rgba(56,189,248,0.15); padding-top: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ AI Shield SMTP Integration Test</h1>
                <p>This is a synchronous diagnostics test verification email for the AI Shield platform.</p>
                <p>If you see this, Flask-Mail configuration is correct and emails are active!</p>
                <div class="footer">
                    <img src="cid:jesin_tech_logo" alt="Jesin Technologies Logo" style="height: 35px; max-width: 140px;">
                </div>
            </div>
        </body>
        </html>
        """
        
        success = send_smtp_email_sync(app, recipient, test_subject, test_html)
        
    duration = time.time() - start_time
    print(f"[*] Call duration: {duration:.2f} seconds")
    
    if success:
        print("[+] SUCCESS: The email service was able to connect to SMTP and transmit the email successfully!")
        sys.exit(0)
    else:
        print("[-] FAILURE: The email service failed to transmit the email.")
        sys.exit(1)

if __name__ == "__main__":
    test()
