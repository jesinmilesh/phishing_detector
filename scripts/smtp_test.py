"""
SMTP Configuration Audit & Connection Test
Run from project root: python scripts/smtp_test.py
"""
import os, sys, smtplib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.config import Config

print("=" * 48)
print("   SMTP CONFIGURATION AUDIT")
print("=" * 48)
print(f"MAIL_SERVER         : {Config.MAIL_SERVER}")
print(f"MAIL_PORT           : {Config.MAIL_PORT}")
print(f"MAIL_USE_TLS        : {Config.MAIL_USE_TLS}")
print(f"MAIL_USE_SSL        : {Config.MAIL_USE_SSL}")
print(f"MAIL_USERNAME       : {Config.MAIL_USERNAME}")
clean_pwd = Config.MAIL_PASSWORD.replace(" ", "")
print(f"MAIL_PASSWORD SET   : {bool(Config.MAIL_PASSWORD)} (len={len(clean_pwd)} chars, spaces stripped)")
print(f"MAIL_DEFAULT_SENDER : {Config.MAIL_DEFAULT_SENDER}")
print(f"APP_BASE_URL        : {Config.APP_BASE_URL}")

# Gmail App Password check
if Config.MAIL_SERVER == "smtp.gmail.com":
    if len(clean_pwd) == 16:
        print("\nGmail App Password  : OK (16 chars — valid format)")
    else:
        print(f"\nGmail App Password  : WARNING — {len(clean_pwd)} chars (must be exactly 16 chars App Password, NOT normal password)")

print()
print("=" * 48)
print("   RAW SMTP CONNECTION TEST")
print("=" * 48)
try:
    with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=15) as smtp:
        smtp.ehlo()
        print(f"EHLO               : OK")
        if Config.MAIL_USE_TLS:
            smtp.starttls()
            smtp.ehlo()
            print(f"STARTTLS           : OK")
        smtp.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
        print(f"LOGIN              : OK")
        print(f"\nRESULT: Connected and authenticated to {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
        print("SMTP is OPERATIONAL. Emails should deliver successfully.")
except smtplib.SMTPAuthenticationError as e:
    print(f"RESULT: SMTP AUTH FAILED")
    print(f"Error: {e}")
    print("\nFix: Use a Gmail App Password (16 chars), not your normal password.")
    print("     Go to: https://myaccount.google.com/apppasswords")
except smtplib.SMTPConnectError as e:
    print(f"RESULT: SMTP CONNECT FAILED")
    print(f"Error: {e}")
    print(f"\nFix: Check firewall/proxy blocking port {Config.MAIL_PORT} to {Config.MAIL_SERVER}")
except ConnectionRefusedError as e:
    print(f"RESULT: CONNECTION REFUSED — {e}")
except Exception as e:
    print(f"RESULT: FAILED [{type(e).__name__}] — {e}")
