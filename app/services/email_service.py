import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from app.config import Config

logger = logging.getLogger('ai-shield')

def safe_print_email(to_email, subject, body, sender=None):
    try:
        # Encode as ASCII and replace characters that cannot be mapped in console CP1252
        safe_body = body.encode('ascii', errors='replace').decode('ascii')
        safe_subject = subject.encode('ascii', errors='replace').decode('ascii')
        
        print("\n--- [EMAIL NOTIFICATION LOG] ---")
        print(f"To: {to_email}")
        print(f"Subject: {safe_subject}")
        if sender:
            print(f"Sender: {sender}")
        print("Body Content:")
        print(safe_body[:1000])
        if len(safe_body) > 1000:
            print("... [truncated]")
        print("--------------------------------\n")
    except Exception:
        pass

def send_smtp_email_sync(to_email, subject, html_content):
    """
    Synchronous SMTP sender execution.
    """
    sender = Config.MAIL_DEFAULT_SENDER
    username = Config.MAIL_USERNAME
    password = Config.MAIL_PASSWORD
    server = Config.MAIL_SERVER
    port = Config.MAIL_PORT
    
    # If credentials are not set, run in dry-run simulation mode
    if not username or not password:
        logger.info(f"[EMAIL SIMULATION/DRY-RUN]")
        logger.info(f"To: {to_email}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Sender: {sender}")
        logger.info(f"Body: {html_content[:500]}...")
        safe_print_email(to_email, subject, html_content, sender=sender)
        return True

    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to_email

        # Create alternative container for text/HTML compatibility
        msg_alt = MIMEMultipart('alternative')
        msg.attach(msg_alt)

        part = MIMEText(html_content, 'html')
        msg_alt.attach(part)

        # Attach Jesin Technologies Logo inline if it exists
        import os
        from email.mime.image import MIMEImage
        logo_path = os.path.join(Config.BASE_DIR, 'static', 'assets', 'logo', 'Jeisn Tech Logo.png')
        if os.path.exists(logo_path):
            with open(logo_path, 'rb') as f:
                img_data = f.read()
            msg_img = MIMEImage(img_data)
            msg_img.add_header('Content-ID', '<jesin_tech_logo>')
            msg_img.add_header('Content-Disposition', 'inline', filename='jesin_tech_logo.png')
            msg.attach(msg_img)

        # Connect using TLS
        if port == 587:
            smtp_conn = smtplib.SMTP(server, port, timeout=10)
            smtp_conn.starttls()
        else:
            smtp_conn = smtplib.SMTP_SSL(server, port, timeout=10)

        smtp_conn.login(username, password)
        smtp_conn.sendmail(sender, [to_email], msg.as_string())
        smtp_conn.quit()
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        # Print fallback securely so it doesn't fail on system encoding limits
        safe_print_email(to_email, subject, html_content)
        return False


def send_smtp_email(to_email, subject, html_content):
    """
    Asynchronous SMTP sender wrapper to prevent main thread blocking.
    """
    import threading
    thread = threading.Thread(
        target=send_smtp_email_sync,
        args=(to_email, subject, html_content)
    )
    thread.daemon = True
    thread.start()
    return True


# ----------------------------------------------------------------------
# Platform Email Workflows
# ----------------------------------------------------------------------

def send_welcome_email(user_email, username, login_url):
    """
    Sends responsive HTML onboarding email.
    """
    subject = "Welcome to AI Shield"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to AI Shield</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 12px; padding: 30px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }}
            .header {{ text-align: center; border-bottom: 1px solid rgba(56, 189, 248, 0.1); padding-bottom: 20px; }}
            .logo {{ color: #0ea5e9; font-size: 24px; font-weight: bold; letter-spacing: 1px; }}
            .welcome-title {{ font-size: 20px; margin-top: 25px; color: #f8fafc; text-align: center; }}
            .content {{ line-height: 1.6; margin-top: 20px; font-size: 15px; }}
            .feature-list {{ margin: 20px 0; padding-left: 20px; }}
            .feature-list li {{ margin-bottom: 10px; }}
            .cta-container {{ text-align: center; margin: 30px 0; }}
            .btn {{ background-color: #0ea5e9; color: #060913 !important; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-weight: bold; font-size: 15px; display: inline-block; box-shadow: 0 0 15px rgba(14, 165, 233, 0.4); }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ AI SHIELD</div>
            </div>
            <div class="welcome-title">Account Verified & Activated</div>
            <div class="content">
                <p>Hello <strong>{username}</strong>,</p>
                <p>Thank you for verifying your email. Your analyst node has been successfully authorized and activated on AI Shield – the enterprise real-time phishing detection and threat intelligence platform.</p>
                <p>You can now access your Security Operations Center (SOC) dashboard using the button below:</p>
                
                <div class="cta-container">
                    <a href="{login_url}" class="btn">Access SOC Dashboard</a>
                </div>
                
                <p>Our platform includes state-of-the-art protection services:</p>
                <ul class="feature-list">
                    <li><strong>AI Phishing Classifier:</strong> Machine learning URL risk auditing.</li>
                    <li><strong>Visual Brand Spoofing Sandbox:</strong> Domain verification to detect fraudulent branding assets.</li>
                    <li><strong>Security Alerts:</strong> Instant notifications for critical server threats.</li>
                </ul>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
                <div style="margin-top: 15px; border-top: 1px solid rgba(56, 189, 248, 0.15); padding-top: 15px; text-align: center;">
                    <img src="cid:jesin_tech_logo" alt="Jesin Technologies" style="height: 35px; max-width: 140px; display: inline-block;">
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_smtp_email(user_email, subject, html_content)

def send_verification_email(user_email, username, verification_url):
    """
    Sends explicit email verification link.
    """
    subject = "Verify Your AI Shield Node"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 12px; padding: 30px; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 1px solid rgba(56, 189, 248, 0.1); }}
            .logo {{ color: #0ea5e9; font-size: 24px; font-weight: bold; }}
            .cta-container {{ text-align: center; margin: 30px 0; }}
            .btn {{ background-color: #0ea5e9; color: #060913 !important; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-weight: bold; font-size: 15px; display: inline-block; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">🛡️ AI SHIELD</div></div>
            <div style="line-height: 1.6; margin-top: 20px;">
                <p>Hello {username},</p>
                <p>A request was received to verify the email address associated with your AI Shield portal account.</p>
                <p>Please click the button below to confirm your correspondence node:</p>
                <div class="cta-container">
                    <a href="{verification_url}" class="btn">Verify Account Node</a>
                </div>
                <p>If you did not initiate this request, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
                <div style="margin-top: 15px; border-top: 1px solid rgba(56, 189, 248, 0.15); padding-top: 15px; text-align: center;">
                    <img src="cid:jesin_tech_logo" alt="Jesin Technologies" style="height: 35px; max-width: 140px; display: inline-block;">
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_smtp_email(user_email, subject, html_content)

def send_password_reset_email(user_email, username, reset_url):
    """
    Sends secure password reset authorization token.
    """
    subject = "Reset Your AI Shield Password"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset Request</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 12px; padding: 30px; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 1px solid rgba(56, 189, 248, 0.1); }}
            .logo {{ color: #0ea5e9; font-size: 24px; font-weight: bold; }}
            .cta-container {{ text-align: center; margin: 30px 0; }}
            .btn {{ background-color: #ef4444; color: #060913 !important; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-weight: bold; font-size: 15px; display: inline-block; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">🛡️ AI SHIELD</div></div>
            <div style="line-height: 1.6; margin-top: 20px;">
                <p>Hello {username},</p>
                <p>You are receiving this email because a request was submitted to reset the password for your account.</p>
                <p>Click the link below to access the secure password decryption and reset page (this token is valid for 1 hour):</p>
                <div class="cta-container">
                    <a href="{reset_url}" class="btn">Reset Secure Passcode</a>
                </div>
                <p>If you did not request a password change, please update your security credentials immediately as this may indicate unauthorized access attempts.</p>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
                <div style="margin-top: 15px; border-top: 1px solid rgba(56, 189, 248, 0.15); padding-top: 15px; text-align: center;">
                    <img src="cid:jesin_tech_logo" alt="Jesin Technologies" style="height: 35px; max-width: 140px; display: inline-block;">
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_smtp_email(user_email, subject, html_content)

def send_security_alert_email(user_email, username, alert_type, details):
    """
    Sends automated system security notices.
    """
    subject = f"[AI SHIELD ALERT] Security Notice: {alert_type}"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>System Alert Notice</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 2px solid #ef4444; border-radius: 12px; padding: 30px; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 1px solid rgba(239, 68, 68, 0.2); }}
            .logo {{ color: #ef4444; font-size: 24px; font-weight: bold; }}
            .alert-box {{ background: rgba(239, 68, 68, 0.08); border: 1px dashed #ef4444; border-radius: 8px; padding: 15px; margin: 20px 0; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">⚠️ THREAT ALERT</div></div>
            <div style="line-height: 1.6; margin-top: 20px;">
                <p>Hello {username},</p>
                <p>The AI Shield Security Engine resolved a security alert event for your registered SOC node:</p>
                
                <div class="alert-box">
                    <strong>Event Type:</strong> {alert_type}<br>
                    <strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    <strong>Trigger Details:</strong> {details}
                </div>
                
                <p>Please log in to your dashboard to inspect recent scan entries or terminate open analyst sessions if this action was unexpected.</p>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
                <div style="margin-top: 15px; border-top: 1px solid rgba(239, 68, 68, 0.15); padding-top: 15px; text-align: center;">
                    <img src="cid:jesin_tech_logo" alt="Jesin Technologies" style="height: 35px; max-width: 140px; display: inline-block;">
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return send_smtp_email(user_email, subject, html_content)
