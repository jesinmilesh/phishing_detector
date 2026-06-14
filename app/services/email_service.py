import os
import smtplib
import logging
from datetime import datetime
from flask import current_app
from flask_mail import Message
from app.config import Config

# Get email logger configured in app/__init__.py
logger = logging.getLogger('email_logger')

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

def validate_smtp_config():
    """
    Validates SMTP configurations and returns list of warnings/instructions.
    """
    warnings = []
    
    # 1. Check empty credentials
    if not Config.MAIL_USERNAME:
        warnings.append("MAIL_USERNAME is empty. Emails will be run in SIMULATION/DRY-RUN mode.")
    if not Config.MAIL_PASSWORD:
        warnings.append("MAIL_PASSWORD is empty. Emails will be run in SIMULATION/DRY-RUN mode.")
        
    # 2. Check types
    if not isinstance(Config.MAIL_PORT, int):
        warnings.append(f"MAIL_PORT must be an integer, got: {type(Config.MAIL_PORT)}")
        
    # 3. Gmail security checks
    if Config.MAIL_SERVER == "smtp.gmail.com" and Config.MAIL_USERNAME:
        clean_pwd = Config.MAIL_PASSWORD.replace(" ", "")
        if len(clean_pwd) != 16:
            warnings.append(
                "WARNING: Gmail SMTP is configured but the password is NOT a 16-character App Password. "
                "Normal passwords WILL fail. Please enable 2-Step Verification on Gmail and generate an App Password."
            )
            
    # Log validation warnings
    for warn in warnings:
        logger.warning(f"SMTP Config Warning: {warn}")
        print(f"[SMTP WARNING] {warn}")
        
    return warnings

def notify_admin_of_failure(db_manager, to_email, subject, error_msg):
    """
    Alerts the administrator by adding a platform notification on email failure.
    """
    try:
        admin_user = db_manager.get_user_by_username("admin")
        if admin_user:
            db_manager.add_notification(
                user_id=admin_user['id'],
                title="Email Delivery Alert",
                message=f"Failed to deliver '{subject}' to {to_email}. Error: {error_msg}",
                type_="email_failure"
            )
            logger.info("Admin notified in SOC platform about email failure.")
    except Exception as notify_err:
        logger.error(f"Failed to record admin alert: {str(notify_err)}")

def send_smtp_email_sync(app, to_email, subject, html_content, text_content=None):
    """
    Synchronous SMTP sender execution using Flask-Mail.
    """
    with app.app_context():
        # Lazy imports to prevent circular dependencies at startup
        from app import mail, db_manager
        
        sender = Config.MAIL_DEFAULT_SENDER
        username = Config.MAIL_USERNAME
        password = Config.MAIL_PASSWORD
        server = Config.MAIL_SERVER
        port = Config.MAIL_PORT
        
        # Dry-run/simulation mode
        if not username or not password:
            logger.info(f"[EMAIL SIMULATION/DRY-RUN]")
            logger.info(f"To: {to_email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Sender: {sender}")
            safe_print_email(to_email, subject, html_content, sender=sender)
            return True

        # Run SMTP and App Password checks
        validate_smtp_config()

        try:
            print("[DEBUG] SMTP Connected")
            logger.info(f"Initiating email send to {to_email} (Subject: {subject})")
            
            msg = Message(
                subject=subject,
                sender=sender,
                recipients=[to_email]
            )
            msg.html = html_content
            
            if text_content:
                msg.body = text_content
            else:
                # Basic text strip fallback
                import re
                msg.body = re.sub('<[^<]+?>', '', html_content)


            # Send the email
            mail.send(msg)
            
            logger.info(f"Email delivery status: Sent successfully to {to_email}")
            print("[DEBUG] Email Sent Successfully")
            return True
            
        except smtplib.SMTPAuthenticationError as auth_err:
            error_msg = f"SMTP Authentication Failed: {str(auth_err)}"
            logger.error(f"{error_msg} (Recipient: {to_email})")
            print(f"[-] {error_msg}")
            notify_admin_of_failure(db_manager, to_email, subject, error_msg)
            safe_print_email(to_email, subject, html_content)
            return False
            
        except smtplib.SMTPConnectError as conn_err:
            error_msg = f"SMTP Connection Failed: {str(conn_err)}"
            logger.error(f"{error_msg} (Recipient: {to_email})")
            print(f"[-] {error_msg}")
            notify_admin_of_failure(db_manager, to_email, subject, error_msg)
            safe_print_email(to_email, subject, html_content)
            return False
            
        except Exception as e:
            error_msg = f"Email delivery failure: {str(e)}"
            logger.error(f"{error_msg} (Recipient: {to_email})")
            print(f"[-] {error_msg}")
            notify_admin_of_failure(db_manager, to_email, subject, error_msg)
            safe_print_email(to_email, subject, html_content)
            return False

def send_smtp_email(to_email, subject, html_content, text_content=None):
    """
    Asynchronous SMTP sender wrapper to prevent blocking the main request thread.
    """
    import threading
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        # Fallback for out-of-context execution (like command line tests)
        from app import app
        
    thread = threading.Thread(
        target=send_smtp_email_sync,
        args=(app, to_email, subject, html_content, text_content)
    )
    thread.daemon = True
    thread.start()
    return True

# ----------------------------------------------------------------------
# Platform Email Workflows
# ----------------------------------------------------------------------

def send_welcome_email(user_email, username, login_url):
    """
    Sends responsive HTML welcome / onboarding email.
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
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = (
        f"Hello {username},\n\n"
        f"Thank you for verifying your email. Your analyst node has been successfully authorized and activated "
        f"on AI Shield – the enterprise real-time phishing detection and threat intelligence platform.\n\n"
        f"You can now access your Security Operations Center (SOC) dashboard at: {login_url}\n\n"
        f"Platform features:\n"
        f"- AI Phishing Classifier: Machine learning URL risk auditing.\n"
        f"- Visual Brand Spoofing Sandbox: Domain verification to detect fraudulent branding assets.\n"
        f"- Security Alerts: Instant notifications for critical server threats.\n\n"
        f"AI Shield SOC Team."
    )
    
    return send_smtp_email(user_email, subject, html_content, text_content)

def send_verification_email(user_email, username, verification_url):
    """
    Sends email verification link.
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
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = (
        f"Hello {username},\n\n"
        f"A request was received to verify the email address associated with your AI Shield portal account.\n\n"
        f"Please click the link below to confirm your correspondence node:\n{verification_url}\n\n"
        f"If you did not initiate this request, you can safely ignore this email.\n\n"
        f"AI Shield SOC Team."
    )
    
    return send_smtp_email(user_email, subject, html_content, text_content)

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
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = (
        f"Hello {username},\n\n"
        f"You are receiving this email because a request was submitted to reset the password for your account.\n\n"
        f"Please click the link below to reset your passcode (this link is valid for 1 hour):\n{reset_url}\n\n"
        f"If you did not request a password change, please update your security credentials immediately.\n\n"
        f"AI Shield SOC Team."
    )
    
    return send_smtp_email(user_email, subject, html_content, text_content)

def send_security_alert_email(user_email, username, alert_type, details):
    """
    Sends automated system security notices.
    """
    subject = f"[AI SHIELD ALERT] Security Notice: {alert_type}"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
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
                    <strong>Timestamp:</strong> {timestamp}<br>
                    <strong>Trigger Details:</strong> {details}
                </div>
                
                <p>Please log in to your dashboard to inspect recent scan entries or terminate open analyst sessions if this action was unexpected.</p>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = (
        f"Hello {username},\n\n"
        f"The AI Shield Security Engine resolved a security alert event for your registered SOC node:\n\n"
        f"Event Type: {alert_type}\n"
        f"Timestamp: {timestamp}\n"
        f"Trigger Details: {details}\n\n"
        f"Please log in to your dashboard to inspect recent scan entries.\n\n"
        f"AI Shield SOC Team."
    )
    
    return send_smtp_email(user_email, subject, html_content, text_content)
