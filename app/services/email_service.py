import os
import sys
import smtplib
import logging
import threading
from datetime import datetime
from flask import current_app
from flask_mail import Message
from app.config import Config

# Ensure stdout is UTF-8 safe (critical on Windows cp1252 terminals / Gunicorn).
# Without this, any print() containing non-ASCII characters (emojis, etc.) will
# raise UnicodeEncodeError inside the success path, causing the function to
# erroneously return False even after a successful mail.send().
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def _safe_print(msg: str) -> None:
    """Print that never raises UnicodeEncodeError on narrow-encoding terminals."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode('ascii', errors='replace').decode('ascii'))

# ---------------------------------------------------------------------------
# Loggers
# ---------------------------------------------------------------------------
logger = logging.getLogger('email_logger')
reg_logger = logging.getLogger('registration_logger')


def _get_registration_logger():
    """Lazily initialize registration logger pointing to logs/registration.log."""
    if not reg_logger.handlers:
        import logging.handlers as lh
        os.makedirs('logs', exist_ok=True)
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
        handler = lh.RotatingFileHandler('logs/registration.log', maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
        handler.setFormatter(formatter)
        reg_logger.setLevel(logging.DEBUG)
        reg_logger.addHandler(handler)
        reg_logger.propagate = False
    return reg_logger


def _log_reg(level, msg):
    """Helper to write to both console and registration log."""
    _safe_print(f"[REGISTRATION] {msg}")
    getattr(_get_registration_logger(), level)(msg)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def safe_print_email(to_email, subject, body, sender=None):
    try:
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
    """Validates SMTP config, returns list of warnings."""
    warnings = []

    # Log loaded values except passwords
    _log_reg('info', "SMTP Configuration Loaded:")
    _log_reg('info', f"  MAIL_SERVER: {Config.MAIL_SERVER}")
    _log_reg('info', f"  MAIL_PORT: {Config.MAIL_PORT}")
    _log_reg('info', f"  MAIL_USE_TLS: {Config.MAIL_USE_TLS}")
    _log_reg('info', f"  MAIL_USE_SSL: {Config.MAIL_USE_SSL}")
    _log_reg('info', f"  MAIL_USERNAME: {Config.MAIL_USERNAME}")
    _log_reg('info', f"  MAIL_DEFAULT_SENDER: {Config.MAIL_DEFAULT_SENDER}")

    if not Config.MAIL_USERNAME:
        warnings.append("MAIL_USERNAME is empty — emails will run in SIMULATION/DRY-RUN mode.")
    if not Config.MAIL_PASSWORD:
        warnings.append("MAIL_PASSWORD is empty — emails will run in SIMULATION/DRY-RUN mode.")

    if not isinstance(Config.MAIL_PORT, int):
        warnings.append(f"MAIL_PORT must be an integer, got: {type(Config.MAIL_PORT)}")

    if Config.MAIL_SERVER == "smtp.gmail.com" and Config.MAIL_USERNAME:
        clean_pwd = Config.MAIL_PASSWORD.replace(" ", "")
        if len(clean_pwd) != 16:
            warnings.append(
                "WARNING: Gmail SMTP requires a 16-character App Password. "
                "Normal passwords WILL fail. Enable 2-Step Verification and generate an App Password."
            )

    for warn in warnings:
        logger.warning(f"SMTP Config Warning: {warn}")
        print(f"[SMTP WARNING] {warn}")

    return warnings


def notify_admin_of_failure(db_manager, to_email, subject, error_msg):
    """Alerts admin via platform notification on email failure."""
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


def log_advanced_email(recipient, smtp_status, auth_status, token_generated, email_sent, delivery_failed, error_details=None, stack_trace=None):
    """
    Writes a structured, detailed log entry to logs/email.log.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
    log_msg = (
        f"\n==================================================\n"
        f"Timestamp: {timestamp}\n"
        f"Recipient: {recipient}\n"
        f"SMTP Status: {smtp_status}\n"
        f"Authentication Status: {auth_status}\n"
        f"Token Generated: {token_generated or 'N/A'}\n"
        f"Email Sent: {'Yes' if email_sent else 'No'}\n"
        f"Delivery Failed: {'Yes' if delivery_failed else 'No'}\n"
        f"Error Details: {error_details or 'None'}\n"
        f"Stack Trace:\n{stack_trace or 'None'}\n"
        f"=================================================="
    )
    logger.info(log_msg)


# ---------------------------------------------------------------------------
# Core SMTP sender — synchronous
# ---------------------------------------------------------------------------

def send_smtp_email_sync(app, to_email, subject, html_content, text_content=None, token=None):
    """
    Synchronous SMTP sender using Flask-Mail inside a pushed app context.
    This is safe to call from background threads.
    Includes 3-attempt automatic retry logic with 2-second delay.
    """
    with app.app_context():
        from app import mail, db_manager

        sender = Config.MAIL_DEFAULT_SENDER
        username = Config.MAIL_USERNAME
        password = Config.MAIL_PASSWORD

        # Dry-run / simulation mode when credentials are absent
        if not username or not password:
            logger.info("[EMAIL SIMULATION/DRY-RUN] — credentials not configured")
            logger.info(f"To: {to_email} | Subject: {subject} | Sender: {sender}")
            safe_print_email(to_email, subject, html_content, sender=sender)
            log_advanced_email(
                recipient=to_email,
                smtp_status="SIMULATED",
                auth_status="SIMULATED",
                token_generated=token,
                email_sent=True,
                delivery_failed=False,
                error_details="Simulation mode active (no SMTP credentials configured)"
            )
            return (True, None)

        validate_smtp_config()

        print("Email Created")
        msg = Message(
            subject=subject,
            sender=sender,
            recipients=[to_email]
        )
        msg.html = html_content

        if text_content:
            msg.body = text_content
        else:
            import re
            msg.body = re.sub('<[^<]+?>', '', html_content)

        max_attempts = 3
        delay_seconds = 2
        smtp_status = "Not Connected"
        auth_status = "Pending"
        email_sent = False
        delivery_failed = True
        error_details = None
        stack_trace = None

        for attempt in range(1, max_attempts + 1):
            try:
                if attempt > 1:
                    _safe_print(f"[SMTP] Attempt {attempt} of {max_attempts}...")
                    import time
                    time.sleep(delay_seconds)

                logger.info(f"Initiating email send to {to_email} (Subject: {subject}) - Attempt {attempt}")
                _safe_print(f"[EMAIL] Sending to: {to_email} | Subject: {subject} | Attempt {attempt}")

                with mail.connect() as conn:
                    print("SMTP Connected")
                    smtp_status = "Connected"
                    auth_status = "Success"
                    conn.send(msg)

                print("Email Sent Successfully")
                logger.info(f"[SUCCESS] Email delivered to {to_email} | Subject: {subject}")
                _safe_print(f"[EMAIL] [OK] Sent successfully to {to_email}")
                email_sent = True
                delivery_failed = False
                error_details = None
                stack_trace = None
                break  # Success, break retry loop

            except smtplib.SMTPAuthenticationError as auth_err:
                auth_status = "Failed"
                smtp_status = "Connected"
                error_details = f"SMTPAuthenticationError: {str(auth_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Recipient: {to_email} | Subject: {subject}")
                logger.error("HINT: For Gmail, ensure you are using an App Password (not your normal password) and 2FA is enabled.")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                    safe_print_email(to_email, subject, html_content)

            except smtplib.SMTPConnectError as conn_err:
                smtp_status = "Connection Failed"
                error_details = f"SMTPConnectError: {str(conn_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Recipient: {to_email} | Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                    safe_print_email(to_email, subject, html_content)

            except smtplib.SMTPRecipientsRefused as ref_err:
                smtp_status = "Recipient Refused"
                error_details = f"SMTPRecipientsRefused: {str(ref_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Recipient: {to_email}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                break  # Don't retry for refused recipient

            except smtplib.SMTPSenderRefused as sender_err:
                smtp_status = "Sender Refused"
                error_details = f"SMTPSenderRefused: {str(sender_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Sender: {sender} | Recipient: {to_email}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                break  # Don't retry for refused sender

            except smtplib.SMTPDataError as data_err:
                smtp_status = "Data Error"
                error_details = f"SMTPDataError: {str(data_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Recipient: {to_email}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                break  # Don't retry for data error

            except TimeoutError as t_err:
                smtp_status = "Timeout"
                error_details = f"TimeoutError: {str(t_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                    safe_print_email(to_email, subject, html_content)

            except ConnectionRefusedError as cr_err:
                smtp_status = "Connection Refused"
                error_details = f"ConnectionRefusedError: {str(cr_err)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                    safe_print_email(to_email, subject, html_content)

            except Exception as e:
                smtp_status = "Unexpected Error"
                error_details = f"Unexpected email failure [{type(e).__name__}]: {str(e)}"
                import traceback
                stack_trace = traceback.format_exc()
                print("Email Failed")
                print(f"Exception Details: {error_details}")
                logger.error(f"[FAIL] {error_details} | Recipient: {to_email} | Subject: {subject}")
                logger.error(f"Traceback:\n{stack_trace}")
                _safe_print(f"[EMAIL FAIL] {error_details}")
                if attempt == max_attempts:
                    notify_admin_of_failure(db_manager, to_email, subject, error_details)
                    safe_print_email(to_email, subject, html_content)

        # Write to advanced log
        log_advanced_email(
            recipient=to_email,
            smtp_status=smtp_status,
            auth_status=auth_status,
            token_generated=token,
            email_sent=email_sent,
            delivery_failed=delivery_failed,
            error_details=error_details,
            stack_trace=stack_trace
        )

        return (email_sent, error_details)


# ---------------------------------------------------------------------------
# Async wrapper (fire-and-forget for non-critical emails)
# ---------------------------------------------------------------------------

def send_smtp_email(to_email, subject, html_content, text_content=None, token=None):
    """
    Asynchronous SMTP sender — spawns background thread.
    Use for non-critical emails (login alerts, security notices).
    For critical registration emails, use send_smtp_email_sync directly.
    """
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        from app import app  # noqa: F811

    thread = threading.Thread(
        target=send_smtp_email_sync,
        args=(app, to_email, subject, html_content, text_content, token),
        name=f"email-thread-{to_email}"
    )
    thread.daemon = True
    thread.start()
    return True


# ---------------------------------------------------------------------------
# Critical sender — synchronous with full registration logging
# ---------------------------------------------------------------------------

def send_smtp_email_critical(to_email, subject, html_content, text_content=None, token=None):
    """
    Synchronous sender for critical emails (registration verification).
    Blocks until sent so the caller can log success/failure accurately.
    """
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        from app import app  # noqa: F811

    return send_smtp_email_sync(app, to_email, subject, html_content, text_content, token)


# ---------------------------------------------------------------------------
# Platform Email Workflows
# ---------------------------------------------------------------------------

def send_verification_email(user_email, username, verification_url, token=None):
    """
    Sends email verification link. Uses SYNCHRONOUS sending so failures
    are caught immediately during registration.
    """
    _log_reg('info', f"STEP: Building verification email for {user_email} ({username})")
    _log_reg('info', f"STEP: Verification URL = {verification_url}")

    subject = "Verify Your AI Shield Node"

    # If token wasn't passed directly, try to extract it from verification_url
    if not token and "token=" in verification_url:
        try:
            token = verification_url.split("token=")[1].split("&")[0]
        except Exception:
            pass

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your AI Shield Node</title>
    <style>
        body {{
            font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #030712;
            color: #e2e8f0;
            margin: 0;
            padding: 0;
            width: 100% !important;
            -webkit-text-size-adjust: 100%;
            -ms-text-size-adjust: 100%;
        }}
        .wrapper {{
            background-color: #030712;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #0b0f19;
            border: 1px solid #1e293b;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #020617 100%);
            padding: 30px;
            text-align: center;
            border-bottom: 1px solid #1e293b;
        }}
        .logo-container {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }}
        .logo-shield {{
            font-size: 32px;
            margin-right: 10px;
            vertical-align: middle;
        }}
        .logo-text {{
            font-size: 24px;
            font-weight: 800;
            color: #38bdf8;
            letter-spacing: 2px;
            text-transform: uppercase;
            vertical-align: middle;
        }}
        .content {{
            padding: 40px 30px;
            line-height: 1.7;
        }}
        .greeting {{
            font-size: 20px;
            font-weight: 700;
            color: #f8fafc;
            margin-top: 0;
            margin-bottom: 15px;
        }}
        .text {{
            color: #94a3b8;
            font-size: 15px;
            margin-bottom: 25px;
        }}
        .cta-box {{
            text-align: center;
            margin: 35px 0;
        }}
        .btn-verify {{
            background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%);
            color: #ffffff !important;
            text-decoration: none;
            padding: 16px 40px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 16px;
            display: inline-block;
            box-shadow: 0 4px 20px rgba(14, 165, 233, 0.4);
            letter-spacing: 0.5px;
        }}
        .notice-box {{
            background-color: rgba(15, 23, 42, 0.6);
            border-left: 4px solid #ef4444;
            border-radius: 6px;
            padding: 15px 20px;
            margin: 30px 0;
        }}
        .notice-title {{
            color: #ef4444;
            font-weight: 700;
            font-size: 14px;
            margin-top: 0;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .notice-text {{
            color: #94a3b8;
            font-size: 13px;
            margin: 0;
        }}
        .url-box {{
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 15px;
            margin-top: 25px;
        }}
        .url-title {{
            color: #64748b;
            font-size: 12px;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 8px;
            text-transform: uppercase;
        }}
        .url-link {{
            color: #38bdf8;
            font-size: 13px;
            word-break: break-all;
            font-family: 'Courier New', Courier, monospace;
        }}
        .footer {{
            background-color: #090d16;
            padding: 25px 30px;
            text-align: center;
            border-top: 1px solid #1e293b;
        }}
        .footer-text {{
            color: #64748b;
            font-size: 12px;
            margin: 0;
        }}
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="container">
            <div class="header">
                <div class="logo-container">
                    <span class="logo-shield">🛡️</span>
                    <span class="logo-text">AI Shield</span>
                </div>
            </div>
            <div class="content">
                <p class="greeting">Establish Analyst Node Authorization</p>
                <p class="text">Hello <strong>{username}</strong>,</p>
                <p class="text">A request was made to activate this analyst node on the AI Shield threat intelligence platform. To complete authorization and verify your node identity, click the button below:</p>
                
                <div class="cta-box">
                    <a href="{verification_url}" class="btn-verify">Authorize Analyst Node</a>
                </div>

                <div class="notice-box">
                    <p class="notice-title">⚠️ Security Notice</p>
                    <p class="notice-text">This authentication token is sensitive and valid for a single use. Do not share or forward this email. If you did not initiate this request, please contact security operations immediately.</p>
                </div>

                <div class="url-box">
                    <p class="url-title">Fallback Authorization Link</p>
                    <div class="url-link">{verification_url}</div>
                </div>
            </div>
            <div class="footer">
                <p class="footer-text">&copy; 2026 AI Shield SOC. All rights reserved.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

    text_content = (
        f"Hello {username},\n\n"
        f"A request was received to verify the email address associated with your AI Shield portal account.\n\n"
        f"Please click the link below to confirm your account:\n{verification_url}\n\n"
        f"If you did not create this account, you can safely ignore this email.\n\n"
        f"AI Shield SOC Team."
    )

    _log_reg('info', f"STEP: Calling SMTP sender for verification email to {user_email}")
    res = send_smtp_email_critical(user_email, subject, html_content, text_content, token=token)
    if isinstance(res, tuple):
        success, error_details = res
    else:
        success, error_details = res, None

    if success:
        _log_reg('info', f"SUCCESS: Verification email sent to {user_email}")
        return True
    else:
        _log_reg('error', f"FAILED: Verification email could NOT be sent to {user_email}. Error: {error_details}")
        return (False, error_details)


def send_welcome_email(user_email, username, login_url):
    """Sends responsive HTML welcome / onboarding email (async)."""
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
            <div class="welcome-title">Account Verified &amp; Activated</div>
            <div class="content">
                <p>Hello <strong>{username}</strong>,</p>
                <p>Thank you for verifying your email. Your analyst node has been successfully authorized and activated on AI Shield.</p>
                <p>You can now access your Security Operations Center (SOC) dashboard:</p>
                <div class="cta-container">
                    <a href="{login_url}" class="btn">Access SOC Dashboard</a>
                </div>
                <p>Our platform includes state-of-the-art protection services:</p>
                <ul class="feature-list">
                    <li><strong>AI Phishing Classifier:</strong> Machine learning URL risk auditing.</li>
                    <li><strong>Visual Brand Spoofing Sandbox:</strong> Domain verification to detect fraudulent branding.</li>
                    <li><strong>Security Alerts:</strong> Instant notifications for critical threats.</li>
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
        f"Thank you for verifying your email. Your analyst node has been activated on AI Shield.\n\n"
        f"Access your SOC dashboard at: {login_url}\n\n"
        f"AI Shield SOC Team."
    )

    return send_smtp_email(user_email, subject, html_content, text_content)


def send_password_reset_email(user_email, username, reset_url):
    """Sends secure password reset token email (async)."""
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
            .url-fallback {{ word-break: break-all; font-size: 12px; color: #94a3b8; background: rgba(239,68,68,0.08); border-radius: 6px; padding: 10px; margin-top: 15px; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">🛡️ AI SHIELD</div></div>
            <div style="line-height: 1.6; margin-top: 20px;">
                <p>Hello {username},</p>
                <p>A password reset request was submitted for your AI Shield account.</p>
                <p>Click below to access the secure reset page (valid for 1 hour):</p>
                <div class="cta-container">
                    <a href="{reset_url}" class="btn">Reset Secure Passcode</a>
                </div>
                <p>Or copy and paste:</p>
                <div class="url-fallback">{reset_url}</div>
                <p style="margin-top: 20px; color: #94a3b8; font-size: 13px;">If you did not request this, please secure your account immediately.</p>
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
        f"A password reset request was submitted for your account.\n\n"
        f"Reset link (valid for 1 hour):\n{reset_url}\n\n"
        f"If you did not request this, please secure your credentials.\n\n"
        f"AI Shield SOC Team."
    )

    return send_smtp_email(user_email, subject, html_content, text_content)


def send_security_alert_email(user_email, username, alert_type, details):
    """Sends automated system security notices (async)."""
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
                <p>The AI Shield Security Engine resolved a security alert for your SOC node:</p>
                <div class="alert-box">
                    <strong>Event Type:</strong> {alert_type}<br>
                    <strong>Timestamp:</strong> {timestamp}<br>
                    <strong>Trigger Details:</strong> {details}
                </div>
                <p>Please log in to your dashboard to inspect recent scan entries or terminate open sessions if this was unexpected.</p>
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
        f"Security Alert: {alert_type}\n"
        f"Timestamp: {timestamp}\n"
        f"Details: {details}\n\n"
        f"AI Shield SOC Team."
    )

    return send_smtp_email(user_email, subject, html_content, text_content)


def send_newsletter_subscription_email(user_email):
    """Sends a professional newsletter subscription confirmation email (async)."""
    subject = "AI Shield Threat Intelligence - Subscription Confirmed"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Threat Intelligence Subscription</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 12px; padding: 30px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }}
            .header {{ text-align: center; border-bottom: 1px solid rgba(16, 185, 129, 0.15); padding-bottom: 20px; }}
            .logo {{ color: #10b981; font-size: 24px; font-weight: bold; letter-spacing: 1px; }}
            .title {{ font-size: 20px; margin-top: 25px; color: #f8fafc; text-align: center; }}
            .content {{ line-height: 1.6; margin-top: 20px; font-size: 15px; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ AI SHIELD INTEL</div>
            </div>
            <div class="title">Subscription Confirmed</div>
            <div class="content">
                <p>Hello,</p>
                <p>You have successfully subscribed to the AI Shield Threat Intelligence newsletter.</p>
                <p>You will now receive weekly digests on active phishing campaigns, global threat feeds, and emerging zero-day intelligence reports collected by our SOC platform.</p>
                <p>To unsubscribe or manage your notifications, log in to your profile portal at any time.</p>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = (
        f"Hello,\n\n"
        f"You have successfully subscribed to the AI Shield Threat Intelligence newsletter.\n\n"
        f"You will now receive weekly digests on active phishing campaigns, global threat feeds, and emerging zero-day intelligence reports.\n\n"
        f"AI Shield SOC Team."
    )
    
    return send_smtp_email(user_email, subject, html_content, text_content)

