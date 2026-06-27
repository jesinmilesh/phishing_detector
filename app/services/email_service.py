import os
import sys
import logging
from datetime import datetime
from flask import current_app
import resend

# Ensure stdout is UTF-8 safe (critical on Windows cp1252 terminals / Gunicorn).
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

def validate_smtp_config():
    """Validates configuration for email services. Returns list of warnings."""
    warnings = []
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        warnings.append("RESEND_API_KEY is empty — email system will run in SIMULATION/DRY-RUN mode.")
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
    """Writes a structured, detailed log entry to logs/email.log."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
    log_msg = (
        f"\n==================================================\n"
        f"Timestamp: {timestamp}\n"
        f"Recipient: {recipient}\n"
        f"HTTP Status: {smtp_status}\n"
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
# Core Resend sender
# ---------------------------------------------------------------------------

def _classify_resend_error(err_str: str) -> str:
    """Returns a human-readable root cause from a Resend API exception string."""
    e = err_str.lower()
    if "api_key" in e or "unauthorized" in e or "401" in e:
        return "Invalid or missing Resend API key. Check RESEND_API_KEY in env/.env."
    if "domain" in e or "sender" in e or "from" in e or "403" in e:
        return "Sender domain not verified on Resend. Verify your domain at https://resend.com/domains or use onboarding@resend.dev for testing."
    if "rate" in e or "429" in e:
        return "Resend rate limit exceeded. Wait before retrying."
    if "timeout" in e or "connection" in e or "network" in e:
        return "Network/connection error reaching Resend API. Check server connectivity."
    if "422" in e or "invalid" in e:
        return f"Invalid request to Resend API: {err_str}"
    return err_str


def send_with_resend(to_email, subject, html_content, retries=3):
    """
    Sends email via Resend API with automatic retry and structured error classification.
    Reads sender address from RESEND_FROM_EMAIL environment variable.
    Falls back to dry-run/simulation mode when RESEND_API_KEY is not set.
    """
    import time
    from app.config import Config

    try:
        is_testing = current_app.config.get('TESTING', False)
    except RuntimeError:
        is_testing = False

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_address = os.environ.get("RESEND_FROM_EMAIL", "").strip() or Config.RESEND_FROM_EMAIL

    # ── Simulation / dry-run mode ──────────────────────────────────────────────
    if not api_key or is_testing:
        _log_reg('warning', "[EMAIL DRY-RUN] RESEND_API_KEY is not set in env/.env — emails are NOT being delivered.")
        _log_reg('info', f"[DRY-RUN] Would send to: {to_email} | Subject: {subject} | From: {from_address}")
        log_advanced_email(
            recipient=to_email,
            smtp_status="DRY-RUN",
            auth_status="NO_API_KEY",
            token_generated=None,
            email_sent=False,
            delivery_failed=True,
            error_details="RESEND_API_KEY missing in env/.env — email NOT sent. Add your key to env/.env."
        )
        # Return False so registration accurately reports delivery failure
        return False, "RESEND_API_KEY not configured. Email was NOT sent. Please set RESEND_API_KEY in env/.env."

    resend.api_key = api_key

    last_error = "Unknown error"
    for attempt in range(1, retries + 1):
        try:
            _safe_print(f"[EMAIL] Attempt {attempt}/{retries} → to={to_email} | from={from_address} | subject={subject}")
            response = resend.Emails.send({
                "from": from_address,
                "to": [to_email],
                "subject": subject,
                "html": html_content
            })

            # SDK v1 returns object with .id; SDK v2 may return dict
            email_id = None
            if isinstance(response, dict):
                email_id = response.get("id")
            elif hasattr(response, "id"):
                email_id = getattr(response, "id")

            if email_id:
                _safe_print(f"[EMAIL SUCCESS] Delivered to {to_email} | Resend ID: {email_id}")
                log_advanced_email(
                    recipient=to_email,
                    smtp_status="200 OK",
                    auth_status="SUCCESS",
                    token_generated=None,
                    email_sent=True,
                    delivery_failed=False
                )
                return True, None
            else:
                last_error = "Resend returned no email ID — delivery unconfirmed."
                _safe_print(f"[EMAIL WARN] No ID in response on attempt {attempt}: {response}")

        except Exception as exc:
            raw_err = str(exc)
            last_error = _classify_resend_error(raw_err)
            _safe_print(f"[EMAIL ERROR] Attempt {attempt} failed: {last_error}")
            logger.error(f"Resend attempt {attempt} failed for {to_email}: {last_error}")

            if attempt < retries:
                backoff = 2 ** attempt  # 2s, 4s
                _safe_print(f"[EMAIL] Retrying in {backoff}s…")
                time.sleep(backoff)

    # All attempts exhausted
    log_advanced_email(
        recipient=to_email,
        smtp_status="FAILED",
        auth_status="FAILED",
        token_generated=None,
        email_sent=False,
        delivery_failed=True,
        error_details=last_error
    )
    return False, last_error


# ---------------------------------------------------------------------------
# Compatibility Mappers (Legacy SMTP mappings to Resend)
# ---------------------------------------------------------------------------

def send_smtp_email_sync(app, to_email, subject, html_content, text_content=None, token=None):
    """Synchronous sender mapped to Resend API."""
    with app.app_context():
        return send_with_resend(to_email, subject, html_content)


def send_smtp_email(to_email, subject, html_content, text_content=None, token=None):
    """Asynchronous sender mapped to Resend API."""
    res, err = send_with_resend(to_email, subject, html_content)
    return res


def send_smtp_email_critical(to_email, subject, html_content, text_content=None, token=None):
    """Synchronous critical sender mapped to Resend API."""
    return send_with_resend(to_email, subject, html_content)


# ---------------------------------------------------------------------------
# Platform Email Workflows
# ---------------------------------------------------------------------------

def send_verification_email(user_email, username, verification_url, token=None):
    """Sends email verification link via Resend."""
    _log_reg('info', f"STEP: Building verification email for {user_email} ({username})")
    _log_reg('info', f"STEP: Verification URL = {verification_url}")

    subject = "Verify Your AI Shield Node"

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
            color: #e2e8f0;
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
            </div>
            <div class="footer">
                <p class="footer-text">&copy; 2026 AI Shield SOC. All rights reserved.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
    _log_reg('info', f"STEP: Calling Resend sender for verification email to {user_email}")
    success, error_details = send_with_resend(user_email, subject, html_content)
    if success:
        _log_reg('info', f"SUCCESS: Verification email sent to {user_email}")
        return True, None
    else:
        _log_reg('error', f"FAILED: Verification email could NOT be sent to {user_email}. Error: {error_details}")
        return False, error_details


def send_welcome_email(user_email, username, login_url):
    """Sends responsive HTML welcome / onboarding email via Resend."""
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
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 12px; padding: 30px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); color: #cbd5e1; }}
            .header {{ text-align: center; border-bottom: 1px solid rgba(56, 189, 248, 0.1); padding-bottom: 20px; }}
            .logo {{ color: #0ea5e9; font-size: 24px; font-weight: bold; letter-spacing: 1px; }}
            .welcome-title {{ font-size: 20px; margin-top: 25px; color: #f8fafc; text-align: center; }}
            .content {{ line-height: 1.6; margin-top: 20px; font-size: 15px; color: #cbd5e1; }}
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
    return send_with_resend(user_email, subject, html_content)


def send_password_reset_email(user_email, username, reset_url, token=None):
    """Sends secure password reset token email via Resend."""
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
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(56, 189, 248, 0.15); border-radius: 12px; padding: 30px; color: #cbd5e1; }}
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
            <div style="line-height: 1.6; margin-top: 20px; color: #cbd5e1;">
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
    return send_with_resend(user_email, subject, html_content)


def send_security_alert_email(user_email, username, alert_type, details):
    """Sends automated system security notices via Resend."""
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
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 2px solid #ef4444; border-radius: 12px; padding: 30px; color: #cbd5e1; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 1px solid rgba(239, 68, 68, 0.2); }}
            .logo {{ color: #ef4444; font-size: 24px; font-weight: bold; }}
            .alert-box {{ background: rgba(239, 68, 68, 0.08); border: 1px dashed #ef4444; border-radius: 8px; padding: 15px; margin: 20px 0; color: #cbd5e1; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">⚠️ THREAT ALERT</div></div>
            <div style="line-height: 1.6; margin-top: 20px; color: #cbd5e1;">
                <p style="color: #cbd5e1;">Hello {username},</p>
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
    return send_with_resend(user_email, subject, html_content)


def send_login_alert_email(user_email, username, ip_address, timestamp):
    """Sends security alert on new login via Resend (mapped to send_security_alert_email)."""
    details = f"New analyst login recorded from IP Address: {ip_address} at {timestamp}."
    return send_security_alert_email(user_email, username, "New Access Node Authorized", details)


def send_newsletter_subscription_email(user_email):
    """Sends a professional newsletter subscription confirmation email via Resend."""
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
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 12px; padding: 30px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); color: #cbd5e1; }}
            .header {{ text-align: center; border-bottom: 1px solid rgba(16, 185, 129, 0.15); padding-bottom: 20px; }}
            .logo {{ color: #10b981; font-size: 24px; font-weight: bold; letter-spacing: 1px; }}
            .title {{ font-size: 20px; margin-top: 25px; color: #f8fafc; text-align: center; }}
            .content {{ line-height: 1.6; margin-top: 20px; font-size: 15px; color: #cbd5e1; }}
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
    return send_with_resend(user_email, subject, html_content)


def send_contact_email(name, from_email, subject, message):
    """Sends contact form submission notification to the support team email."""
    to_email = "jesintechnologies@gmail.com"
    email_subject = f"[AI SHIELD CONTACT] {subject or 'New Inquiry'} from {name}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Contact Form Submission</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #060913; color: #cbd5e1; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid rgba(59, 130, 246, 0.15); border-radius: 12px; padding: 30px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); color: #cbd5e1; }}
            .header {{ text-align: center; border-bottom: 1px solid rgba(59, 130, 246, 0.1); padding-bottom: 20px; }}
            .logo {{ color: #3b82f6; font-size: 24px; font-weight: bold; letter-spacing: 1px; }}
            .title {{ font-size: 20px; margin-top: 25px; color: #f8fafc; text-align: center; }}
            .content {{ line-height: 1.6; margin-top: 20px; font-size: 15px; color: #cbd5e1; }}
            .detail-box {{ background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.15); border-radius: 8px; padding: 15px; margin: 20px 0; color: #cbd5e1; }}
            .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 35px; border-top: 1px solid rgba(59, 130, 246, 0.1); padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ AI SHIELD SOC</div>
            </div>
            <div class="title">Incident Ticket / Inquiry Received</div>
            <div class="content">
                <p>Hello Admin,</p>
                <p>A new contact form inquiry has been submitted from the platform landing page:</p>
                <div class="detail-box">
                    <strong>Submitter Name:</strong> {name}<br>
                    <strong>Submitter Email:</strong> {from_email}<br>
                    <strong>Subject:</strong> {subject or 'N/A'}<br><br>
                    <strong>Message Body:</strong><br>
                    {message}
                </div>
            </div>
            <div class="footer">
                <p>&copy; 2026 AI Shield SOC. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_with_resend(to_email, email_subject, html_content)
