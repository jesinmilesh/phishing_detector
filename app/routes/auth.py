import os
import re
import secrets
import logging
from datetime import datetime, timedelta, timezone
from flask import render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from app import app, db_manager, limiter, csrf, app_logger, error_logger, security_logger
from app.config import Config
from app.utils.helpers import allowed_file, parse_user_agent, get_approx_location, verify_totp, login_required
from app.services.email_service import (
    send_welcome_email,
    send_verification_email,
    send_password_reset_email,
    send_security_alert_email,
    send_newsletter_subscription_email
)

# Registration-specific logger
reg_logger = logging.getLogger('registration_logger')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip() or request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username_or_email or not password:
            flash("All fields are required.", "danger")
            return render_template('login.html')
            
        user = None
        if '@' in username_or_email:
            user = db_manager.get_user_by_email(username_or_email)
        if not user:
            user = db_manager.get_user_by_username(username_or_email)
            
        if user and check_password_hash(user['password_hash'], password):
            username = user['username']
            # Check 2FA
            sec_settings = db_manager.get_security_settings_by_user_id(user['id'])
            if sec_settings and sec_settings.get('two_factor_enabled', 0) == 1:
                session['pre_2fa_user_id'] = user['id']
                return redirect(url_for('login_2fa'))
                
            session.pop(f'failed_attempts_{username}', None)
            
            # Create session token
            session_token = secrets.token_hex(32)
            session['session_token'] = session_token
            session['user'] = {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
            
            # Track active session
            ua = request.headers.get('User-Agent', '')
            device_name, browser, os_name = parse_user_agent(ua)
            ip = request.remote_addr
            location = get_approx_location(ip)
            
            db_manager.create_session(user['id'], session_token, device_name, browser, os_name, ip, location)
            db_manager.update_last_login(user['id'])
            
            # Send Notification
            db_manager.add_notification(
                user['id'],
                "New Analyst Login",
                f"Analyst session established from {device_name} ({browser} on {os_name}) - IP: {ip}.",
                "new_login"
            )
            
            # Dispatch login alert email if enabled
            if not sec_settings or sec_settings.get('login_alerts_enabled', 1) == 1:
                send_security_alert_email(
                    user['email'],
                    username,
                    "New Access Node Authorized",
                    f"Your account was authenticated from remote address {ip} ({location}) at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} using {browser} on {os_name}."
                )
                
            security_logger.info(f"SUCCESSFUL LOGIN | User: {username} | IP: {ip}")
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            user_record = None
            if '@' in username_or_email:
                user_record = db_manager.get_user_by_email(username_or_email)
            if not user_record:
                user_record = db_manager.get_user_by_username(username_or_email)
                
            if user_record:
                failed_username = user_record['username']
                attempts = session.get(f'failed_attempts_{failed_username}', 0) + 1
                session[f'failed_attempts_{failed_username}'] = attempts
                if attempts >= 3:
                    send_security_alert_email(
                        user_record['email'],
                        failed_username,
                        "Multiple Failed Login Attempts",
                        f"There have been {attempts} failed login attempts on your account from remote address {request.remote_addr}. If this wasn't you, please secure your credentials immediately."
                    )
            security_logger.warning(f"FAILED LOGIN | User: {username_or_email} | IP: {request.remote_addr}")
            flash("Invalid credentials.", "danger")
            
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login_2fa():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    pre_user_id = session.get('pre_2fa_user_id')
    if not pre_user_id:
        flash("Session invalid. Please start authentication again.", "danger")
        return redirect(url_for('login'))
        
    user = db_manager.get_user_by_id(pre_user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        code = request.form.get('otp_code', '').strip()
        sec_settings = db_manager.get_security_settings_by_user_id(pre_user_id)
        
        if sec_settings and verify_totp(sec_settings['two_factor_secret'], code):
            # 2FA Succeeded
            session.pop('pre_2fa_user_id', None)
            session.pop(f'failed_attempts_{user["username"]}', None)
            
            # Create session token
            session_token = secrets.token_hex(32)
            session['session_token'] = session_token
            session['user'] = {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
            
            # Track active session
            ua = request.headers.get('User-Agent', '')
            device_name, browser, os_name = parse_user_agent(ua)
            ip = request.remote_addr
            location = get_approx_location(ip)
            
            db_manager.create_session(user['id'], session_token, device_name, browser, os_name, ip, location)
            db_manager.update_last_login(user['id'])
            
            # Send Notification
            db_manager.add_notification(
                user['id'],
                "New Analyst Login (2FA)",
                f"Analyst session verified with 2FA and established from {device_name} - IP: {ip}.",
                "new_login"
            )
            
            # Dispatch login alert email if enabled
            if sec_settings.get('login_alerts_enabled', 1) == 1:
                send_security_alert_email(
                    user['email'],
                    user['username'],
                    "New Access Node Authorized (2FA)",
                    f"Your account was authenticated using 2FA from remote address {ip} ({location}) at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} using {browser} on {os_name}."
                )
                
            security_logger.info(f"SUCCESSFUL 2FA LOGIN | User: {user['username']} | IP: {ip}")
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            security_logger.warning(f"FAILED 2FA CODE | User: {user['username']} | IP: {request.remote_addr}")
            flash("Invalid 2FA code. Please try again.", "danger")
            
    return render_template('login_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        print("Registration Started")
        reg_logger.info(f"--- REGISTRATION STARTED | IP: {request.remote_addr} ---")
        print("[REGISTRATION] Step 1: Form submitted")

        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        # Normalize email: strip whitespace and lowercase to prevent delivery failures
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        reg_logger.info(f"Form data: username={username}, email={email}, full_name={full_name}")

        # ---- Validation ----
        if not username or not email or not password:
            reg_logger.warning("Validation failed: missing required fields")
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            reg_logger.warning("Validation failed: passwords do not match")
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            reg_logger.warning(f"Validation failed: invalid email format: {email}")
            flash("Invalid email address.", "danger")
            return render_template('register.html')
            
        if len(password) < 6:
            reg_logger.warning("Validation failed: password too short")
            flash("Password must be at least 6 characters.", "danger")
            return render_template('register.html')

        # ---- Create User ----
        reg_logger.info("Step 2: Creating user record in database")
        user_id = db_manager.create_user(username, email, password)

        if user_id:
            print("User Saved")
            reg_logger.info(f"Step 3: User saved successfully — user_id={user_id}")
            print(f"[REGISTRATION] Step 3: User created — ID={user_id}")

            if full_name:
                db_manager.update_profile(user_id, full_name, '', '', '', '')
                reg_logger.info(f"Step 3b: Profile updated with full_name={full_name}")

            # ---- Generate Verification Token ----
            token = secrets.token_urlsafe(32)
            db_manager.set_user_verification_token(user_id, token)
            print("Token Generated")
            reg_logger.info(f"Step 4: Verification token generated and stored for user_id={user_id}")
            print("[REGISTRATION] Step 4: Verification token created")

            # ---- Build Verification URL ----
            # Use APP_BASE_URL from config to ensure the link resolves correctly
            # regardless of SERVER_NAME or deployment environment.
            base_url = Config.APP_BASE_URL.rstrip('/')
            verification_url = f"{base_url}/verify-email?token={token}"
            reg_logger.info(f"Step 5: Verification URL built: {verification_url}")
            print(f"[REGISTRATION] Step 5: Verification URL = {verification_url}")

            # ---- Send Verification Email ----
            reg_logger.info(f"Step 6: Sending verification email to {email}")
            print(f"[REGISTRATION] Step 6: Sending email to {email}")
            email_sent = False
            email_error = None
            try:
                res = send_verification_email(email, username, verification_url, token=token)
                if isinstance(res, tuple):
                    email_sent, email_error = res
                else:
                    email_sent, email_error = res, None

                if email_sent:
                    reg_logger.info(f"Step 7: Verification email sent successfully to {email}")
                    print(f"[REGISTRATION] Step 7: Email sent OK")
                else:
                    reg_logger.error(f"Step 7: Verification email FAILED to send to {email}. Error: {email_error}")
                    print(f"[REGISTRATION] Step 7: Email send returned False. Error: {email_error}")
                    error_logger.error(f"REGISTRATION EMAIL FAILED | User: {username} | Email: {email} | Error: {email_error}")
            except Exception as email_exc:
                email_error = str(email_exc)
                reg_logger.error(f"Step 7: Email send raised exception: {email_error}")
                error_logger.error(f"REGISTRATION EMAIL EXCEPTION | User: {username} | Email: {email} | Error: {email_error}")
                print(f"[REGISTRATION] Step 7: EMAIL EXCEPTION — {email_exc}")
                email_sent = False

            security_logger.info(f"USER REGISTRATION | User: {username} | Email: {email} | IP: {request.remote_addr} | EmailSent: {email_sent}")
            reg_logger.info(f"Step 8: Registration complete — email_sent={email_sent} — redirecting to login")

            if email_sent:
                flash(
                    "Account created! ✅ A verification link has been sent to your email address. "
                    "Please check your inbox (and spam/junk folder).",
                    "success"
                )
            else:
                # Log raw error server-side but show a clean message to the user
                reg_logger.error(f"Step 8: Email delivery failed — {email_error}")
                error_logger.error(f"REGISTRATION EMAIL FAILED | User: {username} | Email: {email} | Error: {email_error}")
                flash(
                    "Your account was created successfully, but we could not deliver the verification email. "
                    "Please use the 'Resend Verification Email' option after logging in, or contact support.",
                    "warning"
                )
            return redirect(url_for('login'))
        else:
            reg_logger.error(f"FAILED: Username or email collision — username={username}, email={email}")
            security_logger.error(f"USER REGISTRATION FAILED | User: {username} | Email: {email} | IP: {request.remote_addr}")
            flash("Username or Email already exists.", "danger")
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        db_manager.delete_session(session_token)
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/verify-email')
def verify_email():
    token = request.args.get('token', '')
    if not token:
        return render_template('verify_email.html', status='pending')
        
    user = db_manager.verify_user_email(token)
    if user:
        if 'user' in session and session['user']['id'] == user['id']:
            session['user']['is_verified'] = 1
        # Dispatch welcome email upon successful verification
        login_url = url_for('login', _external=True)
        send_welcome_email(user['email'], user['username'], login_url)
        return render_template('verify_email.html', status='success')
    else:
        return render_template('verify_email.html', status='error')

@app.route('/verify-email/resend', methods=['POST'])
@limiter.limit("3 per minute")
def verify_email_resend():
    email = request.form.get('email', '').strip().lower()
    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for('verify_email'))
        
    # Check cooldown (60 seconds)
    cooldown = 60
    session_key = f"last_resend_{email}"
    last_resend = session.get(session_key)
    if last_resend:
        try:
            last_resend_dt = datetime.fromisoformat(last_resend)
            time_elapsed = (datetime.now() - last_resend_dt).total_seconds()
            if time_elapsed < cooldown:
                remaining = int(cooldown - time_elapsed)
                flash(f"Please wait {remaining} seconds before requesting another verification email.", "danger")
                return redirect(url_for('verify_email'))
        except Exception:
            pass

    user = db_manager.get_user_by_email(email)
    if user:
        if user.get('is_verified', 0):
            flash("Your account is already verified. Please log in.", "info")
            return redirect(url_for('login'))
            
        token = secrets.token_urlsafe(32)
        db_manager.set_user_verification_token(user['id'], token)
        base_url = Config.APP_BASE_URL.rstrip('/')
        verification_url = f"{base_url}/verify-email?token={token}"
        res = send_verification_email(email, user['username'], verification_url, token=token)
        if isinstance(res, tuple):
            resend_sent, resend_error = res
        else:
            resend_sent, resend_error = res, None

        if resend_sent:
            session[session_key] = datetime.now().isoformat()
            flash("✅ A new verification link has been sent to your email. Please check your inbox and spam folder.", "success")
        else:
            err_msg = f"Verification email could not be delivered. Details: {resend_error}" if resend_error else "Verification email could not be delivered."
            flash(err_msg, "danger")
    else:
        # Prevent user enumeration — always show neutral message, but record send attempts to session
        session[session_key] = datetime.now().isoformat()
        flash("If that email address is registered, a new verification link has been sent.", "success")
        
    return redirect(url_for('verify_email'))

@app.route('/api/check-username', methods=['POST'])
@limiter.limit("20 per minute")
def check_username():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    if not username:
        return jsonify({"available": False, "error": "Username is required."}), 400
    user = db_manager.get_user_by_username(username)
    return jsonify({"available": user is None})

@app.route('/api/check-email', methods=['POST'])
@limiter.limit("20 per minute")
def check_email():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"available": False, "error": "Email is required."}), 400
    user = db_manager.get_user_by_email(email)
    return jsonify({"available": user is None})

@app.route('/resend-verification', methods=['GET', 'POST'])
@login_required
def resend_verification():
    user = db_manager.get_user_by_id(session['user']['id'])
    if user:
        if user.get('is_verified', 0):
            flash("Your account is already verified.", "info")
            return redirect(url_for('dashboard'))
            
        email = user['email']
        cooldown = 60
        session_key = f"last_resend_{email}"
        last_resend = session.get(session_key)
        if last_resend:
            try:
                last_resend_dt = datetime.fromisoformat(last_resend)
                time_elapsed = (datetime.now() - last_resend_dt).total_seconds()
                if time_elapsed < cooldown:
                    remaining = int(cooldown - time_elapsed)
                    flash(f"Please wait {remaining} seconds before requesting another verification email.", "danger")
                    return redirect(url_for('dashboard'))
            except Exception:
                pass
                
        token = secrets.token_urlsafe(32)
        db_manager.set_user_verification_token(user['id'], token)
        base_url = Config.APP_BASE_URL.rstrip('/')
        verification_url = f"{base_url}/verify-email?token={token}"
        res = send_verification_email(user['email'], user['username'], verification_url, token=token)
        if isinstance(res, tuple):
            resend_sent, resend_error = res
        else:
            resend_sent, resend_error = res, None

        if resend_sent:
            session[session_key] = datetime.now().isoformat()
            flash("✅ Verification email has been resent. Please check your inbox (and spam folder).", "success")
        else:
            err_msg = f"Verification email could not be delivered. Details: {resend_error}" if resend_error else "Verification email could not be delivered."
            flash(err_msg, "danger")
    else:
        flash("User record not found.", "danger")
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Email field is required.", "danger")
            return render_template('forgot_password.html')
            
        user = db_manager.get_user_by_email(email)
        if user:
            token = secrets.token_urlsafe(32)
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            db_manager.set_user_reset_token(email, token, expiry)
            
            reset_url = url_for('reset_password', token=token, _external=True)
            send_password_reset_email(email, user['username'], reset_url)
            security_logger.info(f"PASSWORD RESET REQUESTED | User: {user['username']} | IP: {request.remote_addr}")
            
        flash("If that email address is registered, a password reset link has been sent to it.", "success")
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    token = request.args.get('token', '') or request.form.get('token', '')
    if not token:
        flash("Password reset token is missing.", "danger")
        return redirect(url_for('login'))
        
    user = db_manager.get_user_by_reset_token(token)
    if not user:
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for('login'))
        
    expiry_str = user.get('reset_token_expiry')
    if expiry_str:
        try:
            expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expiry:
                flash("Reset token has expired.", "danger")
                return redirect(url_for('login'))
        except Exception:
            pass

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not password or len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('reset_password.html', token=token)
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('reset_password.html', token=token)
            
        db_manager.reset_user_password(user['id'], password)
        security_logger.info(f"PASSWORD RESET SUCCESS | User: {user['username']} | IP: {request.remote_addr}")
        
        send_security_alert_email(
            user['email'],
            user['username'],
            "Password Changed Successfully",
            f"The access credentials for your AI Shield account were updated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}."
        )
        
        flash("Password reset successful! You can now log in with your new credentials.", "success")
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

@app.route('/newsletter/subscribe', methods=['POST'])
@limiter.limit("3 per minute")
def newsletter_subscribe():
    email = request.form.get('email', '').strip()
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "error": "Invalid email address."}), 400
        
    success = db_manager.add_newsletter_subscriber(email)
    if success:
        security_logger.info(f"NEWSLETTER SUBSCRIPTION | Email: {email} | IP: {request.remote_addr}")
        try:
            send_newsletter_subscription_email(email)
        except Exception as e:
            error_logger.error(f"Newsletter confirmation email failed: {e}")
        return jsonify({"success": True, "message": "Subscribed successfully! Thank you for staying informed."})
    else:
        return jsonify({"success": True, "message": "Email is already subscribed."})



# ==========================================
# DIAGNOSTICS & SYSTEM ROUTES
# ==========================================

@app.route('/debug-registration-email')
def debug_registration_email():
    """
    Diagnostic endpoint to test the full registration email pipeline.
    Tests token generation, URL building, and SMTP delivery end-to-end.
    Access: GET /debug-registration-email?email=your@email.com
    """
    import traceback as _tb
    from app.services.email_service import send_verification_email, validate_smtp_config
    
    recipient = request.args.get('email', '').strip() or Config.MAIL_USERNAME or 'admin@ai-shield.local'
    results = []

    # Step 1: SMTP config validation
    results.append({"step": 1, "name": "SMTP Config Validation", "status": "running"})
    try:
        warnings = validate_smtp_config()
        results[-1]["status"] = "ok"
        results[-1]["warnings"] = warnings
        results[-1]["config"] = {
            "MAIL_SERVER": Config.MAIL_SERVER,
            "MAIL_PORT": Config.MAIL_PORT,
            "MAIL_USE_TLS": Config.MAIL_USE_TLS,
            "MAIL_USERNAME": Config.MAIL_USERNAME,
            "MAIL_PASSWORD_SET": bool(Config.MAIL_PASSWORD),
            "MAIL_DEFAULT_SENDER": Config.MAIL_DEFAULT_SENDER,
            "APP_BASE_URL": Config.APP_BASE_URL,
        }
    except Exception as e:
        results[-1]["status"] = "error"
        results[-1]["error"] = str(e)

    # Step 2: Token generation
    results.append({"step": 2, "name": "Token Generation", "status": "running"})
    try:
        token = secrets.token_urlsafe(32)
        results[-1]["status"] = "ok"
        results[-1]["token_length"] = len(token)
    except Exception as e:
        results[-1]["status"] = "error"
        results[-1]["error"] = str(e)
        token = "fallback_debug_token"

    # Step 3: URL building
    results.append({"step": 3, "name": "Verification URL Build", "status": "running"})
    try:
        base_url = Config.APP_BASE_URL.rstrip('/')
        verification_url = f"{base_url}/verify-email?token={token}"
        results[-1]["status"] = "ok"
        results[-1]["verification_url"] = verification_url
    except Exception as e:
        results[-1]["status"] = "error"
        results[-1]["error"] = str(e)
        verification_url = "http://localhost:5000/verify-email?token=debug"

    # Step 4: Send verification email
    results.append({"step": 4, "name": f"Send Verification Email to {recipient}", "status": "running"})
    try:
        success = send_verification_email(recipient, "debug_user", verification_url)
        results[-1]["status"] = "ok" if success else "failed"
        results[-1]["sent"] = success
    except Exception as e:
        results[-1]["status"] = "error"
        results[-1]["error"] = str(e)
        results[-1]["traceback"] = _tb.format_exc()

    all_ok = all(r["status"] in ("ok",) for r in results)
    return jsonify({
        "overall_status": "ALL SYSTEMS GO" if all_ok else "ISSUES DETECTED",
        "recipient": recipient,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "steps": results,
        "advice": (
            "All steps passed. Check recipient spam/promotions folder if email is not visible."
            if all_ok else
            "One or more steps failed. Check logs/email.log and logs/registration.log for details."
        )
    }), (200 if all_ok else 500)

@app.route('/test-email')
def test_email():
    """
    Diagnostic route: Send a test email and return sequential checks in plain text.
    Usage: GET /test-email?email=your@address.com
    """
    from app.services.email_service import send_smtp_email_sync
    from app import app as current_flask_app
    from flask import Response
    import smtplib

    recipient = request.args.get('email', '').strip().lower()
    if not recipient:
        recipient = Config.MAIL_USERNAME or "admin@ai-shield.local"

    print(f"[TEST-EMAIL] Initiating diagnostic test email to: {recipient}")

    test_subject = "AI Shield Diagnostics: SMTP Test"
    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>AI Shield Diagnostics</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #060913; color: #cbd5e1; padding: 20px; }
            .card { max-width: 600px; margin: 0 auto; background: #0d1423; border: 1px solid #0ea5e9; border-radius: 8px; padding: 25px; }
            h1 { color: #0ea5e9; margin-top: 0; }
            .success-msg { color: #10b981; font-weight: bold; font-size: 18px; }
            .info { color: #94a3b8; font-size: 13px; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>&#127313; AI Shield — Diagnostic Email</h1>
            <p class="success-msg">&#10003; SMTP Delivery Confirmed</p>
            <p>This is a diagnostic message from the <strong>/test-email</strong> route.</p>
            <p>If you received this, your Flask-Mail SMTP integration is fully operational.</p>
            <p class="info">This email was sent synchronously to verify end-to-end deliverability.</p>
        </div>
    </body>
    </html>
    """

    steps = []

    # Step 1: SMTP Connection Test
    try:
        smtp = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10)
        steps.append("SMTP Connected")
    except Exception as e:
        steps.append(f"SMTP Connection Failed: {str(e)}")
        return Response("\n".join(steps), mimetype='text/plain'), 500

    # Step 2: Authentication Test
    try:
        smtp.ehlo()
        if Config.MAIL_USE_TLS:
            smtp.starttls()
            smtp.ehlo()
        if Config.MAIL_USERNAME and Config.MAIL_PASSWORD:
            smtp.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
        smtp.close()
        steps.append("Authentication Success")
    except Exception as e:
        try:
            smtp.close()
        except Exception:
            pass
        steps.append(f"Authentication Failed: {str(e)}")
        return Response("\n".join(steps), mimetype='text/plain'), 500

    # Step 3: Send Test Email via Flask-Mail
    try:
        success = send_smtp_email_sync(current_flask_app, recipient, test_subject, test_html)
        if success:
            steps.append("Email Sent Successfully")
            return Response("\n".join(steps), mimetype='text/plain'), 200
        else:
            steps.append("Email Delivery Failed: Flask-Mail returned False. Check logs/email.log.")
            return Response("\n".join(steps), mimetype='text/plain'), 500
    except Exception as e:
        steps.append(f"Email Delivery Failed: {str(e)}")
        return Response("\n".join(steps), mimetype='text/plain'), 500


