import os
import re
import secrets
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
    send_security_alert_email
)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash("All fields are required.", "danger")
            return render_template('login.html')
            
        user = db_manager.authenticate_user(username, password)
        if user:
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
            user_record = db_manager.get_user_by_username(username)
            if user_record:
                attempts = session.get(f'failed_attempts_{username}', 0) + 1
                session[f'failed_attempts_{username}'] = attempts
                if attempts >= 3:
                    send_security_alert_email(
                        user_record['email'],
                        username,
                        "Multiple Failed Login Attempts",
                        f"There have been {attempts} failed login attempts on your account from remote address {request.remote_addr}. If this wasn't you, please secure your credentials immediately."
                    )
            security_logger.warning(f"FAILED LOGIN | User: {username} | IP: {request.remote_addr}")
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
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.", "danger")
            return render_template('register.html')
            
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('register.html')
            
        user_id = db_manager.create_user(username, email, password)
        if user_id:
            token = secrets.token_urlsafe(32)
            db_manager.set_user_verification_token(user_id, token)
            verification_url = url_for('verify_email', token=token, _external=True)
            send_verification_email(email, username, verification_url)
            security_logger.info(f"USER REGISTRATION | User: {username} | Email: {email} | IP: {request.remote_addr}")
            flash("Registration successful! A verification link has been sent to your email.", "success")
            return redirect(url_for('login'))
        else:
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
        flash("Invalid verification token.", "danger")
        return redirect(url_for('login'))
        
    user = db_manager.verify_user_email(token)
    if user:
        if 'user' in session and session['user']['id'] == user['id']:
            session['user']['is_verified'] = 1
        # Dispatch welcome email upon successful verification
        login_url = url_for('login', _external=True)
        send_welcome_email(user['email'], user['username'], login_url)
        flash("Email verified successfully! Your AI Shield node is now fully authorized.", "success")
        return redirect(url_for('login'))
    else:
        flash("Verification token expired or invalid.", "danger")
        return redirect(url_for('login'))

@app.route('/resend-verification', methods=['GET', 'POST'])
@login_required
def resend_verification():
    user = db_manager.get_user_by_id(session['user']['id'])
    if user:
        if user.get('is_verified', 0):
            flash("Your account is already verified.", "info")
            return redirect(url_for('dashboard'))
            
        token = secrets.token_urlsafe(32)
        db_manager.set_user_verification_token(user['id'], token)
        verification_url = url_for('verify_email', token=token, _external=True)
        send_verification_email(user['email'], user['username'], verification_url)
        flash("Verification email has been resent. Please check your inbox.", "success")
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
        return jsonify({"success": True, "message": "Subscribed successfully! Thank you for staying informed."})
    else:
        return jsonify({"success": True, "message": "Email is already subscribed."})


# ==========================================
# APPLICATION ROUTES
# ==========================================

