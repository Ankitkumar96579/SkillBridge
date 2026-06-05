from flask import Blueprint, request, jsonify, session, current_app, redirect, flash, render_template
from utils.otp import generate_otp, store_otp, verify_otp, clear_otp
from utils.email import send_otp_email
from utils.security import verify_password, hash_password
import MySQLdb.cursors
from time import time

auth_bp = Blueprint('auth', __name__)
@auth_bp.route('/send_otp', methods=['POST'])
def send_otp():
    """
    Send an OTP to the user's email.
    """

    data = request.get_json()

    email = data.get('email')
    purpose = data.get('purpose')

    if not email or not purpose:
        return jsonify({
            'success': False,
            'message': 'Email and purpose are required.'
        }), 400

    # OTP resend protection (5 minutes)
    last_sent = session.get(f'otp_sent_{email}_{purpose}')

    if last_sent:

        remaining = 300 - (time() - last_sent)

        if remaining > 0:

            return jsonify({
                'success': False,
                'message': f'Please wait {int(remaining)} seconds before requesting another OTP.',
                'remaining': int(remaining)
            }), 429

    from app import mysql, bcrypt

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Signup validation
    if purpose == 'signup':

        cur.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        if cur.fetchone():

            return jsonify({
                'success': False,
                'message': 'An account with this email already exists.'
            }), 400

    # Forgot password / Admin login validation
    elif purpose in ['admin_login', 'forgot_password']:

        table = 'admins' if purpose == 'admin_login' else 'users'

        cur.execute(
            f"SELECT * FROM {table} WHERE email=%s",
            (email,)
        )

        if not cur.fetchone():

            return jsonify({
                'success': False,
                'message': 'Email not found.'
            }), 404

    otp = generate_otp()

    store_otp(email, otp, purpose)

    print(
        f"DEBUG: auth.py calling send_otp_email for {email}...",
        flush=True
    )

    success, msg = send_otp_email(
        email,
        otp,
        purpose
    )

    print(
        f"DEBUG: send_otp_email returned: {success}, {msg}",
        flush=True
    )

    if success:

        session[f'otp_sent_{email}_{purpose}'] = time()

        return jsonify({
            'success': True,
            'message': 'OTP sent to your email.',
            'remaining': 300
        })

    return jsonify({
        'success': False,
        'message': f'Failed to send email: {msg}'
    }), 500

@auth_bp.route('/verify_otp', methods=['POST'])
def verify():
    """
    Verify the user's OTP.
    """
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    purpose = data.get('purpose')

    if not all([email, otp, purpose]):
        return jsonify({'success': False, 'message': 'Missing data.'}), 400

    success, msg = verify_otp(email, otp, purpose)
    
    if success:
        # On success, we set a flag in session that this email + purpose is verified
        session[f'verified_{purpose}'] = email
        return jsonify({'success': True, 'message': msg})
    else:
        return jsonify({'success': False, 'message': msg})

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """
    Final step for user signup.
    """
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    if confirm_password is not None and password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match.'}), 400

    # Security check: must be verified
    if session.get('verified_signup') != email:
        return jsonify({'success': False, 'message': 'Email not verified.'}), 401

    from app import mysql, bcrypt

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    try:
        cur.execute("INSERT INTO users(name, email, password) VALUES(%s, %s, %s)", (name, email, hashed_pw))
        new_uid = cur.lastrowid
        
        # Credits Bonus
        cur.execute("INSERT INTO wallet (user_id, credits) VALUES (%s, 20)", (new_uid,))
        cur.execute("INSERT INTO transactions (user_id, type, credits, description) VALUES (%s, 'Earned', 20, 'Welcome Bonus!')", (new_uid,))
        
        mysql.connection.commit()

        from app import increment_total_user_metric
        increment_total_user_metric()

        session.pop('verified_signup', None)
        return jsonify({'success': True, 'message': 'Account created successfully! Please login.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/admin_login_verify', methods=['POST'])
def admin_login_verify():
    """
    Final step for admin login (2FA).
    """
    data = request.get_json()
    email = data.get('email')
    
    if session.get('verified_admin_login') != email:
        return jsonify({'success': False, 'message': '2FA verification required.'}), 401

    from app import mysql
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM admins WHERE email=%s", (email,))
    admin = cur.fetchone()

    if admin:
        session['role'] = 'admin'
        session['admin_id'] = admin['id']
        session.pop('verified_admin_login', None)
        return jsonify({'success': True, 'message': 'Login successful.', 'redirect': '/admin_panel'})
    else:
        return jsonify({'success': False, 'message': 'Admin not found.'}), 404

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    """
    Final step for forgot password.
    """
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('password')

    if session.get('verified_forgot_password') != email:
        return jsonify({'success': False, 'message': 'Email verification required.'}), 401

    from app import mysql, bcrypt
    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cur = mysql.connection.cursor()
    
    cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_pw, email))
    mysql.connection.commit()
    
    session.pop('verified_forgot_password', None)
    return jsonify({'success': True, 'message': 'Password reset successful. Please login.'})

@auth_bp.route('/check_credentials', methods=['POST'])
def check_credentials():
    """
    Step 1 for Admin Login: Check password before sending OTP.
    """
    data = request.get_json()
    usernameOrEmail = data.get('username') # The form might send username or email
    password = data.get('password')

    from app import mysql, bcrypt
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Check if it's email or username
    if '@' in usernameOrEmail:
        cur.execute("SELECT * FROM admins WHERE email=%s", (usernameOrEmail,))
    else:
        cur.execute("SELECT * FROM admins WHERE username=%s", (usernameOrEmail,))
    
    admin = cur.fetchone()

    if admin:
        is_valid, needs_migration = verify_password(admin['password'], password)
        if is_valid:
            # Auto-migrate Admin password if needed
            if needs_migration:
                new_hash = hash_password(password)
                cur.execute("UPDATE admins SET password=%s WHERE id=%s", (new_hash, admin['id']))
                mysql.connection.commit()
                
            # Credentials match, send OTP
            return jsonify({'success': True, 'email': admin['email']})
    
    return jsonify({'success': False, 'message': 'Invalid credentials.'})
