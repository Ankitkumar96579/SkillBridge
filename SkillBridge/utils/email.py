import smtplib
from email.message import EmailMessage
from flask import current_app

def send_otp_email(email, otp, purpose):
    """
    Send an OTP email using smtplib directly to ensure compatibility
    with Gmail App Passwords.
    """
    subjects = {
        'signup': 'Your SkillBridge Signup OTP',
        'admin_login': 'SkillBridge Admin 2FA Code',
        'forgot_password': 'SkillBridge Password Reset OTP'
    }

    subject = subjects.get(purpose, 'Your OTP Code')
    body = f"""
    Hello,

    Your OTP code for {purpose.replace('_', ' ')} is: {otp}

    This code will expire in 5 minutes.
    If you did not request this code, please ignore this email.

    Regards,
    The SkillBridge Team
    """

    # Retrieve configuration
    server_host = current_app.config.get('MAIL_SERVER', 'smtp.gmail.com')
    port = current_app.config.get('MAIL_PORT', 587)
    use_tls = current_app.config.get('MAIL_USE_TLS', True)
    use_ssl = current_app.config.get('MAIL_USE_SSL', False)
    username = current_app.config.get('MAIL_USERNAME')
    password = current_app.config.get('MAIL_PASSWORD')
    sender = current_app.config.get('MAIL_DEFAULT_SENDER', username)

    invalid_fields = []
    if not username or username == 'your_email@gmail.com':
        invalid_fields.append('MAIL_USERNAME')
    if not password or password == 'your_app_password':
        invalid_fields.append('MAIL_PASSWORD')

    if invalid_fields:
        return False, f"Email configuration is incomplete: {', '.join(invalid_fields)}"

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = email

    try:
        smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP

        # Use smtplib directly so OTP delivery stays independent of Flask-Mail.
        with smtp_class(server_host, port, timeout=20) as smtp:
            if use_tls and not use_ssl:
                smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
            return True, "Email sent successfully."
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False, str(e)
