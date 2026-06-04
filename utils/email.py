import requests
from flask import current_app

def send_otp_email(email, otp, purpose):
    """
    Send OTP email using Brevo API
    """

    subjects = {
        'signup': 'Your SkillBridge Signup OTP',
        'admin_login': 'SkillBridge Admin 2FA Code',
        'forgot_password': 'SkillBridge Password Reset OTP'
    }

    subject = subjects.get(purpose, 'Your OTP Code')

    html_content = f"""
    <html>
    <body>
        <h2>SkillBridge OTP Verification</h2>

        <p>Hello,</p>

        <p>Your OTP code for <b>{purpose.replace('_', ' ')}</b> is:</p>

        <h1 style="color:#2563eb;">{otp}</h1>

        <p>This code will expire in 5 minutes.</p>

        <p>If you did not request this code, please ignore this email.</p>

        <br>

        <p>Regards,<br>
        SkillBridge Team</p>
    </body>
    </html>
    """

    api_key = current_app.config.get('BREVO_API_KEY')

    if not api_key:
        return False, "BREVO_API_KEY is missing"

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    payload = {
        "sender": {
            "name": "SkillBridge",
            "email": current_app.config.get(
                'MAIL_DEFAULT_SENDER',
                'skillbridge1202@gmail.com'
            )
        },
        "to": [
            {
                "email": email
            }
        ],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            json=payload,
            headers=headers,
            timeout=30
        )

        print("Brevo Response:", response.status_code)
        print("Brevo Body:", response.text)

        if response.status_code == 201:
            return True, "Email sent successfully"

        return False, response.text

    except Exception as e:
        print("Brevo API Error:", e)
        return False, str(e)
