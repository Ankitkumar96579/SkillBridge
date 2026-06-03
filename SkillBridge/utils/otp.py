import random
import time
from flask import session

OTP_EXPIRY_MINUTES = 5
MAX_ATTEMPTS = 3

def generate_otp():
    """Generate a random 6-digit OTP."""
    return str(random.randint(100000, 999999))

def store_otp(email, otp, purpose):
    """Store OTP data in the session."""
    session['otp_data'] = {
        'email': email,
        'otp': otp,
        'purpose': purpose,
        'timestamp': time.time(),
        'attempts': 0
    }

def verify_otp(email, otp, purpose):
    """
    Verify the provided OTP against the session data.
    Returns (success, message).
    """
    otp_data = session.get('otp_data')

    if not otp_data:
        return False, "No OTP found. Please request a new one."

    # Validate email and purpose
    if otp_data['email'] != email or otp_data['purpose'] != purpose:
        return False, "Invalid OTP request."

    # Check expiry
    if time.time() - otp_data['timestamp'] > OTP_EXPIRY_MINUTES * 60:
        session.pop('otp_data', None)
        return False, "OTP has expired. Please request a new one."

    # Check attempts
    if otp_data['attempts'] >= MAX_ATTEMPTS:
        session.pop('otp_data', None)
        return False, "Too many failed attempts. Please request a new OTP."

    # Check OTP match
    if otp_data['otp'] == otp:
        # Success! Clear OTP from session
        session.pop('otp_data', None)
        return True, "OTP verified successfully."
    else:
        # Increment attempts
        otp_data['attempts'] += 1
        session['otp_data'] = otp_data
        remaining = MAX_ATTEMPTS - otp_data['attempts']
        if remaining > 0:
            return False, f"Invalid OTP. {remaining} attempt(s) remaining."
        else:
            session.pop('otp_data', None)
            return False, "Too many failed attempts. Please request a new OTP."

def clear_otp():
    """Manually clear OTP data from session."""
    session.pop('otp_data', None)
