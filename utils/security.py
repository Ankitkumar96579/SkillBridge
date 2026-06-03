from flask_bcrypt import check_password_hash as bcrypt_check
from werkzeug.security import check_password_hash as werkzeug_check
from flask_bcrypt import generate_password_hash

def verify_password(pw_hash, plain_pw):
    """
    Verify password by trying Bcrypt first, then falling back to Werkzeug.
    Returns (is_valid, needs_migration)
    """
    if not pw_hash:
        return False, False
        
    # Check if it's a Bcrypt hash (usually starts with $2b$ or $2a$)
    if pw_hash.startswith('$2b$') or pw_hash.startswith('$2a$'):
        try:
            return bcrypt_check(pw_hash, plain_pw), False
        except ValueError:
            pass # Fallthrough if invalid salt
            
    # Check fallback (Werkzeug)
    is_valid = werkzeug_check(pw_hash, plain_pw)
    # If it's valid via Werkzeug, it needs migration to Bcrypt
    return is_valid, is_valid

def hash_password(password):
    """Generate a Bcrypt hash."""
    from app import bcrypt
    return bcrypt.generate_password_hash(password).decode('utf-8')
