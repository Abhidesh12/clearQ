import re
import secrets
import string
from urllib.parse import urlparse, urljoin
from flask import request, current_app
from werkzeug.security import generate_password_hash, check_password_hash

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def is_safe_url(target: str) -> bool:
    """Check if URL is safe for redirection"""
    if not target:
        return False
    
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    
    # Check same scheme and netloc
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password: str) -> str:
    """Hash password using werkzeug"""
    return generate_password_hash(password)

def verify_password(password_hash: str, password: str) -> bool:
    """Verify password against hash"""
    return check_password_hash(password_hash, password)
