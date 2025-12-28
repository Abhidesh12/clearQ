import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FIXED: Create password context with fallback
try:
    # Try to create with bcrypt
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    print("✅ Using passlib with bcrypt")
except Exception:
    # Fallback to direct bcrypt
    pwd_context = None
    print("⚠️ Using direct bcrypt (passlib compatibility issue)")

def get_password_hash(password: str) -> str:
    """Hash password with bcrypt, handling 72-byte limit"""
    # Convert to bytes
    password_bytes = password.encode('utf-8')
    
    # TRUNCATE to 72 bytes if necessary (FIX FOR YOUR ERROR)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
        print(f"⚠️ Password truncated to 72 bytes for bcrypt")
    
    try:
        if pwd_context:
            # Use passlib if available
            return pwd_context.hash(password)
        else:
            # Fallback to direct bcrypt
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password_bytes, salt)
            return hashed.decode('utf-8')
    except Exception as e:
        # Ultimate fallback
        print(f"⚠️ Error in get_password_hash: {e}, using simple hash")
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password with bcrypt"""
    try:
        # Convert to bytes
        password_bytes = plain_password.encode('utf-8')
        
        # TRUNCATE to 72 bytes if necessary
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        
        if pwd_context:
            return pwd_context.verify(plain_password, hashed_password)
        else:
            # Direct bcrypt
            return bcrypt.checkpw(
                password_bytes,
                hashed_password.encode('utf-8')
            )
    except Exception as e:
        print(f"⚠️ Error verifying password: {e}")
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# For backward compatibility with your existing code
authenticate_user = None  # Will be defined in app.py or models
