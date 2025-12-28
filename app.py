import os
import json
import random
import re
import uuid
import secrets
import logging
import traceback
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import razorpay
import requests
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import hashlib
from urllib.parse import urlparse, urljoin
import bleach

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Force FLASK to find templates
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
static_dir = os.path.join(basedir, 'static')

app = Flask(__name__, 
            template_folder=template_dir,
            static_folder=static_dir)

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

# Generate secure secret keys if not in environment
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
    on_breach=lambda _: None  # Custom handler will catch this
)

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

# Use PostgreSQL in production, SQLite for development
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Fix for Heroku PostgreSQL URL
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'clearq.db')}"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_size': 10,
    'max_overflow': 20,
}

db = SQLAlchemy(app)

# ============================================================================
# FILE UPLOAD CONFIGURATION
# ============================================================================

app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {
    'png', 'jpg', 'jpeg', 'gif',  # Images
    'pdf', 'doc', 'docx',         # Documents
    'zip', 'rar',                 # Archives
    'mp4', 'mov', 'avi',          # Videos
    'mp3', 'wav'                  # Audio
}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_images'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'digital_products'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'resources'), exist_ok=True)

# ============================================================================
# EMAIL CONFIGURATION
# ============================================================================

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@clearq.in')
app.config['MAIL_DEBUG'] = os.environ.get('MAIL_DEBUG', 'false').lower() == 'true'

# ============================================================================
# PAYMENT CONFIGURATION (RAZORPAY)
# ============================================================================

app.config['RAZORPAY_KEY_ID'] = os.environ.get('RAZORPAY_KEY_ID', '')
app.config['RAZORPAY_KEY_SECRET'] = os.environ.get('RAZORPAY_KEY_SECRET', '')

# Initialize Razorpay client
razorpay_client = None
if app.config['RAZORPAY_KEY_ID'] and app.config['RAZORPAY_KEY_SECRET']:
    try:
        razorpay_client = razorpay.Client(
            auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET'])
        )
        logger.info("Razorpay client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Razorpay client: {e}")
        razorpay_client = None

# ============================================================================
# LOGIN MANAGER
# ============================================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'

# ============================================================================
# SERIALIZERS (FOR EMAIL TOKENS)
# ============================================================================

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ============================================================================
# CUSTOM DECORATORS
# ============================================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def mentor_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'mentor':
            flash('Mentor access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def learner_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'learner':
            flash('Learner access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def verified_email_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_email_verified:
            flash('Please verify your email address to access this page.', 'warning')
            return redirect(url_for('resend_verification'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']

def validate_file(file) -> tuple[bool, str]:
    """Validate uploaded file for security."""
    if not file or file.filename == '':
        return False, 'No file selected'
    
    if not allowed_file(file.filename):
        return False, 'File type not allowed'
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > app.config['MAX_CONTENT_LENGTH']:
        return False, f'File too large. Maximum size is {app.config["MAX_CONTENT_LENGTH"] // (1024*1024)}MB'
    
    # Check filename security
    filename = secure_filename(file.filename)
    if not filename:
        return False, 'Invalid filename'
    
    return True, 'File valid'

def save_profile_image(file, user_id: int) -> Optional[str]:
    """Save profile image and return path."""
    valid, message = validate_file(file)
    if not valid:
        logger.warning(f"Invalid profile image: {message}")
        return None
    
    # Create secure filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{user_id}_{timestamp}.{ext}"
    
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_images')
    os.makedirs(upload_path, exist_ok=True)
    
    filepath = os.path.join(upload_path, filename)
    try:
        file.save(filepath)
        
        # Generate thumbnail for profile display
        from PIL import Image
        img = Image.open(filepath)
        img.thumbnail((300, 300))
        thumbnail_path = os.path.join(upload_path, f"thumb_{filename}")
        img.save(thumbnail_path)
        
        return f'uploads/profile_images/{filename}'
    except Exception as e:
        logger.error(f"Error saving profile image: {e}")
        return None

def save_digital_product(file, user_id: int, product_name: str) -> Optional[str]:
    """Save digital product file and return path."""
    valid, message = validate_file(file)
    if not valid:
        logger.warning(f"Invalid digital product: {message}")
        return None
    
    # Create secure filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    ext = file.filename.rsplit('.', 1)[1].lower()
    safe_name = re.sub(r'[^\w\-_]', '', product_name.replace(' ', '_'))
    filename = f"product_{user_id}_{safe_name}_{timestamp}.{ext}"
    
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'digital_products')
    os.makedirs(upload_path, exist_ok=True)
    
    filepath = os.path.join(upload_path, filename)
    try:
        file.save(filepath)
        return f'uploads/digital_products/{filename}'
    except Exception as e:
        logger.error(f"Error saving digital product: {e}")
        return None

def generate_slug(text: str) -> str:
    """Generate URL-friendly slug from text."""
    if not text:
        return str(uuid.uuid4())[:8]
    
    # Convert to lowercase
    slug = text.lower()
    # Remove special characters
    slug = re.sub(r'[^\w\s-]', '', slug)
    # Replace spaces with hyphens
    slug = re.sub(r'[-\s]+', '-', slug)
    # Remove leading/trailing hyphens and spaces
    slug = slug.strip('- ')
    
    if not slug:
        slug = str(uuid.uuid4())[:8]
    
    return slug

def is_safe_url(target: str) -> bool:
    """Check if URL is safe for redirection."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def sanitize_html(content: str) -> str:
    """Sanitize HTML content to prevent XSS."""
    if not content:
        return ''
    
    allowed_tags = [
        'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'h1', 'h2', 'h3', 'h4', 
        'h5', 'h6', 'hr', 'i', 'li', 'ol', 'p', 'pre', 'span', 'strong', 'ul'
    ]
    allowed_attrs = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'div': ['class'],
        'span': ['class']
    }
    
    return bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )

def get_available_dates(mentor_id: int, days_ahead: int = 14) -> List[Dict]:
    """Get available dates for booking."""
    from datetime import datetime, timedelta
    
    today = datetime.now().date()
    available_dates = []
    
    # Get booked dates for this mentor
    booked_dates = Booking.query.filter_by(mentor_id=mentor_id).all()
    
    for i in range(days_ahead):
        current_date = today + timedelta(days=i)
        
        # Check if date is not fully booked (max 8 slots per day)
        day_bookings = [b for b in booked_dates if b.booking_date and b.booking_date.date() == current_date]
        
        date_info = {
            'date': current_date,
            'day_name': current_date.strftime('%a'),
            'date_str': current_date.strftime('%b %d'),
            'full_date': current_date.strftime('%Y-%m-%d'),
            'day_num': current_date.day,
            'month': current_date.strftime('%b'),
            'is_today': i == 0,
            'is_tomorrow': i == 1,
            'available_slots': max(0, 8 - len(day_bookings))
        }
        
        available_dates.append(date_info)
    
    return available_dates

def get_time_slots_for_date(mentor_id: int, date_str: str) -> List[str]:
    """Get available time slots for a specific date."""
    try:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return []
    
    # Standard time slots
    all_slots = [
        "9:00 AM", "10:00 AM", "11:00 AM", 
        "12:00 PM", "1:00 PM", "2:00 PM", 
        "3:00 PM", "4:00 PM", "5:00 PM", 
        "6:00 PM", "7:00 PM", "8:00 PM"
    ]
    
    # Get booked slots for this date
    booked_slots = [
        b.slot_time for b in Booking.query.filter_by(
            mentor_id=mentor_id
        ).all() 
        if b.booking_date and b.booking_date.date() == date_obj and b.slot_time
    ]
    
    # Filter out booked slots
    available_slots = [s for s in all_slots if s not in booked_slots]
    
    return available_slots

# ============================================================================
# EMAIL FUNCTIONS
# ============================================================================

def send_email(to: str, subject: str, body: str, html_body: Optional[str] = None) -> bool:
    """Send email using configured mail server."""
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        logger.info(f"Email not sent (no credentials): To={to}, Subject={subject}")
        return True  # Return True in development to continue
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to
        
        # Attach plain text version
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach HTML version if provided
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))
        
        # Connect to SMTP server
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            if app.config['MAIL_USE_TLS']:
                server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        
        logger.info(f"Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False

def send_verification_email(user) -> bool:
    """Send email verification link."""
    token = serializer.dumps(user.email, salt='email-verify')
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = 'Verify Your Email - ClearQ'
    
    body = f"""
Welcome to ClearQ!

Please verify your email address by clicking the link below:
{verification_url}

If you did not create an account, please ignore this email.

This link will expire in 24 hours.

Best regards,
The ClearQ Team
"""
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email - ClearQ</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">ClearQ</h1>
        <p style="color: white; opacity: 0.9; margin: 10px 0 0 0;">Mentorship Platform</p>
    </div>
    
    <div style="background: #fff; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <h2 style="color: #333; margin-top: 0;">Welcome to ClearQ!</h2>
        
        <p>Hi {user.username},</p>
        
        <p>Thank you for registering with ClearQ. To complete your registration and access all features, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                Verify Email Address
            </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;">
            <a href="{verification_url}" style="color: #667eea; text-decoration: none;">{verification_url}</a>
        </p>
        
        <p>This verification link will expire in 24 hours.</p>
        
        <p>If you did not create a ClearQ account, please ignore this email.</p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 0.9em;">
            Need help? Contact our support team at 
            <a href="mailto:support@clearq.in" style="color: #667eea;">support@clearq.in</a>
        </p>
    </div>
    
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 0.8em;">
        <p>&copy; {datetime.now().year} ClearQ. All rights reserved.</p>
    </div>
</body>
</html>
"""
    
    return send_email(user.email, subject, body, html_body)

def send_password_reset_email(user) -> bool:
    """Send password reset link."""
    token = serializer.dumps(user.email, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)
    
    subject = 'Reset Your Password - ClearQ'
    
    body = f"""
Reset Your ClearQ Password

You requested to reset your password. Click the link below to create a new password:
{reset_url}

If you did not request a password reset, please ignore this email.

This link will expire in 1 hour.

Best regards,
The ClearQ Team
"""
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password - ClearQ</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">ClearQ</h1>
        <p style="color: white; opacity: 0.9; margin: 10px 0 0 0;">Password Reset</p>
    </div>
    
    <div style="background: #fff; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
        
        <p>Hi {user.username},</p>
        
        <p>We received a request to reset your password for your ClearQ account. Click the button below to create a new password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                Reset Password
            </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;">
            <a href="{reset_url}" style="color: #667eea; text-decoration: none;">{reset_url}</a>
        </p>
        
        <p>This reset link will expire in 1 hour.</p>
        
        <p>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 0.9em;">
            Need help? Contact our support team at 
            <a href="mailto:support@clearq.in" style="color: #667eea;">support@clearq.in</a>
        </p>
    </div>
    
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 0.8em;">
        <p>&copy; {datetime.now().year} ClearQ. All rights reserved.</p>
    </div>
</body>
</html>
"""
    
    return send_email(user.email, subject, body, html_body)

def send_booking_confirmation_email(booking, user) -> bool:
    """Send booking confirmation email."""
    mentor = User.query.get(booking.mentor_id)
    
    subject = f'Booking Confirmed - {booking.service_name}'
    
    body = f"""
Booking Confirmed!

Dear {user.username},

Your booking has been successfully confirmed. Here are the details:

Service: {booking.service_name}
Mentor: {mentor.full_name if mentor else 'N/A'}
Date: {booking.booking_date.strftime('%B %d, %Y') if booking.booking_date else 'To be scheduled'}
Time: {booking.slot_time}
Price: ₹{booking.price or 0}

Meeting Link: {booking.meeting_link or 'Will be provided before the session'}

Please join the meeting on time. If you need to reschedule or cancel, please contact the mentor at least 24 hours in advance.

Best regards,
The ClearQ Team
"""
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Booking Confirmed - ClearQ</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">ClearQ</h1>
        <p style="color: white; opacity: 0.9; margin: 10px 0 0 0;">Booking Confirmation</p>
    </div>
    
    <div style="background: #fff; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <h2 style="color: #333; margin-top: 0;">Booking Confirmed! 🎉</h2>
        
        <p>Hi {user.username},</p>
        
        <p>Your booking has been successfully confirmed. Here are your booking details:</p>
        
        <div style="background: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; margin: 20px 0;">
            <p><strong>Service:</strong> {booking.service_name}</p>
            <p><strong>Mentor:</strong> {mentor.full_name if mentor else 'N/A'}</p>
            <p><strong>Date:</strong> {booking.booking_date.strftime('%B %d, %Y') if booking.booking_date else 'To be scheduled'}</p>
            <p><strong>Time:</strong> {booking.slot_time}</p>
            <p><strong>Price:</strong> ₹{booking.price or 0}</p>
            <p><strong>Status:</strong> {booking.status}</p>
        </div>
        
        <p><strong>Meeting Link:</strong> 
            {booking.meeting_link if booking.meeting_link else 'Will be provided before the session'}
        </p>
        
        <div style="background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #2196F3;">
            <p style="margin: 0; color: #0c5460;">
                <strong>Important:</strong> Please join the meeting on time. If you need to reschedule or cancel, please contact the mentor at least 24 hours in advance.
            </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{url_for('dashboard', _external=True)}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                Go to Dashboard
            </a>
        </div>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 0.9em;">
            Need to cancel or reschedule? Contact support at 
            <a href="mailto:support@clearq.in" style="color: #667eea;">support@clearq.in</a>
        </p>
    </div>
    
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 0.8em;">
        <p>&copy; {datetime.now().year} ClearQ. All rights reserved.</p>
    </div>
</body>
</html>
"""
    
    return send_email(user.email, subject, body, html_body)

# ============================================================================
# AI RECOMMENDATION ENGINE
# ============================================================================

def get_ai_recommendations(user_goal: str, limit: int = 3) -> List[Any]:
    """
    Use TF-IDF and cosine similarity to recommend mentors based on user goal.
    """
    try:
        # Get all verified mentors
        mentors = User.query.filter_by(role='mentor', is_verified=True).all()
        
        if not mentors:
            return []
        
        # Prepare mentor data
        mentor_data = []
        for mentor in mentors:
            # Combine relevant text fields
            text_content = " ".join([
                mentor.domain or "",
                mentor.company or "",
                mentor.skills or "",
                mentor.bio or "",
                mentor.full_name or "",
                mentor.job_title or ""
            ]).strip()
            
            mentor_data.append({
                'id': mentor.id,
                'content': text_content,
                'mentor': mentor
            })
        
        if not mentor_data:
            return []
        
        # Create corpus
        corpus = [m['content'] for m in mentor_data]
        corpus.append(user_goal)  # Add user goal as last document
        
        # TF-IDF Vectorization
        vectorizer = TfidfVectorizer(
            stop_words='english',
            max_features=1000,
            min_df=1,
            max_df=0.8
        )
        
        tfidf_matrix = vectorizer.fit_transform(corpus)
        
        # Calculate cosine similarity between user goal and mentors
        goal_vector = tfidf_matrix[-1]
        mentor_vectors = tfidf_matrix[:-1]
        
        similarities = cosine_similarity(goal_vector, mentor_vectors).flatten()
        
        # Get indices of top matches
        top_indices = similarities.argsort()[::-1][:limit]
        
        # Return top mentors with similarity > 0.1
        recommended_mentors = []
        for idx in top_indices:
            if similarities[idx] > 0.1:
                recommended_mentors.append(mentor_data[idx]['mentor'])
        
        return recommended_mentors
        
    except Exception as e:
        logger.error(f"Error in AI recommendations: {e}")
        return []

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='learner', nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Email verification
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Mentor specific fields
    full_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    job_title = db.Column(db.String(100), nullable=True)
    domain = db.Column(db.String(100), nullable=True)
    company = db.Column(db.String(100), nullable=True)
    previous_company = db.Column(db.String(100), nullable=True)
    experience = db.Column(db.String(50), nullable=True)
    skills = db.Column(db.Text, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    price = db.Column(db.Integer, default=0)
    availability = db.Column(db.String(200), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Profile
    profile_image = db.Column(db.String(500), nullable=True)
    facebook_url = db.Column(db.String(200), nullable=True)
    instagram_url = db.Column(db.String(200), nullable=True)
    youtube_url = db.Column(db.String(200), nullable=True)
    linkedin_url = db.Column(db.String(200), nullable=True)
    twitter_url = db.Column(db.String(200), nullable=True)
    github_url = db.Column(db.String(200), nullable=True)
    
    # Stats
    success_rate = db.Column(db.Integer, default=95)
    response_rate = db.Column(db.Integer, default=98)
    rating = db.Column(db.Float, default=4.9)
    review_count = db.Column(db.Integer, default=0)
    profile_views = db.Column(db.Integer, default=0)
    total_sessions = db.Column(db.Integer, default=0)
    total_earnings = db.Column(db.Integer, default=0)
    
    # Preferences
    timezone = db.Column(db.String(50), default='UTC')
    notification_preferences = db.Column(db.Text, default='{}')  # JSON
    
    # Indexes
    __table_args__ = (
        db.Index('idx_user_role_verified', 'role', 'is_verified'),
        db.Index('idx_user_email_verified', 'email', 'is_email_verified'),
    )
    
    def set_password(self, password: str):
        """Hash and set password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def get_notification_preferences(self) -> Dict:
        """Get notification preferences as dict."""
        try:
            return json.loads(self.notification_preferences)
        except:
            return {}
    
    def set_notification_preferences(self, prefs: Dict):
        """Set notification preferences."""
        self.notification_preferences = json.dumps(prefs)
    
    def to_dict(self) -> Dict:
        """Convert user to dictionary for API responses."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'full_name': self.full_name,
            'profile_image': self.profile_image,
            'rating': self.rating,
            'review_count': self.review_count,
            'domain': self.domain,
            'company': self.company,
            'experience': self.experience
        }

class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    detailed_description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.String(50), nullable=True)
    
    # Service type
    service_type = db.Column(db.String(50), default='consultation', nullable=False)
    
    # Digital product fields
    digital_product_name = db.Column(db.String(200), nullable=True)
    digital_product_description = db.Column(db.Text, nullable=True)
    digital_product_file = db.Column(db.String(500), nullable=True)
    digital_product_link = db.Column(db.String(500), nullable=True)
    access_after_payment = db.Column(db.Boolean, default=True)
    
    # Status
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_featured = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Metadata
    tags = db.Column(db.String(200), nullable=True)  # Comma-separated tags
    category = db.Column(db.String(50), nullable=True)
    
    # Relationships
    mentor = db.relationship('User', backref=db.backref('services', lazy=True))
    
    __table_args__ = (
        db.Index('idx_service_mentor_active', 'mentor_id', 'is_active'),
        db.UniqueConstraint('mentor_id', 'slug', name='uq_mentor_service_slug'),
        db.Index('idx_service_type_category', 'service_type', 'category'),
    )
    
    def get_tags_list(self) -> List[str]:
        """Get tags as list."""
        if not self.tags:
            return []
        return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
    
    def set_tags_list(self, tags: List[str]):
        """Set tags from list."""
        self.tags = ','.join([tag.strip() for tag in tags if tag.strip()])

class Booking(db.Model):
    __tablename__ = 'bookings'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    
    # Booking details
    service_name = db.Column(db.String(100), nullable=False)
    slot_time = db.Column(db.String(50), nullable=True)
    booking_date = db.Column(db.DateTime, nullable=True, index=True)
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    price = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    
    # Meeting details
    meeting_link = db.Column(db.String(500), nullable=True)
    meeting_platform = db.Column(db.String(50), nullable=True)
    meeting_id = db.Column(db.String(100), nullable=True)
    meeting_password = db.Column(db.String(100), nullable=True)
    meeting_notes = db.Column(db.Text, nullable=True)
    
    # Session completion
    is_session_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    session_feedback = db.Column(db.Text, nullable=True)
    session_rating = db.Column(db.Integer, nullable=True)
    
    # Payment
    payment_status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    razorpay_order_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    cancelled_at = db.Column(db.DateTime, nullable=True)
    refund_status = db.Column(db.String(20), nullable=True)
    
    # Relationships
    mentor = db.relationship('User', foreign_keys=[mentor_id], backref='mentor_bookings')
    learner = db.relationship('User', foreign_keys=[learner_id], backref='learner_bookings')
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_booking_mentor_date', 'mentor_id', 'booking_date'),
        db.Index('idx_booking_learner_status', 'learner_id', 'status'),
        db.Index('idx_booking_date_status', 'booking_date', 'status'),
        db.Index('idx_booking_payment_status', 'payment_status'),
    )

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    program_name = db.Column(db.String(100), nullable=False)
    program_type = db.Column(db.String(50), default='career_mentorship')
    
    # Enrollment details
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='active', nullable=False)
    
    # Payment
    payment_status = db.Column(db.String(20), default='pending', nullable=False)
    payment_amount = db.Column(db.Integer, default=0)
    payment_method = db.Column(db.String(50), nullable=True)
    transaction_id = db.Column(db.String(100), nullable=True)
    
    # Additional data
    additional_data = db.Column(db.Text, nullable=True)  # JSON
    
    # Progress tracking
    progress = db.Column(db.Integer, default=0)  # Percentage
    completed_modules = db.Column(db.Integer, default=0)
    total_modules = db.Column(db.Integer, default=0)
    
    # Relationships
    user = db.relationship('User', backref='enrollments')
    
    __table_args__ = (
        db.Index('idx_enrollment_user_status', 'user_id', 'status'),
        db.Index('idx_enrollment_program_type', 'program_type'),
    )
    
    def get_additional_data(self) -> Dict:
        """Get additional data as dict."""
        try:
            return json.loads(self.additional_data) if self.additional_data else {}
        except:
            return {}
    
    def set_additional_data(self, data: Dict):
        """Set additional data from dict."""
        self.additional_data = json.dumps(data)

class Payment(db.Model):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'), nullable=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollments.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    
    # Payment details
    amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    currency = db.Column(db.String(3), default='INR', nullable=False)
    payment_method = db.Column(db.String(50), nullable=True)
    payment_gateway = db.Column(db.String(50), default='razorpay')
    
    # Razorpay fields
    razorpay_order_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    
    # Status
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    captured = db.Column(db.Boolean, default=False)
    refunded = db.Column(db.Boolean, default=False)
    refund_amount = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Metadata
    notes = db.Column(db.Text, nullable=True)
    meta_data = db.Column(db.Text, nullable=True)  # JSON
    
    # Relationships
    user = db.relationship('User', backref='payments')
    booking = db.relationship('Booking', backref='payment_record')
    enrollment = db.relationship('Enrollment')
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_payment_user_status', 'user_id', 'status'),
        db.Index('idx_payment_created', 'created_at'),
        db.Index('idx_payment_gateway', 'payment_gateway'),
    )
    
    def get_metadata(self) -> Dict:
        """Get metadata as dict."""
        try:
            return json.loads(self.meta_data) if self.meta_data else {}
        except:
            return {}
    
    def set_metadata(self, data: Dict):
        """Set meta_data from dict."""
        self.meta_data = json.dumps(data)

class DigitalProductAccess(db.Model):
    __tablename__ = 'digital_product_access'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=True)
    
    # Access details
    access_granted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    
    # Usage tracking
    downloads_count = db.Column(db.Integer, default=0)
    last_download_at = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)
    last_accessed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='digital_accesses')
    service = db.relationship('Service', backref='accesses')
    payment = db.relationship('Payment')
    
    __table_args__ = (
        db.Index('idx_access_user_active', 'user_id', 'is_active'),
        db.Index('idx_access_expires', 'expires_at'),
        db.UniqueConstraint('user_id', 'service_id', name='uq_user_service_access'),
    )

class Review(db.Model):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    
    # Review content
    rating = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    
    # Moderation
    is_approved = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    moderator_notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    mentor = db.relationship('User', foreign_keys=[mentor_id], backref='mentor_reviews')
    learner = db.relationship('User', foreign_keys=[learner_id], backref='learner_reviews')
    booking = db.relationship('Booking')
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_review_mentor_rating', 'mentor_id', 'rating'),
        db.Index('idx_review_approved', 'is_approved'),
        db.UniqueConstraint('booking_id', name='uq_booking_review'),
    )

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Notification details
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False, index=True)
    
    # Status
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)
    
    # Metadata
    action_url = db.Column(db.String(500), nullable=True)
    icon = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.Integer, default=0)  # 0=low, 1=normal, 2=high
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='notifications')
    
    __table_args__ = (
        db.Index('idx_notification_user_read', 'user_id', 'is_read'),
        db.Index('idx_notification_created', 'created_at'),
    )

# ============================================================================
# LOGIN MANAGER USER LOADER
# ============================================================================

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load user by ID for Flask-Login."""
    try:
        return User.query.get(int(user_id))
    except:
        return None

# ============================================================================
# TEMPLATE FILTERS
# ============================================================================

@app.template_filter('datetime')
def format_datetime(value: datetime, format: str = '%Y-%m-%d %H:%M') -> str:
    """Format datetime in templates."""
    if value is None:
        return ''
    return value.strftime(format)

@app.template_filter('date')
def format_date(value: datetime, format: str = '%Y-%m-%d') -> str:
    """Format date in templates."""
    if value is None:
        return ''
    return value.strftime(format)

@app.template_filter('time')
def format_time(value: datetime, format: str = '%H:%M') -> str:
    """Format time in templates."""
    if value is None:
        return ''
    return value.strftime(format)

@app.template_filter('currency')
def format_currency(value: int) -> str:
    """Format currency in templates."""
    if value is None:
        return '₹0'
    return f'₹{value:,}'

@app.template_filter('pluralize')
def pluralize(value: int, singular: str, plural: str = None) -> str:
    """Pluralize words in templates."""
    if plural is None:
        plural = singular + 's'
    return singular if value == 1 else plural

@app.template_filter('truncate')
def truncate(text: str, length: int = 100, ellipsis: str = '...') -> str:
    """Truncate text in templates."""
    if len(text) <= length:
        return text
    return text[:length].rsplit(' ', 1)[0] + ellipsis

@app.template_filter('from_json')
def from_json(value: str) -> Dict:
    """Parse JSON in templates."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except:
        return {}

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"500 Error: {error}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def ratelimit_error(error):
    return render_template('errors/429.html'), 429

@app.errorhandler(CSRFError)
def csrf_error(error):
    flash('CSRF token missing or invalid. Please try again.', 'danger')
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle uncaught exceptions."""
    db.session.rollback()
    
    # Log the error
    logger.error(f"Unhandled exception: {error}")
    logger.error(traceback.format_exc())
    
    # For API requests, return JSON
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': 'An internal server error occurred'
        }), 500
    
    # For web requests, show error page
    return render_template('errors/500.html'), 500

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page."""
    # Get featured mentors
    try:
        featured_mentors = User.query.filter_by(
            role='mentor',
            is_verified=True,
            is_active=True
        ).order_by(User.rating.desc()).limit(6).all()
    except Exception:
        featured_mentors = []
    
    # Get featured services
    try:
        featured_services = Service.query.filter_by(
            is_active=True,
            is_featured=True
        ).order_by(Service.created_at.desc()).limit(6).all()
    except Exception:
        featured_services = []
    
    # Get stats for display
    try:
        stats = {
            'mentors': User.query.filter_by(role='mentor', is_verified=True).count(),
            'sessions': Booking.query.filter_by(status='completed').count(),
            'learners': User.query.filter_by(role='learner').count(),
            'success_rate': 95
        }
    except Exception:
        stats = {
            'mentors': 0,
            'sessions': 0,
            'learners': 0,
            'success_rate': 95
        }
    
    return render_template('index.html',
                         featured_mentors=featured_mentors,
                         featured_services=featured_services,
                         stats=stats)
@app.route('/mentorship-program')
def mentorship_program():
    """Mentorship program page."""
    # Get featured mentorship programs
    featured_programs = Service.query.filter_by(
        is_active=True,
        is_featured=True
    ).order_by(Service.created_at.desc()).limit(6).all()
    
    # Get stats
    stats = {
        'total_programs': Service.query.filter_by(is_active=True).count(),
        'active_mentors': User.query.filter_by(role='mentor', is_verified=True).count(),
        'success_rate': 95
    }
    
    return render_template('mentorship_program.html',
                         featured_programs=featured_programs,
                         stats=stats)
@app.route('/explore', methods=['GET', 'POST'])
def explore():
    """Explore mentors and services."""
    query = request.args.get('q', '')
    domain = request.args.get('domain', '')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    sort = request.args.get('sort', 'rating')
    
    # Base query
    mentors_query = User.query.filter_by(
        role='mentor',
        is_verified=True,
        is_active=True
    )
    
    # Apply filters
    if query:
        mentors_query = mentors_query.filter(
            db.or_(
                User.full_name.ilike(f'%{query}%'),
                User.domain.ilike(f'%{query}%'),
                User.skills.ilike(f'%{query}%'),
                User.company.ilike(f'%{query}%')
            )
        )
    
    if domain:
        mentors_query = mentors_query.filter(User.domain.ilike(f'%{domain}%'))
    
    # Apply sorting
    if sort == 'rating':
        mentors_query = mentors_query.order_by(User.rating.desc())
    elif sort == 'price_low':
        mentors_query = mentors_query.order_by(User.price.asc())
    elif sort == 'price_high':
        mentors_query = mentors_query.order_by(User.price.desc())
    elif sort == 'experience':
        mentors_query = mentors_query.order_by(User.experience.desc())
    else:
        mentors_query = mentors_query.order_by(User.created_at.desc())
    
    # Get mentors
    page = request.args.get('page', 1, type=int)
    per_page = 12
    mentors = mentors_query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique domains for filter dropdown
    domains = db.session.query(User.domain).filter(
        User.domain.isnot(None),
        User.role == 'mentor',
        User.is_verified == True
    ).distinct().all()
    domains = [d[0] for d in domains if d[0]]
    
    # AI recommendations if search query
    recommendations = []
    if query and request.method == 'GET':
        recommendations = get_ai_recommendations(query, limit=3)
    
    return render_template('explore.html',
                         mentors=mentors,
                         query=query,
                         domain=domain,
                         domains=domains,
                         recommendations=recommendations,
                         sort=sort)

@app.route('/mentor/<username>')
def mentor_public_profile(username):
    """Public mentor profile page."""
    mentor = User.query.filter_by(username=username, role='mentor').first_or_404()
    
    # Increment profile views
    mentor.profile_views += 1
    db.session.commit()
    
    # Get mentor services
    services = Service.query.filter_by(
        mentor_id=mentor.id,
        is_active=True
    ).order_by(Service.created_at.desc()).all()
    
    # Get reviews
    reviews = Review.query.filter_by(
        mentor_id=mentor.id,
        is_approved=True
    ).order_by(Review.created_at.desc()).limit(10).all()
    
    # Calculate average rating
    avg_rating = 0
    if reviews:
        avg_rating = sum(r.rating for r in reviews) / len(reviews)
    
    # Get available dates
    available_dates = get_available_dates(mentor.id)
    
    # Get booking stats
    total_sessions = Booking.query.filter_by(
        mentor_id=mentor.id,
        status='completed'
    ).count()
    
    return render_template('mentor_public_profile.html',
                         mentor=mentor,
                         services=services,
                         reviews=reviews,
                         avg_rating=avg_rating,
                         available_dates=available_dates,
                         total_sessions=total_sessions)

@app.route('/service/<int:service_id>')
@app.route('/service/<slug>')
def service_detail(service_id=None, slug=None):
    """Service detail page."""
    if service_id:
        service = Service.query.get_or_404(service_id)
    elif slug:
        service = Service.query.filter_by(slug=slug, is_active=True).first_or_404()
    else:
        abort(404)
    
    mentor = User.query.get_or_404(service.mentor_id)
    
    # Check if user has access to digital product
    has_access = False
    if current_user.is_authenticated:
        access = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            service_id=service.id,
            is_active=True
        ).first()
        has_access = access is not None
    
    # Get reviews for this service
    reviews = Review.query.filter_by(
        service_id=service.id,
        is_approved=True
    ).order_by(Review.created_at.desc()).limit(10).all()
    
    # Calculate average rating
    avg_rating = 0
    if reviews:
        avg_rating = sum(r.rating for r in reviews) / len(reviews)
    
    # Get available dates and slots
    available_dates = get_available_dates(mentor.id)
    today_date = datetime.now().strftime('%Y-%m-%d')
    available_slots = get_time_slots_for_date(mentor.id, today_date)
    
    # Get other services from same mentor
    other_services = Service.query.filter_by(
        mentor_id=mentor.id,
        is_active=True
    ).filter(Service.id != service.id).limit(3).all()
    
    return render_template('service_detail.html',
                         service=service,
                         mentor=mentor,
                         has_access=has_access,
                         reviews=reviews,
                         avg_rating=avg_rating,
                         available_dates=available_dates,
                         available_slots=available_slots,
                         today_date=today_date,
                         other_services=other_services)

@app.route('/api/time-slots/<int:mentor_id>', methods=['POST'])
@csrf.exempt
def api_time_slots(mentor_id):
    """API endpoint for getting available time slots."""
    try:
        data = request.get_json()
        date_str = data.get('date')
        
        if not date_str:
            return jsonify({'error': 'Date is required'}), 400
        
        slots = get_time_slots_for_date(mentor_id, date_str)
        
        return jsonify({
            'success': True,
            'slots': slots,
            'date': date_str
        })
    except Exception as e:
        logger.error(f"Error getting time slots: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/book/<int:service_id>', methods=['POST'])
@login_required
@verified_email_required
def book_service(service_id):
    """Book a service."""
    service = Service.query.get_or_404(service_id)
    mentor = User.query.get_or_404(service.mentor_id)
    
    # Validate user
    if current_user.role == 'mentor':
        flash('Mentors cannot book services.', 'danger')
        return redirect(url_for('service_detail', service_id=service_id))
    
    # Get form data
    slot_time = request.form.get('slot_time')
    booking_date = request.form.get('booking_date')
    notes = request.form.get('notes', '').strip()
    
    # Validate required fields for consultation services
    if service.service_type in ['consultation', 'both']:
        if not slot_time or not booking_date:
            flash('Please select both date and time for consultation.', 'danger')
            return redirect(url_for('service_detail', service_id=service_id))
        
        # Validate date format
        try:
            booking_date_obj = datetime.strptime(booking_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('service_detail', service_id=service_id))
        
        # Check if slot is available
        existing_booking = Booking.query.filter_by(
            mentor_id=mentor.id,
            slot_time=slot_time,
            booking_date=booking_date_obj
        ).first()
        
        if existing_booking:
            flash('This time slot is already booked. Please select another time.', 'danger')
            return redirect(url_for('service_detail', service_id=service_id))
    
    # Check for existing pending booking for same service
    existing_pending = Booking.query.filter_by(
        learner_id=current_user.id,
        service_id=service_id,
        status='pending'
    ).first()
    
    if existing_pending:
        flash('You already have a pending booking for this service.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Create booking
    booking = Booking(
        mentor_id=mentor.id,
        learner_id=current_user.id,
        service_id=service.id,
        service_name=service.name,
        slot_time=slot_time if service.service_type in ['consultation', 'both'] else None,
        booking_date=datetime.strptime(booking_date, '%Y-%m-%d') if booking_date else None,
        price=service.price,
        notes=notes[:500] if notes else None,
        status='pending'
    )
    
    db.session.add(booking)
    db.session.commit()
    
    # For digital products with immediate access
    if service.service_type in ['digital_product', 'both'] and not service.access_after_payment:
        access = DigitalProductAccess(
            user_id=current_user.id,
            service_id=service.id,
            expires_at=datetime.utcnow() + timedelta(days=365)
        )
        db.session.add(access)
        db.session.commit()
        
        send_digital_product_access_email(current_user, service)
        flash(f'Digital product "{service.name}" has been added to your account!', 'success')
        return redirect(url_for('my_digital_products'))
    
    flash(f'Booking created for {service.name}! Please complete payment.', 'success')
    return redirect(url_for('create_payment', booking_id=booking.id))

@app.route('/payment/<int:booking_id>')
@login_required
@verified_email_required
def create_payment(booking_id):
    """Create payment for a booking."""
    booking = Booking.query.get_or_404(booking_id)
    
    # Validate user
    if booking.learner_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if already paid
    if booking.payment_status == 'success':
        flash('Payment already completed.', 'info')
        return redirect(url_for('dashboard'))
    
    # Create Razorpay order
    if razorpay_client:
        try:
            order_data = {
                'amount': booking.price * 100,  # Convert to paise
                'currency': 'INR',
                'receipt': f'booking_{booking.id}',
                'payment_capture': 1,
                'notes': {
                    'booking_id': booking.id,
                    'user_id': current_user.id,
                    'service_name': booking.service_name
                }
            }
            
            order = razorpay_client.order.create(order_data)
            booking.razorpay_order_id = order['id']
            db.session.commit()
            
            return render_template('payment.html',
                                 booking=booking,
                                 order=order,
                                 key_id=app.config['RAZORPAY_KEY_ID'],
                                 user=current_user)
            
        except Exception as e:
            logger.error(f"Razorpay error: {e}")
            flash('Error creating payment. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        # Payment gateway not configured
        flash('Payment gateway not configured. Please contact support.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/payment/success', methods=['POST'])
@login_required
@csrf.exempt
def payment_success():
    """Handle successful payment."""
    try:
        # Get payment details
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        razorpay_signature = request.form.get('razorpay_signature')
        
        if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
            flash('Invalid payment parameters.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Find booking
        booking = Booking.query.filter_by(razorpay_order_id=razorpay_order_id).first_or_404()
        
        # Verify user
        if booking.learner_id != current_user.id:
            flash('Unauthorized payment.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Verify payment hasn't been processed
        if booking.payment_status == 'success':
            flash('Payment already processed.', 'info')
            return redirect(url_for('dashboard'))
        
        # Verify signature
        params_dict = {
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_order_id': razorpay_order_id,
            'razorpay_signature': razorpay_signature
        }
        
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # Fetch payment details
        payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
        
        # Validate payment
        expected_amount = booking.price * 100
        if payment_details['amount'] != expected_amount:
            raise ValueError('Payment amount mismatch')
        
        if payment_details['currency'] != 'INR':
            raise ValueError('Invalid currency')
        
        if payment_details['status'] != 'captured':
            raise ValueError('Payment not captured')
        
        # Update booking
        booking.razorpay_payment_id = razorpay_payment_id
        booking.razorpay_signature = razorpay_signature
        booking.payment_status = 'success'
        booking.status = 'confirmed'
        
        # Generate meeting link for consultation services
        if booking.service:
            service = Service.query.get(booking.service_id)
            if service and service.service_type in ['consultation', 'both']:
                booking.meeting_link = f"https://meet.jit.si/ClearQ-{secrets.token_urlsafe(12)}"
                booking.meeting_platform = 'jitsi'
        
        # Create payment record
        payment = Payment(
            user_id=current_user.id,
            booking_id=booking.id,
            service_id=booking.service_id,
            amount=payment_details['amount'],
            currency=payment_details['currency'],
            razorpay_order_id=razorpay_order_id,
            razorpay_payment_id=razorpay_payment_id,
            razorpay_signature=razorpay_signature,
            status='success',
            payment_method=payment_details.get('method', 'card'),
            captured=True
        )
        db.session.add(payment)
        
        # Grant digital product access if applicable
        if booking.service:
            service = Service.query.get(booking.service_id)
            if service and service.service_type in ['digital_product', 'both'] and service.access_after_payment:
                access = DigitalProductAccess(
                    user_id=current_user.id,
                    service_id=service.id,
                    payment_id=payment.id,
                    expires_at=datetime.utcnow() + timedelta(days=365)
                )
                db.session.add(access)
        
        db.session.commit()
        
        # Send confirmation email
        send_booking_confirmation_email(booking, current_user)
        
        flash('Payment successful! Your booking has been confirmed.', 'success')
        return redirect(url_for('dashboard'))
        
    except razorpay.errors.SignatureVerificationError:
        flash('Payment verification failed. Please contact support.', 'danger')
    except ValueError as e:
        flash(f'Payment validation error: {str(e)}', 'danger')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Payment processing error: {e}")
        flash('Error processing payment. Please contact support.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/payment/failed')
@login_required
def payment_failed():
    """Handle failed payment."""
    order_id = request.args.get('order_id')
    
    if order_id:
        booking = Booking.query.filter_by(razorpay_order_id=order_id).first()
        if booking and booking.learner_id == current_user.id:
            booking.payment_status = 'failed'
            booking.status = 'cancelled'
            db.session.commit()
    
    flash('Payment failed. Please try again.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    """User registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        role = request.form.get('role', 'learner')
        
        # Common fields
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        # Validate username
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores.')
        
        # Validate email
        if not email or '@' not in email:
            errors.append('Valid email is required.')
        
        # Validate password
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters long.')
        elif password != confirm_password:
            errors.append('Passwords do not match.')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', role=role)
        
        # Create user based on role
        if role == 'learner':
            user = User(
                username=username,
                email=email,
                role='learner'
            )
            user.set_password(password)
            
        elif role == 'mentor':
            # Additional mentor fields
            full_name = request.form.get('full_name', '').strip()
            phone = request.form.get('phone', '').strip()
            domain = request.form.get('domain', '').strip()
            company = request.form.get('company', '').strip()
            experience = request.form.get('experience', '').strip()
            bio = request.form.get('bio', '').strip()[:500]
            
            user = User(
                username=username,
                email=email,
                role='mentor',
                full_name=full_name,
                phone=phone,
                domain=domain,
                company=company,
                experience=experience,
                bio=bio,
                is_verified=False  # Needs admin approval
            )
            user.set_password(password)
        
        else:
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('register'))
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(user):
                flash('Registration successful! Please check your email to verify your account.', 'success')
            else:
                flash('Registration successful! Please log in to resend verification email.', 'warning')
            
            # Auto-login for learners
            if role == 'learner':
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('login'))
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated.', 'danger')
            elif not user.is_email_verified and user.role != 'admin':
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('resend_verification'))
            else:
                login_user(user, remember=remember)
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                flash('Logged in successfully!', 'success')
                
                # Redirect to intended page or dashboard
                next_page = request.args.get('next')
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/verify-email/<token>')
def verify_email(token):
    """Verify email address."""
    try:
        email = serializer.loads(token, salt='email-verify', max_age=86400)  # 24 hours
        user = User.query.filter_by(email=email).first_or_404()
        
        if user.is_email_verified:
            flash('Email is already verified.', 'info')
        else:
            user.is_email_verified = True
            user.email_verified_at = datetime.utcnow()
            db.session.commit()
            flash('Email verified successfully!', 'success')
        
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login'))
            
    except SignatureExpired:
        flash('Verification link has expired.', 'danger')
    except BadSignature:
        flash('Invalid verification link.', 'danger')
    except Exception as e:
        logger.error(f"Email verification error: {e}")
        flash('Verification failed. Please try again.', 'danger')
    
    return redirect(url_for('index'))

@app.route('/resend-verification')
@login_required
def resend_verification():
    """Resend verification email."""
    if current_user.is_email_verified:
        flash('Email is already verified.', 'info')
        return redirect(url_for('dashboard'))
    
    if send_verification_email(current_user):
        flash('Verification email sent! Please check your inbox.', 'success')
    else:
        flash('Failed to send verification email. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Request password reset."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            if send_password_reset_email(user):
                flash('Password reset instructions have been sent to your email.', 'success')
            else:
                flash('Failed to send reset email. Please try again.', 'danger')
        else:
            flash('No account found with that email address.', 'danger')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour
        user = User.query.filter_by(email=email).first_or_404()
        
        if request.method == 'POST':
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not password or len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
            elif password != confirm_password:
                flash('Passwords do not match.', 'danger')
            else:
                user.set_password(password)
                db.session.commit()
                flash('Your password has been reset successfully! Please log in.', 'success')
                return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)
        
    except SignatureExpired:
        flash('Password reset link has expired.', 'danger')
    except BadSignature:
        flash('Invalid password reset link.', 'danger')
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        flash('Password reset failed. Please try again.', 'danger')
    
    return redirect(url_for('forgot_password'))

@app.route('/dashboard')
@login_required
@verified_email_required
def dashboard():
    """User dashboard."""
    if current_user.role == 'admin':
        return admin_dashboard()
    elif current_user.role == 'mentor':
        return mentor_dashboard()
    else:
        return learner_dashboard()

def admin_dashboard():
    """Admin dashboard."""
    # Stats
    stats = {
        'total_users': User.query.count(),
        'total_mentors': User.query.filter_by(role='mentor').count(),
        'verified_mentors': User.query.filter_by(role='mentor', is_verified=True).count(),
        'total_learners': User.query.filter_by(role='learner').count(),
        'pending_mentors': User.query.filter_by(role='mentor', is_verified=False).count(),
        'total_bookings': Booking.query.count(),
        'total_revenue': db.session.query(db.func.sum(Payment.amount)).filter_by(status='success').scalar() or 0,
        'active_enrollments': Enrollment.query.filter_by(status='active').count()
    }
    
    # Recent bookings
    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(10).all()
    
    # Recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_bookings=recent_bookings,
                         recent_users=recent_users)

def mentor_dashboard():
    """Mentor dashboard."""
    # Stats
    stats = {
        'total_bookings': Booking.query.filter_by(mentor_id=current_user.id).count(),
        'pending_bookings': Booking.query.filter_by(mentor_id=current_user.id, status='pending').count(),
        'confirmed_bookings': Booking.query.filter_by(mentor_id=current_user.id, status='confirmed').count(),
        'completed_sessions': Booking.query.filter_by(mentor_id=current_user.id, is_session_completed=True).count(),
        'total_earnings': db.session.query(db.func.sum(Payment.amount)).join(Booking).filter(
            Booking.mentor_id == current_user.id,
            Payment.status == 'success'
        ).scalar() or 0,
        'total_services': Service.query.filter_by(mentor_id=current_user.id, is_active=True).count()
    }
    
    # Upcoming bookings
    upcoming_bookings = Booking.query.filter(
        Booking.mentor_id == current_user.id,
        Booking.status == 'confirmed',
        Booking.booking_date >= datetime.utcnow()
    ).order_by(Booking.booking_date.asc()).limit(10).all()
    
    # Recent reviews
    recent_reviews = Review.query.filter_by(
        mentor_id=current_user.id,
        is_approved=True
    ).order_by(Review.created_at.desc()).limit(5).all()
    
    return render_template('mentor/dashboard.html',
                         stats=stats,
                         upcoming_bookings=upcoming_bookings,
                         recent_reviews=recent_reviews)

def learner_dashboard():
    """Learner dashboard."""
    # Stats
    stats = {
        'total_bookings': Booking.query.filter_by(learner_id=current_user.id).count(),
        'upcoming_bookings': Booking.query.filter(
            Booking.learner_id == current_user.id,
            Booking.status == 'confirmed',
            Booking.booking_date >= datetime.utcnow()
        ).count(),
        'completed_sessions': Booking.query.filter_by(
            learner_id=current_user.id,
            is_session_completed=True
        ).count(),
        'digital_products': DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).count(),
        'total_spent': db.session.query(db.func.sum(Payment.amount)).join(Booking).filter(
            Booking.learner_id == current_user.id,
            Payment.status == 'success'
        ).scalar() or 0
    }
    
    # Upcoming bookings
    upcoming_bookings = Booking.query.filter(
        Booking.learner_id == current_user.id,
        Booking.status == 'confirmed',
        Booking.booking_date >= datetime.utcnow()
    ).order_by(Booking.booking_date.asc()).limit(5).all()
    
    # Recent digital products
    recent_digital_products = DigitalProductAccess.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).order_by(DigitalProductAccess.access_granted_at.desc()).limit(5).all()
    
    # Recommended mentors
    recommended_mentors = []
    if current_user.domain:
        recommended_mentors = User.query.filter_by(
            role='mentor',
            is_verified=True,
            domain=current_user.domain
        ).order_by(User.rating.desc()).limit(3).all()
    
    return render_template('learner/dashboard.html',
                         stats=stats,
                         upcoming_bookings=upcoming_bookings,
                         recent_digital_products=recent_digital_products,
                         recommended_mentors=recommended_mentors)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile."""
    if request.method == 'POST':
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                image_path = save_profile_image(file, current_user.id)
                if image_path:
                    current_user.profile_image = image_path
        
        # Update profile based on role
        if current_user.role == 'learner':
            current_user.full_name = request.form.get('full_name', '').strip()
            current_user.phone = request.form.get('phone', '').strip()
            current_user.domain = request.form.get('domain', '').strip()
            
        elif current_user.role == 'mentor':
            current_user.full_name = request.form.get('full_name', '').strip()
            current_user.phone = request.form.get('phone', '').strip()
            current_user.job_title = request.form.get('job_title', '').strip()
            current_user.company = request.form.get('company', '').strip()
            current_user.previous_company = request.form.get('previous_company', '').strip()
            current_user.domain = request.form.get('domain', '').strip()
            current_user.experience = request.form.get('experience', '').strip()
            current_user.skills = request.form.get('skills', '').strip()
            current_user.bio = sanitize_html(request.form.get('bio', ''))
            current_user.price = int(request.form.get('price', 0))
            current_user.availability = request.form.get('availability', '').strip()
            
            # Social links
            current_user.linkedin_url = request.form.get('linkedin_url', '').strip()
            current_user.twitter_url = request.form.get('twitter_url', '').strip()
            current_user.github_url = request.form.get('github_url', '').strip()
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/my-bookings')
@login_required
def my_bookings():
    """User's bookings."""
    if current_user.role == 'mentor':
        bookings = Booking.query.filter_by(mentor_id=current_user.id).order_by(Booking.created_at.desc()).all()
    else:
        bookings = Booking.query.filter_by(learner_id=current_user.id).order_by(Booking.created_at.desc()).all()
    
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/my-digital-products')
@login_required
def my_digital_products():
    """User's digital products."""
    accesses = DigitalProductAccess.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).order_by(DigitalProductAccess.access_granted_at.desc()).all()
    
    return render_template('my_digital_products.html', accesses=accesses)

@app.route('/download-digital-product/<int:access_id>')
@login_required
def download_digital_product(access_id):
    """Download digital product."""
    access = DigitalProductAccess.query.get_or_404(access_id)
    
    # Verify access
    if access.user_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    if not access.is_active:
        flash('Access has expired.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    if access.expires_at and access.expires_at < datetime.utcnow():
        access.is_active = False
        db.session.commit()
        flash('Access has expired.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    # Get service
    service = Service.query.get(access.service_id)
    if not service or not service.digital_product_file:
        flash('Product not found.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    # Update access stats
    access.downloads_count += 1
    access.last_download_at = datetime.utcnow()
    db.session.commit()
    
    # Serve file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'digital_products', 
                           os.path.basename(service.digital_product_file))
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash('File not found.', 'danger')
        return redirect(url_for('my_digital_products'))

# ============================================================================
# MENTOR MANAGEMENT ROUTES
# ============================================================================

@app.route('/mentor/services', methods=['GET', 'POST'])
@login_required
@mentor_required
def mentor_services():
    """Manage mentor services."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            # Create new service
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            detailed_description = sanitize_html(request.form.get('detailed_description', ''))
            price = int(request.form.get('price', 0))
            duration = request.form.get('duration', '').strip()
            service_type = request.form.get('service_type', 'consultation')
            category = request.form.get('category', '').strip()
            tags = request.form.get('tags', '').strip()
            
            # Digital product fields
            digital_product_name = request.form.get('digital_product_name', '').strip()
            digital_product_description = request.form.get('digital_product_description', '').strip()
            access_after_payment = 'access_after_payment' in request.form
            
            # Handle file upload
            digital_product_file = None
            if 'digital_product_file' in request.files:
                file = request.files['digital_product_file']
                if file and file.filename != '':
                    digital_product_file = save_digital_product(file, current_user.id, name)
            
            # Create service
            service = Service(
                mentor_id=current_user.id,
                name=name,
                slug=generate_slug(name),
                description=description,
                detailed_description=detailed_description,
                price=price,
                duration=duration,
                service_type=service_type,
                digital_product_name=digital_product_name,
                digital_product_description=digital_product_description,
                digital_product_file=digital_product_file,
                access_after_payment=access_after_payment,
                category=category,
                tags=tags
            )
            
            db.session.add(service)
            db.session.commit()
            flash('Service created successfully!', 'success')
            
        elif action == 'update':
            # Update existing service
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first_or_404()
            
            service.name = request.form.get('name', '').strip()
            service.slug = generate_slug(service.name)
            service.description = request.form.get('description', '').strip()
            service.detailed_description = sanitize_html(request.form.get('detailed_description', ''))
            service.price = int(request.form.get('price', 0))
            service.duration = request.form.get('duration', '').strip()
            service.service_type = request.form.get('service_type', 'consultation')
            service.category = request.form.get('category', '').strip()
            service.tags = request.form.get('tags', '').strip()
            
            # Digital product fields
            service.digital_product_name = request.form.get('digital_product_name', '').strip()
            service.digital_product_description = request.form.get('digital_product_description', '').strip()
            service.access_after_payment = 'access_after_payment' in request.form
            
            # Handle file upload
            if 'digital_product_file' in request.files:
                file = request.files['digital_product_file']
                if file and file.filename != '':
                    service.digital_product_file = save_digital_product(file, current_user.id, service.name)
            
            db.session.commit()
            flash('Service updated successfully!', 'success')
            
        elif action == 'delete':
            # Soft delete service
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first_or_404()
            service.is_active = False
            db.session.commit()
            flash('Service deleted successfully!', 'success')
            
        elif action == 'toggle_featured':
            # Toggle featured status
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first_or_404()
            service.is_featured = not service.is_featured
            db.session.commit()
            flash('Service featured status updated!', 'success')
        
        return redirect(url_for('mentor_services'))
    
    # Get mentor services
    services = Service.query.filter_by(mentor_id=current_user.id).order_by(Service.created_at.desc()).all()
    
    return render_template('mentor/services.html', services=services)

@app.route('/mentor/calendar')
@login_required
@mentor_required
def mentor_calendar():
    """Mentor calendar view."""
    # Get bookings for the next 30 days
    start_date = datetime.utcnow()
    end_date = start_date + timedelta(days=30)
    
    bookings = Booking.query.filter(
        Booking.mentor_id == current_user.id,
        Booking.booking_date.between(start_date, end_date),
        Booking.status.in_(['confirmed', 'completed'])
    ).order_by(Booking.booking_date).all()
    
    # Format for calendar
    calendar_events = []
    for booking in bookings:
        calendar_events.append({
            'title': f"{booking.service_name} - {booking.learner.username}",
            'start': booking.booking_date.isoformat() if booking.booking_date else None,
            'end': (booking.booking_date + timedelta(hours=1)).isoformat() if booking.booking_date else None,
            'color': '#667eea' if booking.status == 'confirmed' else '#48bb78',
            'url': url_for('view_booking', booking_id=booking.id)
        })
    
    return render_template('mentor/calendar.html', events=calendar_events)

@app.route('/mentor/earnings')
@login_required
@mentor_required
def mentor_earnings():
    """Mentor earnings dashboard."""
    # Calculate earnings
    payments = Payment.query.join(Booking).filter(
        Booking.mentor_id == current_user.id,
        Payment.status == 'success'
    ).order_by(Payment.created_at.desc()).all()
    
    # Calculate totals
    total_earnings = sum(p.amount for p in payments)
    this_month_earnings = sum(
        p.amount for p in payments 
        if p.created_at.month == datetime.utcnow().month
    )
    
    # Get earnings by month for chart
    monthly_earnings = {}
    for payment in payments:
        month_key = payment.created_at.strftime('%Y-%m')
        monthly_earnings[month_key] = monthly_earnings.get(month_key, 0) + payment.amount
    
    return render_template('mentor/earnings.html',
                         payments=payments,
                         total_earnings=total_earnings,
                         this_month_earnings=this_month_earnings,
                         monthly_earnings=monthly_earnings)

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin/mentors')
@login_required
@admin_required
def admin_mentors():
    """Admin mentor management."""
    status = request.args.get('status', 'all')
    
    query = User.query.filter_by(role='mentor')
    
    if status == 'pending':
        query = query.filter_by(is_verified=False)
    elif status == 'verified':
        query = query.filter_by(is_verified=True)
    elif status == 'active':
        query = query.filter_by(is_active=True)
    elif status == 'inactive':
        query = query.filter_by(is_active=False)
    
    mentors = query.order_by(User.created_at.desc()).all()
    
    return render_template('admin/mentors.html', mentors=mentors, status=status)

@app.route('/admin/verify-mentor/<int:mentor_id>')
@login_required
@admin_required
def admin_verify_mentor(mentor_id):
    """Verify a mentor."""
    mentor = User.query.get_or_404(mentor_id)
    
    if mentor.role != 'mentor':
        flash('User is not a mentor.', 'danger')
        return redirect(url_for('admin_mentors'))
    
    mentor.is_verified = True
    db.session.commit()
    
    flash(f'Mentor {mentor.username} has been verified!', 'success')
    return redirect(url_for('admin_mentors'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Admin user management."""
    role = request.args.get('role', 'all')
    
    query = User.query
    
    if role != 'all':
        query = query.filter_by(role=role)
    
    users = query.order_by(User.created_at.desc()).all()
    
    return render_template('admin/users.html', users=users, role=role)

@app.route('/admin/bookings')
@login_required
@admin_required
def admin_bookings():
    """Admin booking management."""
    status = request.args.get('status', 'all')
    
    query = Booking.query
    
    if status != 'all':
        query = query.filter_by(status=status)
    
    bookings = query.order_by(Booking.created_at.desc()).all()
    
    return render_template('admin/bookings.html', bookings=bookings, status=status)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/health')
def api_health():
    """Health check endpoint."""
    try:
        # Check database
        db.session.execute('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'services': {
                'razorpay': razorpay_client is not None,
                'email': bool(app.config['MAIL_USERNAME'])
            }
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@app.route('/api/stats')
@login_required
@admin_required
def api_stats():
    """API endpoint for statistics."""
    try:
        # Calculate statistics
        stats = {
            'total_users': User.query.count(),
            'new_users_today': User.query.filter(
                User.created_at >= datetime.utcnow().date()
            ).count(),
            'total_bookings': Booking.query.count(),
            'active_bookings': Booking.query.filter_by(status='confirmed').count(),
            'total_revenue': db.session.query(db.func.sum(Payment.amount)).filter_by(status='success').scalar() or 0,
            'today_revenue': db.session.query(db.func.sum(Payment.amount)).filter(
                Payment.status == 'success',
                Payment.created_at >= datetime.utcnow().date()
            ).scalar() or 0
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# UTILITY ROUTES
# ============================================================================

@app.route('/terms')
def terms():
    """Terms of service."""
    return render_template('legal/terms.html')

@app.route('/privacy')
def privacy():
    """Privacy policy."""
    return render_template('legal/privacy.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        
        if not all([name, email, message]):
            flash('Please fill in all fields.', 'danger')
            return render_template('contact.html')
        
        # Send email (in production)
        logger.info(f"Contact form submission: {name} <{email}>: {message}")
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

# ============================================================================
# INITIALIZATION
# ============================================================================

def init_database():
    """Initialize database with default data."""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            
            # Create admin user if not exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
            if not User.query.filter_by(email=admin_email).first():
                admin = User(
                    username='admin',
                    email=admin_email,
                    role='admin',
                    is_email_verified=True,
                    is_verified=True,
                    is_active=True
                )
                admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
                db.session.add(admin)
                db.session.commit()
                logger.info("Admin user created")
            
            # Create sample mentors for development
            if app.debug and User.query.filter_by(role='mentor').count() < 3:
                create_sample_mentors()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

def create_sample_mentors():
    """Create sample mentor data for development."""
    sample_mentors = [
        {
            'username': 'john_data',
            'email': 'john.data@example.com',
            'full_name': 'John Data',
            'role': 'mentor',
            'domain': 'Data Science',
            'company': 'Google',
            'job_title': 'Senior Data Scientist',
            'experience': '5 years',
            'skills': 'Python, Machine Learning, SQL, TensorFlow',
            'bio': 'I help aspiring data scientists land jobs at top tech companies.',
            'price': 1500,
            'rating': 4.9,
            'is_verified': True,
            'is_email_verified': True
        },
        {
            'username': 'jane_product',
            'email': 'jane.product@example.com',
            'full_name': 'Jane Product',
            'role': 'mentor',
            'domain': 'Product Management',
            'company': 'Microsoft',
            'job_title': 'Senior Product Manager',
            'experience': '7 years',
            'skills': 'Product Strategy, Agile, User Research',
            'bio': 'I help engineers transition to product management roles.',
            'price': 2000,
            'rating': 4.8,
            'is_verified': True,
            'is_email_verified': True
        }
    ]
    
    for data in sample_mentors:
        if not User.query.filter_by(email=data['email']).first():
            mentor = User(**data)
            mentor.set_password('test123')
            db.session.add(mentor)
    
    db.session.commit()
    logger.info("Sample mentors created")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        try:
            print("🔧 Initializing database...")
            db.create_all()
            
            # Create admin user if not exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
            if not User.query.filter_by(email=admin_email).first():
                admin = User(
                    username='admin',
                    email=admin_email,
                    role='admin',
                    is_email_verified=True,
                    is_verified=True,
                    is_active=True
                )
                admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created")
            
            print("✅ Database setup complete!")
        except Exception as e:
            print(f"⚠️ Note during initialization: {e}")
    
    # Run the app
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    app.run(host=host, port=port, debug=debug, threaded=True)

