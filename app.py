import os
import json
import re
import uuid
import secrets
import logging
import traceback
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
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
import razorpay.errors
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import bleach
from PIL import Image
import html
from urllib.parse import urlparse, urljoin
# Add these imports if not already present
from flask import url_for
from itsdangerous import URLSafeTimedSerializer
import datetime


# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO if os.environ.get('FLASK_ENV') != 'development' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('clearq.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Set base directory
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / 'templates'
STATIC_DIR = BASE_DIR / 'static'
UPLOAD_DIR = BASE_DIR / 'static' / 'uploads'

# Ensure directories exist
TEMPLATE_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
(UPLOAD_DIR / 'profile_images').mkdir(exist_ok=True)
(UPLOAD_DIR / 'digital_products').mkdir(exist_ok=True)
(UPLOAD_DIR / 'resources').mkdir(exist_ok=True)

# Create Flask app with explicit paths
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR)
)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

app.config.update(
    # Security
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', secrets.token_hex(32)),
    WTF_CSRF_TIME_LIMIT=3600,
    
    # Database
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{BASE_DIR}/clearq.db').replace(
        'postgres://', 'postgresql://', 1
    ) if 'postgres://' in os.environ.get('DATABASE_URL', '') else os.environ.get(
        'DATABASE_URL', f'sqlite:///{BASE_DIR}/clearq.db'
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20,
    },
    
    # File Uploads
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50MB
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    ALLOWED_EXTENSIONS={
        'png', 'jpg', 'jpeg', 'gif', 'webp',  # Images
        'pdf', 'doc', 'docx', 'txt', 'md',    # Documents
        'zip', 'rar', '7z',                   # Archives
        'mp4', 'mov', 'avi', 'mkv', 'webm',   # Videos
        'mp3', 'wav', 'm4a', 'ogg', 'flac'    # Audio
    },
    
    # Email
    MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
    MAIL_USE_SSL=os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true',
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME', ''),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', ''),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@clearq.in'),
    
    # Payment
    RAZORPAY_KEY_ID=os.environ.get('RAZORPAY_KEY_ID', ''),
    RAZORPAY_KEY_SECRET=os.environ.get('RAZORPAY_KEY_SECRET', ''),
    
    # Session
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    
    # Application
    FLASK_ENV=os.environ.get('FLASK_ENV', 'development'),
    FLASK_DEBUG=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = "strong"

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
    on_breach=lambda _: None
)

# Serializer for tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Razorpay Client
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
else:
    logger.warning("Razorpay credentials not found. Payment functionality will be limited.")

# ============================================================================
# DATABASE MODELS (Simplified & Optimized)
# ============================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='learner', nullable=False, index=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)  # For mentors
    
    # Profile
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    profile_image = db.Column(db.String(500))
    bio = db.Column(db.Text)
    
    # Mentor specific
    job_title = db.Column(db.String(100))
    company = db.Column(db.String(100))
    domain = db.Column(db.String(100))
    experience = db.Column(db.String(50))
    skills = db.Column(db.Text)
    price = db.Column(db.Integer, default=0)
    
    # Stats
    rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    total_sessions = db.Column(db.Integer, default=0)
    
    # Social links
    linkedin_url = db.Column(db.String(200))
    twitter_url = db.Column(db.String(200))
    github_url = db.Column(db.String(200))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    email_verified_at = db.Column(db.DateTime)
    
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
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'full_name': self.full_name,
            'profile_image': self.profile_image,
            'rating': self.rating,
            'domain': self.domain,
            'company': self.company,
            'experience': self.experience
        }


class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    price = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.String(50))
    
    # Service type
    service_type = db.Column(db.String(50), default='consultation', nullable=False)
    
    # Digital product
    digital_product_file = db.Column(db.String(500))
    digital_product_link = db.Column(db.String(500))
    
    # Status
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_featured = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    mentor = db.relationship('User', backref=db.backref('services', lazy=True))
    
    __table_args__ = (
        db.Index('idx_service_mentor_active', 'mentor_id', 'is_active'),
    )


class Booking(db.Model):
    __tablename__ = 'bookings'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    
    # Booking details
    service_name = db.Column(db.String(100), nullable=False)
    slot_time = db.Column(db.String(50))
    booking_date = db.Column(db.DateTime, index=True)
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    price = db.Column(db.Integer, nullable=False)
    
    # Meeting details
    meeting_link = db.Column(db.String(500))
    
    # Payment
    payment_status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    razorpay_order_id = db.Column(db.String(100), index=True)
    razorpay_payment_id = db.Column(db.String(100))
    razorpay_signature = db.Column(db.String(255))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    mentor = db.relationship('User', foreign_keys=[mentor_id], backref='mentor_bookings')
    learner = db.relationship('User', foreign_keys=[learner_id], backref='learner_bookings')
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_booking_mentor_date', 'mentor_id', 'booking_date'),
        db.Index('idx_booking_learner_status', 'learner_id', 'status'),
    )


class DigitalProductAccess(db.Model):
    __tablename__ = 'digital_product_access'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    payment_id = db.Column(db.Integer)
    
    # Access details
    access_granted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    
    # Relationships
    user = db.relationship('User', backref='digital_accesses')
    service = db.relationship('Service', backref='accesses')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'service_id', name='uq_user_service_access'),
    )


class Review(db.Model):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'))
    
    # Review content
    rating = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200))
    comment = db.Column(db.Text)
    
    # Status
    is_approved = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    mentor = db.relationship('User', foreign_keys=[mentor_id], backref='mentor_reviews')
    learner = db.relationship('User', foreign_keys=[learner_id], backref='learner_reviews')
    booking = db.relationship('Booking')
    
    __table_args__ = (
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
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    read_at = db.Column(db.DateTime)
    
    # Relationship
    user = db.relationship('User', backref='notifications')
    
    __table_args__ = (
        db.Index('idx_notification_user_read', 'user_id', 'is_read'),
    )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load user by ID for Flask-Login."""
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']


def validate_file(file) -> Tuple[bool, str]:
    """Validate uploaded file for security."""
    if not file or file.filename == '':
        return False, 'No file selected'
    
    if not allowed_file(file.filename):
        allowed = ', '.join(app.config['ALLOWED_EXTENSIONS'])
        return False, f'File type not allowed. Allowed types: {allowed}'
    
    # Check file size
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > app.config['MAX_CONTENT_LENGTH']:
            max_size = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
            return False, f'File too large. Maximum size is {max_size}MB'
    except Exception:
        return False, 'Error reading file size'
    
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
    
    upload_path = UPLOAD_DIR / 'profile_images'
    upload_path.mkdir(exist_ok=True)
    
    filepath = upload_path / filename
    try:
        file.save(str(filepath))
        
        # Create thumbnail
        try:
            img = Image.open(filepath)
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            img.thumbnail((300, 300), Image.Resampling.LANCZOS)
            thumbnail_path = upload_path / f"thumb_{filename}"
            img.save(thumbnail_path, 'JPEG', quality=85)
        except Exception as img_error:
            logger.error(f"Error creating thumbnail: {img_error}")
        
        return f'uploads/profile_images/{filename}'
    except Exception as e:
        logger.error(f"Error saving profile image: {e}")
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
    
    return slug[:100]


def is_safe_url(target: str) -> bool:
    """Check if URL is safe for redirection."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength."""
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


def create_notification(user_id: int, title: str, message: str, 
                       notification_type: str = 'info', 
                       action_url: str = None) -> None:
    """Create a new notification for user."""
    try:
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            action_url=action_url
        )
        db.session.add(notification)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error creating notification: {e}")
        db.session.rollback()


# ============================================================================
# EMAIL FUNCTIONS
# ============================================================================

def send_email(to: str, subject: str, body: str, html_body: Optional[str] = None) -> bool:
    """Send email using configured mail server."""
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        logger.info(f"Email not sent (no credentials): To={to}, Subject={subject}")
        return False
    
    try:
        logger.info(f"Attempting to send email to {to} via {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # CRITICAL: Add timeout and handle connection properly
        timeout = 10
        
        logger.info(f"Connecting to SMTP server...")
        
        if app.config['MAIL_USE_SSL']:
            server = smtplib.SMTP_SSL(
                app.config['MAIL_SERVER'], 
                app.config['MAIL_PORT'],
                timeout=timeout
            )
            logger.info(f"Connected via SSL on port {app.config['MAIL_PORT']}")
        else:
            server = smtplib.SMTP(
                app.config['MAIL_SERVER'], 
                app.config['MAIL_PORT'],
                timeout=timeout
            )
            logger.info(f"Connected via SMTP on port {app.config['MAIL_PORT']}")
        
        if app.config['MAIL_USE_TLS'] and not app.config['MAIL_USE_SSL']:
            logger.info("Starting TLS...")
            server.starttls()
            logger.info("TLS started")
        
        logger.info("Logging in to SMTP server...")
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        logger.info("SMTP login successful")
        
        logger.info("Sending email message...")
        server.send_message(msg)
        server.quit()
        
        logger.info(f"✓ Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"✗ FAILED to send email to {to}: {str(e)}")
        logger.error(f"SMTP Config: Server={app.config.get('MAIL_SERVER')}, "
                    f"Port={app.config.get('MAIL_PORT')}, "
                    f"SSL={app.config.get('MAIL_USE_SSL')}, "
                    f"TLS={app.config.get('MAIL_USE_TLS')}")
        return False
def send_verification_email(user) -> bool:
    """Send email verification link."""
    try:
        token = serializer.dumps(user.email, salt='email-verify')
        verification_url = url_for('verify_email', token=token, _external=True)
        
        subject = 'Verify Your Email - ClearQ'
        
        body = f"""Welcome to ClearQ!

Please verify your email address by clicking the link below:
{verification_url}

This link will expire in 24 hours.

Best regards,
The ClearQ Team
"""
        
        return send_email(user.email, subject, body)
        
    except Exception as e:
        logger.error(f"Error in send_verification_email: {e}")
        return False
def send_verification_email_thread(user):
    """Thread-safe email sending with proper context."""
    try:
        logger.info(f"Starting email thread for user {user.email}")
        
        # Create app context for the thread
        with app.app_context():
            logger.info(f"App context created for {user.email}")
            
            token = serializer.dumps(user.email, salt='email-verify')
            logger.info(f"Token generated for {user.email}")
            
            verification_url = url_for('verify_email', token=token, _external=True)
            logger.info(f"Verification URL: {verification_url}")
            
            subject = 'Verify Your Email - ClearQ'
            
            body = f"""Welcome to ClearQ!

Please verify your email address by clicking the link below:
{verification_url}

This link will expire in 24 hours.

Best regards,
The ClearQ Team
"""
            
            result = send_email(user.email, subject, body)
            
            if result:
                logger.info(f"✓ Email successfully sent to {user.email}")
            else:
                logger.error(f"✗ Email failed to send for {user.email}")
                
    except Exception as e:
        logger.error(f"✗ Thread crash for {user.email}: {str(e)}", exc_info=True)

# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def mentor_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'mentor':
            flash('Mentor access required.', 'danger')
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
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"500 Error: {error}")
    logger.error(traceback.format_exc())
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


@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum file size is 50MB.', 'danger')
    return redirect(request.referrer or url_for('index'))


@app.errorhandler(Exception)
def handle_exception(error):
    db.session.rollback()
    logger.error(f"Unhandled exception: {error}")
    logger.error(traceback.format_exc())
    
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': 'An internal server error occurred'
        }), 500
    
    return render_template('errors/500.html'), 500


# ============================================================================
# TEMPLATE FILTERS
# ============================================================================

@app.template_filter('datetime')
def format_datetime(value: datetime, fmt: str = '%Y-%m-%d %H:%M') -> str:
    if value is None:
        return ''
    return value.strftime(fmt)


@app.template_filter('date')
def format_date(value: datetime, fmt: str = '%Y-%m-%d') -> str:
    if value is None:
        return ''
    return value.strftime(fmt)


@app.template_filter('currency')
def format_currency(value: int) -> str:
    if value is None:
        return '₹0'
    return f'₹{value:,}'


@app.template_filter('truncate')
def truncate(text: str, length: int = 100, ellipsis: str = '...') -> str:
    if len(text) <= length:
        return text
    return text[:length].rsplit(' ', 1)[0] + ellipsis


# ============================================================================
# APPLICATION ROUTES
# ============================================================================

@app.before_request
def before_request():
    """Check database connection before each request."""
    try:
        # Test database connection - IMPORTANT: Use text() function
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        try:
            # Try to create tables if they don't exist
            db.create_all()
            logger.info("Database tables created on-demand")
        except Exception as create_error:
            logger.error(f"Failed to create tables: {create_error}")


@app.route('/')
def index():
    """Home page."""
    try:
        featured_mentors = User.query.filter_by(
            role='mentor',
            is_verified=True,
            is_active=True
        ).order_by(User.rating.desc()).limit(6).all()
    except Exception as e:
        logger.error(f"Error getting featured mentors: {e}")
        featured_mentors = []
    
    try:
        featured_services = Service.query.filter_by(
            is_active=True,
            is_featured=True
        ).order_by(Service.created_at.desc()).limit(6).all()
    except Exception as e:
        logger.error(f"Error getting featured services: {e}")
        featured_services = []
    
    return render_template('index.html',
                         featured_mentors=featured_mentors,
                         featured_services=featured_services)

@app.route('/mentorship-program')
def mentorship_program():
    """Mentorship program page."""
    try:
        featured_programs = Service.query.filter_by(
            is_active=True,
            is_featured=True
        ).order_by(Service.created_at.desc()).limit(6).all()
    except Exception as e:
        logger.error(f"Error getting featured programs: {e}")
        featured_programs = []
    
    return render_template('mentorship_program.html',
                         featured_programs=featured_programs)
@app.route('/enroll')
def enroll():
    """Enrollment page for mentorship program."""
    # Get active services
    try:
        services = Service.query.filter_by(is_active=True).limit(6).all()
    except Exception as e:
        logger.error(f"Error getting services: {e}")
        services = []
    
    return render_template('enroll.html', services=services)
    
@app.route('/database-setup')
def database_setup():
    """Manual database setup endpoint."""
    try:
        db.create_all()
        flash('Database tables created successfully!', 'success')
        
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
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'Admin@123'))
            db.session.add(admin)
            db.session.commit()
            flash('Admin user created!', 'success')
        
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Database setup error: {e}")
        flash(f'Database setup failed: {str(e)}', 'danger')
        return redirect(url_for('index'))


@app.route('/explore')
def explore():
    """Explore mentors page."""
    query = request.args.get('q', '')
    domain = request.args.get('domain', '')
    sort = request.args.get('sort', 'rating')
    
    # Base query for mentors
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
                User.skills.ilike(f'%{query}%')
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
    else:
        mentors_query = mentors_query.order_by(User.created_at.desc())
    
    # Get mentors with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 12
    mentors_paginated = mentors_query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique domains for filter dropdown
    try:
        domains = db.session.query(User.domain).filter(
            User.domain.isnot(None),
            User.role == 'mentor',
            User.is_verified == True
        ).distinct().all()
        domains = [d[0] for d in domains if d[0]]
    except Exception as e:
        logger.error(f"Error getting domains: {e}")
        domains = []
    
    return render_template('explore.html',
                         mentors=mentors_paginated,
                         query=query,
                         domain=domain,
                         domains=domains,
                         sort=sort)

@app.route('/mentor/<username>')
def mentor_public_profile(username):
    """Public mentor profile page."""
    mentor = User.query.filter_by(username=username, role='mentor').first_or_404()
    
    # Increment profile views
    try:
        mentor.profile_views = mentor.profile_views + 1 if mentor.profile_views else 1
        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating profile views: {e}")
        db.session.rollback()
    
    # Get mentor services
    try:
        services = Service.query.filter_by(
            mentor_id=mentor.id,
            is_active=True
        ).order_by(Service.created_at.desc()).all()
    except Exception as e:
        logger.error(f"Error getting mentor services: {e}")
        services = []
    
    # Get reviews
    try:
        reviews = Review.query.filter_by(
            mentor_id=mentor.id,
            is_approved=True
        ).order_by(Review.created_at.desc()).limit(10).all()
    except Exception as e:
        logger.error(f"Error getting reviews: {e}")
        reviews = []
    
    return render_template('mentor_profile.html',
                         mentor=mentor,
                         services=services,
                         reviews=reviews)


@app.route('/service/<int:service_id>')
def service_detail(service_id):
    """Service detail page."""
    service = Service.query.get_or_404(service_id)
    mentor = User.query.get_or_404(service.mentor_id)
    
    # Check access
    has_access = False
    if current_user.is_authenticated:
        try:
            access = DigitalProductAccess.query.filter_by(
                user_id=current_user.id,
                service_id=service.id,
                is_active=True
            ).first()
            has_access = access is not None
        except Exception as e:
            logger.error(f"Error checking digital product access: {e}")
    
    # Get reviews
    try:
        reviews = Review.query.filter_by(
            service_id=service.id,
            is_approved=True
        ).order_by(Review.created_at.desc()).limit(10).all()
    except Exception as e:
        logger.error(f"Error getting service reviews: {e}")
        reviews = []
    
    return render_template('service_detail.html',
                         service=service,
                         mentor=mentor,
                         has_access=has_access,
                         reviews=reviews)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    """User registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        role = request.form.get('role', 'learner')
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores.')
        
        if '@' not in email:
            errors.append('Valid email is required.')
        
        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            errors.append(password_error)
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
        
        # Create user
        user = User(
            username=username,
            email=email,
            role=role
        )
        
        if role == 'mentor':
            user.full_name = request.form.get('full_name', '').strip()
            user.domain = request.form.get('domain', '').strip()
            user.company = request.form.get('company', '').strip()
            user.experience = request.form.get('experience', '').strip()
            user.bio = request.form.get('bio', '').strip()[:500]
        
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # FIX: Use the thread wrapper instead of send_verification_email directly
            import threading
            email_thread = threading.Thread(
                target=send_verification_email_thread,  # Changed to thread wrapper
                args=(user,),
                daemon=True
            )
            email_thread.start()
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            
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
                
                next_page = request.args.get('next')
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token and send email
            token = serializer.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send reset email
            subject = 'Password Reset Request - ClearQ'
            body = f"""You requested a password reset.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
The ClearQ Team
"""
            send_email(user.email, subject, body)
        
        # Always show success (security measure)
        flash('If an account exists with that email, you will receive password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with valid token."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, 'danger')
            elif password != confirm_password:
                flash('Passwords do not match.', 'danger')
            else:
                user.set_password(password)
                db.session.commit()
                flash('Your password has been reset! Please log in.', 'success')
                return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))    
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
        user = User.query.filter_by(email=email).first()  # Changed from first_or_404()
        
        if not user:
            flash('Invalid verification link. User not found.', 'danger')
            return redirect(url_for('login'))
        
        if user.is_email_verified:
            flash('Email is already verified.', 'info')
        else:
            user.is_email_verified = True
            user.email_verified_at = datetime.utcnow()
            db.session.commit()
            flash('Email verified successfully!', 'success')
            
            create_notification(
                user_id=user.id,
                title='Email Verified',
                message='Your email has been successfully verified.',
                notification_type='success'
            )
        
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


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    try:
        # Import datetime if not already imported
        from datetime import datetime
        from sqlalchemy import func
        
        if current_user.role == 'admin':
            # Admin stats
            stats = {
                'total_users': User.query.count() or 0,
                'total_mentors': User.query.filter_by(role='mentor').count() or 0,
                'total_learners': User.query.filter_by(role='learner').count() or 0,
                'pending_mentors': User.query.filter_by(role='mentor', is_verified=False).count() or 0,
                'total_bookings': Booking.query.count() if hasattr(app, 'Booking') else 0,
            }
            upcoming_bookings = []
            recommended_mentors = []
            
        elif current_user.role == 'mentor':
            # Mentor stats - safely calculate earnings
            confirmed_bookings = Booking.query.filter_by(
                mentor_id=current_user.id, 
                status='confirmed'
            ).all() if hasattr(app, 'Booking') else []
            
            earnings = sum([b.price for b in confirmed_bookings if b and b.price]) or 0
            
            stats = {
                'total_bookings': Booking.query.filter_by(mentor_id=current_user.id).count() or 0,
                'pending_bookings': Booking.query.filter_by(mentor_id=current_user.id, status='pending').count() or 0,
                'confirmed_bookings': len(confirmed_bookings),
                'total_services': Service.query.filter_by(mentor_id=current_user.id, is_active=True).count() if hasattr(app, 'Service') else 0,
                'total_earnings': earnings,
                'total_sessions': len(confirmed_bookings),
            }
            
            # Get upcoming bookings for mentor
            upcoming_bookings = Booking.query.filter(
                Booking.mentor_id == current_user.id,
                Booking.status == 'confirmed',
                Booking.booking_date >= datetime.utcnow()
            ).order_by(Booking.booking_date).limit(5).all() if hasattr(app, 'Booking') else []
            
            recommended_mentors = []
            
        else:
            # Learner stats
            confirmed_bookings = Booking.query.filter_by(
                learner_id=current_user.id, 
                status='confirmed'
            ).all() if hasattr(app, 'Booking') else []
            
            total_spent = sum([b.price for b in confirmed_bookings if b and b.price]) or 0
            
            stats = {
                'total_bookings': Booking.query.filter_by(learner_id=current_user.id).count() or 0,
                'upcoming_bookings': Booking.query.filter(
                    Booking.learner_id == current_user.id,
                    Booking.status == 'confirmed',
                    Booking.booking_date >= datetime.utcnow()
                ).count() if hasattr(app, 'Booking') else 0,
                'digital_products': DigitalProductAccess.query.filter_by(
                    user_id=current_user.id,
                    is_active=True
                ).count() if hasattr(app, 'DigitalProductAccess') else 0,
                'completed_sessions': Booking.query.filter(
                    Booking.learner_id == current_user.id,
                    Booking.status == 'completed'
                ).count() if hasattr(app, 'Booking') else 0,
                'total_spent': total_spent,
            }
            
            # Get upcoming bookings for learner
            upcoming_bookings = Booking.query.filter(
                Booking.learner_id == current_user.id,
                Booking.status == 'confirmed',
                Booking.booking_date >= datetime.utcnow()
            ).order_by(Booking.booking_date).limit(5).all() if hasattr(app, 'Booking') else []
            
            # Get recommended mentors for learner
            recommended_mentors = User.query.filter_by(
                role='mentor', 
                is_verified=True
            ).order_by(func.random()).limit(3).all()
            
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        stats = {}
        upcoming_bookings = []
        recommended_mentors = []
    
    # Use the single dashboard template
    return render_template(
        'dashboard.html',
        stats=stats,
        upcoming_bookings=upcoming_bookings,
        recommended_mentors=recommended_mentors
    )
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile."""
    if request.method == 'POST':
        try:
            # Handle profile image upload
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and file.filename != '':
                    image_path = save_profile_image(file, current_user.id)
                    if image_path:
                        current_user.profile_image = image_path
            
            # Update profile
            current_user.full_name = request.form.get('full_name', '').strip()
            current_user.phone = request.form.get('phone', '').strip()
            current_user.bio = request.form.get('bio', '').strip()
            
            if current_user.role == 'mentor':
                current_user.job_title = request.form.get('job_title', '').strip()
                current_user.company = request.form.get('company', '').strip()
                current_user.domain = request.form.get('domain', '').strip()
                current_user.experience = request.form.get('experience', '').strip()
                current_user.skills = request.form.get('skills', '').strip()
                current_user.price = int(request.form.get('price', 0))
                current_user.linkedin_url = request.form.get('linkedin_url', '').strip()
                current_user.twitter_url = request.form.get('twitter_url', '').strip()
                current_user.github_url = request.form.get('github_url', '').strip()
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating profile: {e}")
            flash('Error updating profile. Please try again.', 'danger')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html')


@app.route('/my-bookings')
@login_required
def my_bookings():
    """User's bookings."""
    try:
        if current_user.role == 'mentor':
            bookings = Booking.query.filter_by(mentor_id=current_user.id).order_by(Booking.created_at.desc()).all()
        else:
            bookings = Booking.query.filter_by(learner_id=current_user.id).order_by(Booking.created_at.desc()).all()
    except Exception as e:
        logger.error(f"Error getting bookings: {e}")
        bookings = []
    
    return render_template('my_bookings.html', bookings=bookings)


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
    
    # Check for existing pending booking
    existing_pending = Booking.query.filter_by(
        learner_id=current_user.id,
        service_id=service_id,
        status='pending'
    ).first()
    
    if existing_pending:
        flash('You already have a pending booking for this service.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Create booking
    try:
        booking = Booking(
            mentor_id=mentor.id,
            learner_id=current_user.id,
            service_id=service.id,
            service_name=service.name,
            price=service.price,
            status='pending',
            payment_status='pending'
        )
        
        db.session.add(booking)
        db.session.commit()
        
        create_notification(
            user_id=mentor.id,
            title='New Booking Request',
            message=f'{current_user.username} has requested to book {service.name}',
            notification_type='booking',
            action_url=url_for('my_bookings')
        )
        
        flash(f'Booking created for {service.name}! Please complete payment.', 'success')
        return redirect(url_for('create_payment', booking_id=booking.id))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating booking: {e}")
        flash('Error creating booking. Please try again.', 'danger')
        return redirect(url_for('service_detail', service_id=service_id))


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
        flash('Payment gateway not configured. Please contact support.', 'danger')
        return redirect(url_for('dashboard'))


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
    
    try:
        mentors = query.order_by(User.created_at.desc()).all()
    except Exception as e:
        logger.error(f"Error getting mentors: {e}")
        mentors = []
    
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
    
    try:
        mentor.is_verified = True
        db.session.commit()
        
        create_notification(
            user_id=mentor.id,
            title='Account Verified',
            message='Your mentor account has been verified by admin.',
            notification_type='success'
        )
        
        flash(f'Mentor {mentor.username} has been verified!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error verifying mentor: {e}")
        flash('Error verifying mentor. Please try again.', 'danger')
    
    return redirect(url_for('admin_mentors'))


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/health')
def api_health():
    """Health check endpoint."""
    try:
        db.session.execute('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'services': {
                'razorpay': razorpay_client is not None,
                'email': bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])
            }
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


@app.route('/api/notifications')
@login_required
def api_notifications():
    """API endpoint for user notifications."""
    try:
        notifications = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).order_by(Notification.created_at.desc()).limit(10).all()
        
        notification_list = []
        for notification in notifications:
            notification_list.append({
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'type': notification.notification_type,
                'action_url': notification.action_url,
                'created_at': notification.created_at.isoformat(),
            })
        
        return jsonify({
            'success': True,
            'notifications': notification_list
        })
    except Exception as e:
        logger.error(f"Notifications API error: {e}")
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


@app.route('/contact')
def contact():
    """Contact page."""
    return render_template('contact.html')


@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')


@app.route('/faq')
def faq():
    """FAQ page."""
    return render_template('faq.html')


# ============================================================================
# INITIALIZATION
# ============================================================================

def init_database():
    """Initialize database with all tables."""
    with app.app_context():
        try:
            print("🔧 Initializing database...")
            
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Create admin user if not exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
            admin = User.query.filter_by(email=admin_email).first()
            
            if not admin:
                admin = User(
                    username='admin',
                    email=admin_email,
                    role='admin',
                    is_email_verified=True,
                    is_verified=True,
                    is_active=True
                )
                admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created")
            else:
                print("✅ Admin user already exists")
                
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error initializing database: {e}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Run the app
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = app.config['FLASK_DEBUG']
    
    print(f"🚀 Starting ClearQ on {host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug, threaded=True)














