import os
import json
import random
import re
import uuid
import secrets
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from itsdangerous import URLSafeTimedSerializer
import razorpay
import requests
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FORCE FLASK TO FIND TEMPLATES ---
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
app = Flask(__name__, template_folder=template_dir)
# -------------------------------------

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY', secrets.token_hex(32))

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    f"sqlite:///{os.path.join(basedir, 'clearq.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

# File upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'zip', 'rar'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', '')

# Payment Gateway Configuration (Razorpay)
app.config['RAZORPAY_KEY_ID'] = os.environ.get('RAZORPAY_KEY_ID', '')
app.config['RAZORPAY_KEY_SECRET'] = os.environ.get('RAZORPAY_KEY_SECRET', '')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# Initialize Razorpay
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

# Initialize token serializer for email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Custom decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def mentor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'mentor':
            flash('Mentor access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def learner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'learner':
            flash('Learner access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function for file uploads
def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']

def validate_file(file):
    """Validate uploaded file for security"""
    if not file or file.filename == '':
        return False, 'No file selected'
    
    if not allowed_file(file.filename):
        return False, 'File type not allowed'
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > app.config['MAX_CONTENT_LENGTH']:
        return False, 'File too large'
    
    return True, 'File valid'

def save_profile_image(file, user_id):
    valid, message = validate_file(file)
    if not valid:
        return None
    
    # Create secure filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{user_id}_{timestamp}.{ext}"
    
    # Ensure upload folder exists
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_images')
    os.makedirs(upload_path, exist_ok=True)
    
    filepath = os.path.join(upload_path, filename)
    try:
        file.save(filepath)
        return f'uploads/profile_images/{filename}'
    except Exception as e:
        logger.error(f"Error saving profile image: {e}")
        return None

def save_digital_product(file, user_id, service_id):
    valid, message = validate_file(file)
    if not valid:
        return None
    
    # Create secure filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"digital_product_{user_id}_{service_id}_{timestamp}.{ext}"
    
    # Ensure upload folder exists
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'digital_products')
    os.makedirs(upload_path, exist_ok=True)
    
    filepath = os.path.join(upload_path, filename)
    try:
        file.save(filepath)
        return f'uploads/digital_products/{filename}'
    except Exception as e:
        logger.error(f"Error saving digital product: {e}")
        return None

# Helper function to generate URL-friendly slugs
def generate_slug(text):
    """Generate a URL-friendly slug from text"""
    if not text:
        return ''
    
    # Convert to lowercase
    slug = text.lower()
    # Remove special characters
    slug = re.sub(r'[^\w\s-]', '', slug)
    # Replace spaces with hyphens
    slug = re.sub(r'[-\s]+', '-', slug)
    # Remove leading/trailing hyphens
    return slug.strip('-')

# Helper function to get available dates
def get_available_dates(mentor_id, days_ahead=14):
    """Get available dates for booking (next 14 days)"""
    today = datetime.now().date()
    available_dates = []
    
    # Get booked dates for this mentor
    booked_dates = Booking.query.filter_by(mentor_id=mentor_id).all()
    
    for i in range(days_ahead):
        current_date = today + timedelta(days=i)
        
        # Check if date is not fully booked (assuming max 8 slots per day)
        day_bookings = [b for b in booked_dates if b.booking_date == current_date]
        
        # Format date information
        date_info = {
            'date': current_date,
            'day_name': current_date.strftime('%a'),
            'date_str': current_date.strftime('%b %d'),
            'full_date': current_date.strftime('%Y-%m-%d'),
            'day_num': current_date.day,
            'month': current_date.strftime('%b'),
            'is_today': i == 0,
            'is_tomorrow': i == 1,
            'available_slots': 8 - len(day_bookings)  # Max 8 slots per day
        }
        
        available_dates.append(date_info)
    
    return available_dates

# Helper function to get time slots for a specific date
def get_time_slots_for_date(mentor_id, date_str):
    """Get available time slots for a specific date"""
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
    booked_slots = [b.slot_time for b in Booking.query.filter_by(
        mentor_id=mentor_id, 
        booking_date=date_obj
    ).all()]
    
    # Filter out booked slots
    available_slots = [s for s in all_slots if s not in booked_slots]
    
    return available_slots

# Email helper functions
def generate_verification_token(email):
    return s.dumps(email, salt='email-confirm-salt')

def confirm_verification_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=expiration)
    except:
        return False
    return email

def generate_reset_token(email):
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return False
    return email

def send_email(to, subject, body, html_body=None):
    """Send email using external service"""
    # In production, implement actual email sending
    logger.info(f"Email to {to}: {subject}")
    
    # Example with Mailgun (configure in production)
    mailgun_api_key = os.environ.get('MAILGUN_API_KEY')
    mailgun_domain = os.environ.get('MAILGUN_DOMAIN')
    
    if mailgun_api_key and mailgun_domain:
        try:
            response = requests.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": f"ClearQ <noreply@{mailgun_domain}>",
                    "to": [to],
                    "subject": subject,
                    "text": body,
                    "html": html_body
                }
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Mailgun error: {e}")
    
    # Fallback: log to console
    print(f"\n=== EMAIL TO: {to} ===")
    print(f"SUBJECT: {subject}")
    print(f"BODY:\n{body}")
    print("=== END EMAIL ===\n")
    
    return True

def send_verification_email(user):
    token = generate_verification_token(user.email)
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = 'Verify Your Email - ClearQ'
    body = f'''Please click the following link to verify your email:
{verification_url}

If you did not create an account, please ignore this email.

This link will expire in 1 hour.
'''
    html_body = f'''
    <h3>Welcome to ClearQ!</h3>
    <p>Please click the button below to verify your email address:</p>
    <a href="{verification_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
    <p>Or copy and paste this link: {verification_url}</p>
    <p>This link will expire in 1 hour.</p>
    '''
    
    return send_email(user.email, subject, body, html_body)

def send_password_reset_email(user):
    token = generate_reset_token(user.email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    subject = 'Reset Your Password - ClearQ'
    body = f'''To reset your password, visit the following link:
{reset_url}

If you did not request a password reset, please ignore this email.

This link will expire in 1 hour.
'''
    html_body = f'''
    <h3>Password Reset Request</h3>
    <p>Click the button below to reset your password:</p>
    <a href="{reset_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
    <p>Or copy and paste this link: {reset_url}</p>
    <p>This link will expire in 1 hour.</p>
    '''
    
    return send_email(user.email, subject, body, html_body)

def send_booking_confirmation(user, booking):
    """Send booking confirmation email"""
    mentor = User.query.get(booking.mentor_id)
    
    subject = f'Booking Confirmed - {booking.service_name}'
    body = f'''Your booking has been confirmed!

Booking Details:
- Service: {booking.service_name}
- Mentor: {mentor.full_name if mentor else 'Unknown'}
- Date: {booking.booking_date.strftime("%B %d, %Y") if booking.booking_date else 'To be scheduled'}
- Time: {booking.slot_time}
- Price: ₹{booking.price or 0}

Meeting Link: {booking.meeting_link or 'Will be provided before the session'}

Thank you for choosing ClearQ!
'''
    
    return send_email(user.email, subject, body)

def send_digital_product_access_email(user, service):
    """Send digital product access email"""
    subject = f'Digital Product Access - {service.name}'
    body = f'''You now have access to the digital product: {service.name}

Product Details:
- Name: {service.name}
- Description: {service.description}

You can access this product from your dashboard at any time.

Thank you for your purchase!
'''
    
    return send_email(user.email, subject, body)

# Meeting link generation
def generate_meeting_link(booking):
    """Generate a secure meeting link for the booking"""
    # Generate a secure meeting ID
    meeting_id = secrets.token_urlsafe(16)
    
    # Create a unique meeting link
    # Using Jitsi Meet (open source, secure)
    meeting_link = f"https://meet.jit.si/ClearQ-{meeting_id}"
    
    # Store meeting details
    booking.meeting_link = meeting_link
    booking.meeting_id = meeting_id
    booking.meeting_platform = 'jitsi'
    
    return meeting_link

# Payment helper functions
def create_razorpay_order(amount, receipt, notes=None):
    """Create a Razorpay order"""
    order_data = {
        'amount': int(amount * 100),  # Convert to paise
        'currency': 'INR',
        'receipt': receipt,
        'payment_capture': 1
    }
    
    if notes:
        order_data['notes'] = notes
    
    try:
        order = razorpay_client.order.create(data=order_data)
        return order
    except Exception as e:
        logger.error(f"Razorpay error: {e}")
        return None

# --- MODELS ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='learner')  # 'learner', 'mentor', 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Email verification fields
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    
    # Mentor Specific Fields
    full_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    job_title = db.Column(db.String(100), nullable=True)
    domain = db.Column(db.String(100), nullable=True)  # e.g., Data Science, SDE
    company = db.Column(db.String(100), nullable=True)
    previous_company = db.Column(db.String(100), nullable=True)
    experience = db.Column(db.String(50), nullable=True)
    skills = db.Column(db.Text, nullable=True)
    services = db.Column(db.Text, nullable=True)  # Old field - keep for backward compatibility
    bio = db.Column(db.Text, nullable=True)
    price = db.Column(db.Integer, default=0, nullable=True)  # Default price
    availability = db.Column(db.String(50), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Profile fields
    profile_image = db.Column(db.String(500), nullable=True)
    facebook_url = db.Column(db.String(200), nullable=True)
    instagram_url = db.Column(db.String(200), nullable=True)
    youtube_url = db.Column(db.String(200), nullable=True)
    linkedin_url = db.Column(db.String(200), nullable=True)
    success_rate = db.Column(db.Integer, default=95)  # percentage
    response_rate = db.Column(db.Integer, default=98)  # percentage
    rating = db.Column(db.Float, default=4.9)
    review_count = db.Column(db.Integer, default=0)
    profile_views = db.Column(db.Integer, default=0)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_user_role_verified', 'role', 'is_verified'),
    )
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, index=True)  # URL-friendly version of name
    description = db.Column(db.Text, nullable=True)
    detailed_description = db.Column(db.Text, nullable=True)  # More detailed description for service page
    price = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.String(50), nullable=True)  # e.g., "30 mins", "1 hour"
    
    # Digital product fields
    service_type = db.Column(db.String(50), default='consultation')  # 'consultation', 'digital_product', 'both'
    digital_product_link = db.Column(db.String(500), nullable=True)
    digital_product_name = db.Column(db.String(200), nullable=True)
    digital_product_description = db.Column(db.Text, nullable=True)
    digital_product_file = db.Column(db.String(500), nullable=True)  # Path to uploaded file
    access_after_payment = db.Column(db.Boolean, default=True)
    
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    mentor = db.relationship('User', backref='mentor_services')
    
    __table_args__ = (
        db.Index('idx_service_mentor_active', 'mentor_id', 'is_active'),
        db.UniqueConstraint('mentor_id', 'slug', name='uq_mentor_service_slug'),
    )

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    program_name = db.Column(db.String(100), default='career_mentorship')
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    payment_amount = db.Column(db.Integer, default=499)
    status = db.Column(db.String(20), default='active')  # active, completed, cancelled
    additional_data = db.Column(db.Text)  # Store form data as JSON
    
    user = db.relationship('User', backref='enrollments')

class Booking(db.Model):
    __tablename__ = 'bookings'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    service_name = db.Column(db.String(100))
    slot_time = db.Column(db.String(50))
    booking_date = db.Column(db.Date, nullable=True, index=True)  # Date of booking
    status = db.Column(db.String(20), default='Pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    price = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Meeting fields
    meeting_link = db.Column(db.String(500), nullable=True)
    meeting_platform = db.Column(db.String(50), nullable=True)  # 'jitsi', 'zoom', 'custom'
    meeting_id = db.Column(db.String(100), nullable=True)
    meeting_password = db.Column(db.String(100), nullable=True)
    meeting_notes = db.Column(db.Text, nullable=True)
    is_session_completed = db.Column(db.Boolean, default=False)
    session_feedback = db.Column(db.Text, nullable=True)
    session_rating = db.Column(db.Integer, nullable=True)
    
    # Payment fields
    payment_id = db.Column(db.String(100), nullable=True)
    payment_status = db.Column(db.String(20), default='pending', index=True)  # pending, success, failed
    razorpay_order_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)

    mentor = db.relationship('User', foreign_keys=[mentor_id])
    learner = db.relationship('User', foreign_keys=[learner_id])
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_booking_mentor_date', 'mentor_id', 'booking_date'),
        db.Index('idx_booking_learner_status', 'learner_id', 'status'),
        db.Index('idx_booking_date_status', 'booking_date', 'status'),
    )

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    product_type = db.Column(db.String(50), default='1:1 call')  # '1:1 call', 'Digital Product', 'Webinar', 'Combo'
    duration = db.Column(db.String(50), nullable=True)  # '30 mins', '1 hour', 'Downloadable'
    price = db.Column(db.Integer, nullable=False)
    tag = db.Column(db.String(20), nullable=True)  # 'Best Seller', 'Recommended', 'Popular'
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Digital product fields
    digital_product_link = db.Column(db.String(500), nullable=True)
    digital_product_file = db.Column(db.String(500), nullable=True)
    
    mentor = db.relationship('User', backref='products')

class Review(db.Model):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    learner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    learner = db.relationship('User', foreign_keys=[learner_id])
    product = db.relationship('Product')
    service = db.relationship('Service')
    
    __table_args__ = (
        db.Index('idx_review_mentor_rating', 'mentor_id', 'rating'),
    )

class Payment(db.Model):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'), nullable=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollments.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)
    
    amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    currency = db.Column(db.String(3), default='INR')
    razorpay_order_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True, index=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    
    status = db.Column(db.String(20), default='pending', index=True)  # pending, success, failed
    payment_method = db.Column(db.String(50), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='payments')
    booking = db.relationship('Booking', backref='payment_record')
    enrollment = db.relationship('Enrollment')
    service = db.relationship('Service')
    product = db.relationship('Product')
    
    __table_args__ = (
        db.Index('idx_payment_user_status', 'user_id', 'status'),
        db.Index('idx_payment_created', 'created_at'),
    )

class DigitalProductAccess(db.Model):
    __tablename__ = 'digital_product_access'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=True)
    access_granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    downloads_count = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', backref='digital_accesses')
    service = db.relationship('Service', backref='accesses')
    product = db.relationship('Product')
    payment = db.relationship('Payment')
    
    __table_args__ = (
        db.Index('idx_access_user_active', 'user_id', 'is_active'),
        db.Index('idx_access_expires', 'expires_at'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AI ENGINE (No API) ---
def get_ai_recommendations(user_goal):
    """
    Uses Scikit-Learn to find mentors whose bios/domains match the user's goal.
    """
    try:
        mentors = User.query.filter_by(role='mentor', is_verified=True).all()
        if not mentors:
            return []

        # Prepare data for AI
        mentor_data = []
        for m in mentors:
            # Combine relevant fields into a single 'content' string
            content = f"{m.domain} {m.company} {m.services} {m.bio} {m.skills}"
            mentor_data.append({'id': m.id, 'content': content, 'obj': m})

        if not mentor_data:
            return []

        # Add user goal to the corpus
        corpus = [m['content'] for m in mentor_data]
        corpus.append(user_goal)

        # TF-IDF Vectorization
        tfidf = TfidfVectorizer(stop_words='english')
        tfidf_matrix = tfidf.fit_transform(corpus)

        # Calculate Cosine Similarity
        cosine_sim = linear_kernel(tfidf_matrix[-1], tfidf_matrix[:-1])
        
        # Get similarity scores
        scores = list(enumerate(cosine_sim[0]))
        scores = sorted(scores, key=lambda x: x[1], reverse=True)

        # Return top 3 matched mentor objects
        recommended_mentors = []
        for i, score in scores[:3]:
            if score > 0.1:
                recommended_mentors.append(mentor_data[i]['obj'])
                
        return recommended_mentors
    except Exception as e:
        logger.error(f"AI Error: {e}")
        return []

@app.template_filter('escapejs')
def escapejs_filter(value):
    """Escape strings for JavaScript"""
    if value is None:
        return ''
    
    value = str(value)
    replacements = {
        '\\': '\\\\',
        '"': '\\"',
        "'": "\\'",
        '\n': '\\n',
        '\r': '\\r',
        '\t': '\\t',
        '</': '<\\/',
    }
    
    for find, replace in replacements.items():
        value = value.replace(find, replace)
    
    return value

@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string in templates"""
    if not value:
        return {}
    try:
        return json.loads(value)
    except:
        return {}

# --- ERROR HANDLERS ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def ratelimit_error(error):
    return render_template('errors/429.html'), 429

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/<username>')
def redirect_old_profile(username):
    """Redirect old /username URLs to new /mentor/username URLs"""
    if '.' in username and username.split('.')[-1] in ['ico', 'png', 'jpg', 'css', 'js', 'json']:
        return '', 404
    
    return redirect(url_for('mentor_public_profile', username=username))

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

@app.route('/sitemap.xml')
def sitemap():
    return '', 404

@app.route('/explore', methods=['GET', 'POST'])
def explore():
    recommendations = []
    query = ""
    
    if request.method == 'POST':
        query = request.form.get('goal')
        if query:
            try:
                recommendations = get_ai_recommendations(query)
            except Exception as e:
                logger.error(f"AI error: {e}")
                # Fallback: simple text matching
                mentors = User.query.filter_by(role='mentor', is_verified=True).all()
                for mentor in mentors:
                    mentor_text = f"{mentor.domain or ''} {mentor.bio or ''} {mentor.skills or ''}".lower()
                    if query.lower() in mentor_text:
                        recommendations.append(mentor)
    
    # Get all verified mentors
    all_mentors = User.query.filter_by(role='mentor', is_verified=True).all()
    
    return render_template('mentors.html', 
                         mentors=all_mentors, 
                         recommendations=recommendations, 
                         query=query)

@app.route('/mentor/<username>-<int:id>')
def mentor_profile_with_id(username, id):
    """Handle URLs with both username and ID"""
    user = User.query.filter_by(username=username, id=id).first()
    
    if user:
        return redirect(url_for('mentor_public_profile', username=username))
    else:
        return redirect(url_for('mentor_public_profile', username=username))

@app.route('/mentor/<username>')
def mentor_public_profile(username):
    mentor = User.query.filter_by(username=username).first()
    
    if not mentor:
        flash('User not found', 'danger')
        return redirect(url_for('explore'))
    
    if mentor.role != 'mentor':
        flash('User is not a mentor', 'danger')
        return redirect(url_for('explore'))
    
    # Increment profile views
    mentor.profile_views = (mentor.profile_views or 0) + 1
    db.session.commit()
    
    # Get mentor's services
    services = Service.query.filter_by(mentor_id=mentor.id, is_active=True).all()
    
    # Get reviews
    reviews = Review.query.filter_by(mentor_id=mentor.id).all()
    
    # Get available dates for quick booking
    available_dates = get_available_dates(mentor.id, days_ahead=7)
    
    # Calculate total sessions
    total_sessions = Booking.query.filter_by(mentor_id=mentor.id).count()
    
    return render_template('mentor_public_profile.html',
                         mentor=mentor,
                         services=services,
                         reviews=reviews,
                         total_sessions=total_sessions,
                         available_dates=available_dates)

@app.route('/mentor/<username>/service/<service_slug>')
def service_detail(username, service_slug):
    """Service detail page with date and time selection"""
    mentor = User.query.filter_by(username=username, role='mentor').first_or_404()
    service = Service.query.filter_by(mentor_id=mentor.id, slug=service_slug, is_active=True).first_or_404()
    
    # Get reviews for this service
    reviews = Review.query.filter_by(service_id=service.id).all()
    
    # Calculate average rating
    avg_rating = 0
    if reviews:
        avg_rating = sum([r.rating for r in reviews]) / len(reviews)
    
    # Get available dates (next 14 days)
    available_dates = get_available_dates(mentor.id)
    
    # Get time slots for today (default)
    today_date = datetime.now().strftime('%Y-%m-%d')
    available_slots = get_time_slots_for_date(mentor.id, today_date)
    
    # Get other services from the same mentor
    other_services = Service.query.filter_by(
        mentor_id=mentor.id, 
        is_active=True
    ).filter(Service.id != service.id).limit(3).all()
    
    # Check if user already has access to digital product
    has_access = False
    if current_user.is_authenticated and service.service_type in ['digital_product', 'both']:
        access = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            service_id=service.id,
            is_active=True
        ).first()
        has_access = access is not None
    
    return render_template('service_detail.html',
                         mentor=mentor,
                         service=service,
                         reviews=reviews,
                         avg_rating=avg_rating,
                         available_dates=available_dates,
                         available_slots=available_slots,
                         today_date=today_date,
                         other_services=other_services,
                         has_access=has_access)

@app.route('/api/get-time-slots/<int:mentor_id>', methods=['POST'])
@csrf.exempt
def get_time_slots(mentor_id):
    """API endpoint to get available time slots for a specific date"""
    try:
        data = request.get_json()
        date_str = data.get('date')
        
        if not date_str:
            return jsonify({'error': 'Date is required'}), 400
        
        available_slots = get_time_slots_for_date(mentor_id, date_str)
        
        return jsonify({
            'success': True,
            'slots': available_slots,
            'date': date_str
        })
    except Exception as e:
        logger.error(f"Error getting time slots: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/book-service/<int:service_id>', methods=['POST'])
@login_required
@csrf.exempt
def book_service(service_id):
    service = Service.query.get_or_404(service_id)
    mentor = User.query.get(service.mentor_id)
    
    if current_user.role == 'mentor':
        flash('Mentors cannot book their own services', 'danger')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    # Check if it's a digital product and user already has access
    if service.service_type == 'digital_product' and service.access_after_payment:
        access = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            service_id=service.id,
            is_active=True
        ).first()
        
        if access:
            flash('You already have access to this digital product.', 'info')
            return redirect(url_for('my_digital_products'))
    
    # For digital products without consultation, redirect to payment
    if service.service_type == 'digital_product' and service.service_type != 'both':
        return redirect(url_for('create_service_payment', service_id=service.id))
    
    # For consultation or both, proceed with booking
    slot = request.form.get('slot')
    date_str = request.form.get('date')
    notes = request.form.get('notes', '')
    
    if not slot and service.service_type != 'digital_product':
        flash('Please select a time slot', 'danger')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    if not date_str and service.service_type != 'digital_product':
        flash('Please select a date', 'danger')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    # Convert date string to date object
    booking_date = None
    if date_str:
        try:
            booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format', 'danger')
            return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
        
        # Check if slot is already booked
        existing_booking = Booking.query.filter_by(
            mentor_id=service.mentor_id,
            booking_date=booking_date,
            slot_time=slot
        ).first()
        
        if existing_booking:
            flash('This time slot is already booked. Please select another time.', 'danger')
            return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    try:
        # Create booking
        booking = Booking(
            mentor_id=service.mentor_id,
            learner_id=current_user.id,
            service_id=service.id,
            service_name=service.name,
            slot_time=slot,
            booking_date=booking_date,
            price=service.price,
            notes=notes,
            status='Pending Payment'
        )
        db.session.add(booking)
        db.session.commit()
        
        # For digital products with immediate access (no payment required)
        if service.service_type == 'digital_product' and not service.access_after_payment:
            # Grant immediate access
            access = DigitalProductAccess(
                user_id=current_user.id,
                service_id=service.id,
                expires_at=datetime.utcnow() + timedelta(days=365)
            )
            db.session.add(access)
            db.session.commit()
            
            send_digital_product_access_email(current_user, service)
            flash(f'Digital product "{service.name}" added to your account!', 'success')
            return redirect(url_for('my_digital_products'))
        
        flash(f'Booking created for {service.name}! Please complete payment.', 'success')
        return redirect(url_for('create_payment', booking_id=booking.id))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating booking: {e}")
        flash('Error creating booking. Please try again.', 'danger')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))

@app.route('/mentorship-program')
def mentorship_program():
    """Main mentorship program landing page"""
    stats = {
        'success_rate': '95%',
        'students_enrolled': '2000+',
        'completion_rate': '89%'
    }
    return render_template('mentorship_program.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        # Validate input
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return render_template('login.html')
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user, remember=remember)
            flash('Logged in successfully!', 'success')
            
            # Validate next parameter to prevent open redirect
            next_page = request.args.get('next')
            if next_page and not next_page.startswith('//') and '://' not in next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        pending_mentors = User.query.filter_by(role='mentor', is_verified=False).all()
        total_users = User.query.count()
        verified_mentors = User.query.filter_by(role='mentor', is_verified=True).count()
        total_bookings = Booking.query.count()
        
        # Get recent bookings with mentor names
        recent_bookings = []
        bookings = Booking.query.order_by(Booking.created_at.desc()).limit(5).all()
        for booking in bookings:
            mentor = User.query.get(booking.mentor_id)
            learner = User.query.get(booking.learner_id)
            recent_bookings.append({
                'mentor_name': mentor.username if mentor else 'Unknown',
                'learner_name': learner.username if learner else 'Unknown',
                'service_name': booking.service_name,
                'slot_time': booking.slot_time,
                'amount': booking.price or (mentor.price if mentor else 0),
                'status': booking.status,
                'created_at': booking.created_at.strftime('%b %d, %Y') if booking.created_at else 'N/A'
            })
        
        return render_template('admin.html',
                             pending_mentors=pending_mentors,
                             total_users=total_users,
                             verified_mentors=verified_mentors,
                             total_bookings=total_bookings,
                             recent_bookings=recent_bookings)
    
    elif current_user.role == 'mentor':
        my_bookings = Booking.query.filter_by(mentor_id=current_user.id).all()
        
        # Get learner names for bookings
        bookings_with_learners = []
        for booking in my_bookings:
            learner = User.query.get(booking.learner_id)
            bookings_with_learners.append({
                'booking': booking,
                'learner': learner
            })
        
        # Get services count
        services_count = Service.query.filter_by(mentor_id=current_user.id, is_active=True).count()
        
        # Calculate stats
        total_bookings = len(my_bookings)
        pending_bookings = len([b for b in my_bookings if b.status in ['Pending', 'Pending Payment']])
        completed_bookings = [b for b in my_bookings if b.status == 'Completed']
        total_earnings = sum([b.price or current_user.price for b in my_bookings if b.payment_status == 'success'])
        total_sessions = len(completed_bookings)
        
        # Get upcoming bookings
        today = datetime.now().date()
        upcoming_bookings = [b for b in my_bookings if b.booking_date and b.booking_date >= today and b.status in ['Paid', 'Confirmed']]
        
        return render_template('dashboard.html',
                             upcoming_bookings=upcoming_bookings[:5],
                             type='mentor',
                             total_bookings=total_bookings,
                             pending_bookings=pending_bookings,
                             completed_bookings=completed_bookings,
                             total_earnings=total_earnings,
                             total_sessions=total_sessions,
                             services_count=services_count,
                             bookings=bookings_with_learners)
        
    else:  # Learner
        my_bookings = Booking.query.filter_by(learner_id=current_user.id).all()
        bookings_with_mentors = []
        for booking in my_bookings:
            mentor = User.query.get(booking.mentor_id)
            bookings_with_mentors.append({
                'booking': booking,
                'mentor': mentor
            })
        
        # Calculate stats for template
        completed_bookings = [b for b in my_bookings if b.status == 'Completed']
        total_spent = sum([b.price or 0 for b in completed_bookings])
        
        # Get upcoming bookings
        today = datetime.now().date()
        upcoming_bookings = [b for b in my_bookings if b.booking_date and b.booking_date >= today and b.status in ['Paid', 'Confirmed']]
        
        # Get digital products count
        digital_products_count = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).count()
        
        # Get recommended mentors
        recommended_mentors = User.query.filter_by(
            role='mentor',
            is_verified=True
        ).limit(3).all()
        
        return render_template('dashboard.html',
                             upcoming_bookings=upcoming_bookings[:5],
                             completed_bookings=completed_bookings,
                             total_spent=total_spent,
                             recommended_mentors=recommended_mentors,
                             type='learner',
                             digital_products_count=digital_products_count,
                             bookings=bookings_with_mentors)

@app.route('/verify/<int:id>')
@login_required
@admin_required
def verify_mentor(id):
    mentor = User.query.get(id)
    if not mentor:
        flash('Mentor not found', 'danger')
        return redirect(url_for('dashboard'))
    
    if mentor.role != 'mentor':
        flash('User is not a mentor', 'danger')
        return redirect(url_for('dashboard'))
    
    mentor.is_verified = True
    db.session.commit()
    flash(f'{mentor.username} has been verified!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject-mentor/<int:id>', methods=['POST'])
@login_required
@admin_required
def reject_mentor(id):
    mentor = User.query.get(id)
    if not mentor:
        return jsonify({'success': False, 'message': 'Mentor not found'}), 404
    
    if mentor.role != 'mentor':
        return jsonify({'success': False, 'message': 'User is not a mentor'}), 400
    
    db.session.delete(mentor)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Mentor application rejected'})

# EMAIL AUTHENTICATION ROUTES
@app.route('/verify-email/<token>')
@login_required
def verify_email(token):
    try:
        email = confirm_verification_token(token)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('dashboard'))
    
    if current_user.email != email:
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('dashboard'))
    
    if current_user.is_email_verified:
        flash('Email is already verified.', 'info')
        return redirect(url_for('dashboard'))
    
    current_user.is_email_verified = True
    current_user.email_verification_token = None
    db.session.commit()
    
    flash('Email verified successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/resend-verification')
@login_required
def resend_verification():
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
    if request.method == 'POST':
        email = request.form.get('email')
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
    email = verify_reset_token(token)
    
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password.html', token=token)
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# PAYMENT GATEWAY ROUTES
@app.route('/create-payment/<int:booking_id>')
@login_required
def create_payment(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if user is authorized
    if booking.learner_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if payment already processed
    if booking.payment_status == 'success':
        flash('Payment already completed.', 'info')
        return redirect(url_for('dashboard'))
    
    # Create Razorpay order
    order = create_razorpay_order(
        amount=booking.price or 0,
        receipt=f'booking_{booking_id}',
        notes={
            'booking_id': booking_id,
            'user_id': current_user.id,
            'service': booking.service_name
        }
    )
    
    if not order:
        flash('Error creating payment. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update booking with order ID
    booking.razorpay_order_id = order['id']
    db.session.commit()
    
    return render_template('payment.html',
                         booking=booking,
                         order_id=order['id'],
                         amount=booking.price or 0,
                         key_id=app.config['RAZORPAY_KEY_ID'],
                         user=current_user)

@app.route('/create-service-payment/<int:service_id>')
@login_required
def create_service_payment(service_id):
    service = Service.query.get_or_404(service_id)
    
    # Create Razorpay order
    order = create_razorpay_order(
        amount=service.price,
        receipt=f'service_{service_id}_{current_user.id}',
        notes={
            'service_id': service_id,
            'user_id': current_user.id,
            'service_name': service.name,
            'mentor_id': service.mentor_id
        }
    )
    
    if not order:
        flash('Error creating payment. Please try again.', 'danger')
        return redirect(url_for('service_detail', username=service.mentor.username, service_slug=service.slug))
    
    # Create pending booking
    booking = Booking(
        mentor_id=service.mentor_id,
        learner_id=current_user.id,
        service_id=service.id,
        service_name=service.name,
        price=service.price,
        status='Pending Payment',
        razorpay_order_id=order['id']
    )
    db.session.add(booking)
    db.session.commit()
    
    return render_template('payment.html',
                         booking=booking,
                         order_id=order['id'],
                         amount=service.price,
                         key_id=app.config['RAZORPAY_KEY_ID'],
                         user=current_user)

@app.route('/payment-success', methods=['POST'])
@login_required
@csrf.exempt
def payment_success():
    """Secure payment verification and processing"""
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')
    
    if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
        flash('Invalid payment parameters.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Find booking by order ID
    booking = Booking.query.filter_by(razorpay_order_id=razorpay_order_id).first()
    if not booking:
        flash('Invalid booking reference.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Verify user authorization
    if booking.learner_id != current_user.id:
        flash('Unauthorized payment attempt.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Verify payment hasn't already been processed
    if booking.payment_status == 'success':
        flash('Payment already processed.', 'info')
        return redirect(url_for('dashboard'))
    
    try:
        # Verify payment signature with Razorpay
        params_dict = {
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_order_id': razorpay_order_id,
            'razorpay_signature': razorpay_signature
        }
        
        # Verify signature
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # Fetch payment details from Razorpay to verify amount
        payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
        
        # Verify payment amount matches booking amount (convert to paise)
        expected_amount_paise = int((booking.price or 0) * 100)
        actual_amount_paise = payment_details['amount']
        
        if expected_amount_paise != actual_amount_paise:
            raise ValueError(f'Payment amount mismatch. Expected: {expected_amount_paise}, Got: {actual_amount_paise}')
        
        # Verify payment status
        if payment_details['status'] != 'captured':
            raise ValueError('Payment not captured')
        
        # Verify currency
        if payment_details['currency'] != 'INR':
            raise ValueError('Invalid currency')
        
        # Update booking
        booking.razorpay_payment_id = razorpay_payment_id
        booking.razorpay_signature = razorpay_signature
        booking.payment_status = 'success'
        booking.status = 'Confirmed'
        
        # Generate meeting link if it's a consultation service
        if booking.service:
            service = Service.query.get(booking.service_id)
            if service and service.service_type in ['consultation', 'both']:
                generate_meeting_link(booking)
        
        # Create payment record
        payment = Payment(
            user_id=current_user.id,
            booking_id=booking.id,
            service_id=booking.service_id,
            amount=actual_amount_paise,
            currency='INR',
            razorpay_order_id=razorpay_order_id,
            razorpay_payment_id=razorpay_payment_id,
            razorpay_signature=razorpay_signature,
            status='success',
            payment_method=payment_details.get('method', 'card')
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
                send_digital_product_access_email(current_user, service)
        
        db.session.commit()
        
        # Send booking confirmation email
        send_booking_confirmation(current_user, booking)
        
        flash('Payment successful! Your booking has been confirmed.', 'success')
        return redirect(url_for('dashboard'))
        
    except razorpay.errors.SignatureVerificationError as e:
        logger.error(f"Payment signature verification failed: {e}")
        flash('Payment verification failed. Please contact support.', 'danger')
    except ValueError as e:
        logger.error(f"Payment validation error: {e}")
        flash(f'Payment validation error: {str(e)}', 'danger')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Payment processing error: {e}")
        flash('Error processing payment. Please contact support.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/payment-failed')
@login_required
def payment_failed():
    order_id = request.args.get('order_id')
    
    if order_id:
        booking = Booking.query.filter_by(razorpay_order_id=order_id).first()
        if booking:
            booking.payment_status = 'failed'
            booking.status = 'Payment Failed'
            db.session.commit()
    
    flash('Payment failed. Please try again.', 'danger')
    return redirect(url_for('dashboard'))

# MEETING LINK ROUTES
@app.route('/api/generate-meeting-link/<int:booking_id>', methods=['POST'])
@login_required
def api_generate_meeting_link(booking_id):
    """API endpoint to generate meeting link for a booking"""
    booking = Booking.query.get_or_404(booking_id)
    
    # Check permissions
    if current_user.id != booking.mentor_id and current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Only generate for confirmed/paid bookings
    if booking.status not in ['Paid', 'Confirmed']:
        return jsonify({'success': False, 'message': 'Booking is not confirmed'}), 400
    
    try:
        # Generate meeting link
        meeting_link = generate_meeting_link(booking)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Meeting link generated successfully',
            'meeting_link': meeting_link,
            'meeting_id': booking.meeting_id
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating meeting link: {e}")
        return jsonify({'success': False, 'message': f'Error generating meeting link: {str(e)}'}), 500

@app.route('/meeting/<int:booking_id>')
@login_required
def join_meeting(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if user has permission to join
    if current_user.id not in [booking.mentor_id, booking.learner_id] and current_user.role != 'admin':
        flash('You are not authorized to join this meeting.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if meeting is scheduled for today
    today = datetime.now().date()
    if booking.booking_date and booking.booking_date != today:
        flash('This meeting is not scheduled for today.', 'warning')
    
    # If no meeting link exists, generate one
    if not booking.meeting_link and booking.status in ['Paid', 'Confirmed']:
        generate_meeting_link(booking)
        db.session.commit()
    
    return render_template('meeting.html', booking=booking)

@app.route('/complete-session/<int:booking_id>', methods=['POST'])
@login_required
@mentor_required
def complete_session(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    if current_user.id != booking.mentor_id and current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    booking.is_session_completed = True
    booking.status = 'Completed'
    db.session.commit()
    
    flash('Session marked as completed!', 'success')
    return redirect(url_for('dashboard'))

# DIGITAL PRODUCT ROUTES
@app.route('/my-digital-products')
@login_required
def my_digital_products():
    # Get all digital products user has access to
    accesses = DigitalProductAccess.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()
    
    products = []
    for access in accesses:
        if access.service:
            products.append({
                'type': 'service',
                'item': access.service,
                'access': access
            })
        elif access.product:
            products.append({
                'type': 'product',
                'item': access.product,
                'access': access
            })
    
    return render_template('my_digital_products.html', products=products)

@app.route('/download-digital-product/<int:access_id>')
@login_required
def download_digital_product(access_id):
    access = DigitalProductAccess.query.get_or_404(access_id)
    
    # Verify access
    if access.user_id != current_user.id or not access.is_active:
        flash('Access denied or expired.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    if access.expires_at and access.expires_at < datetime.utcnow():
        access.is_active = False
        db.session.commit()
        flash('Access has expired.', 'danger')
        return redirect(url_for('my_digital_products'))
    
    # Increment download count
    access.downloads_count += 1
    db.session.commit()
    
    if access.service and access.service.digital_product_link:
        return redirect(access.service.digital_product_link)
    elif access.product and access.product.digital_product_link:
        return redirect(access.product.digital_product_link)
    else:
        flash('Product link not found.', 'danger')
        return redirect(url_for('my_digital_products'))

# MENTOR MANAGEMENT ROUTES
@app.route('/mentor/products', methods=['GET', 'POST'])
@login_required
@mentor_required
def mentor_products():
    if request.method == 'POST':
        # Add new product
        name = request.form.get('name')
        description = request.form.get('description')
        product_type = request.form.get('product_type')
        duration = request.form.get('duration')
        price = request.form.get('price')
        tag = request.form.get('tag')
        digital_product_link = request.form.get('digital_product_link')
        
        product = Product(
            mentor_id=current_user.id,
            name=name,
            description=description,
            product_type=product_type,
            duration=duration,
            price=int(price) if price else 0,
            tag=tag,
            digital_product_link=digital_product_link
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('mentor_products'))
    
    # Get mentor's products
    products = Product.query.filter_by(mentor_id=current_user.id).all()
    return render_template('mentor_products.html', products=products)

@app.route('/mentor/manage-services', methods=['GET', 'POST'])
@login_required
@mentor_required
def manage_services():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            name = request.form.get('name')
            description = request.form.get('description')
            detailed_description = request.form.get('detailed_description')
            price = request.form.get('price')
            duration = request.form.get('duration')
            service_type = request.form.get('service_type', 'consultation')
            digital_product_link = request.form.get('digital_product_link')
            digital_product_name = request.form.get('digital_product_name')
            digital_product_description = request.form.get('digital_product_description')
            access_after_payment = request.form.get('access_after_payment') == 'on'
            
            # Handle file upload
            digital_product_file = None
            if 'digital_product_file' in request.files:
                file = request.files['digital_product_file']
                if file and file.filename != '':
                    digital_product_file = save_digital_product(file, current_user.id, 0)
            
            service = Service(
                mentor_id=current_user.id,
                name=name,
                slug=generate_slug(name),
                description=description,
                detailed_description=detailed_description,
                price=int(price) if price else 0,
                duration=duration,
                service_type=service_type,
                digital_product_link=digital_product_link,
                digital_product_name=digital_product_name,
                digital_product_description=digital_product_description,
                digital_product_file=digital_product_file,
                access_after_payment=access_after_payment
            )
            db.session.add(service)
            db.session.commit()
            flash('Service added successfully!', 'success')
            
        elif action == 'update':
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first()
            if service:
                service.name = request.form.get('name')
                service.slug = generate_slug(request.form.get('name'))
                service.description = request.form.get('description')
                service.detailed_description = request.form.get('detailed_description')
                service.price = int(request.form.get('price')) if request.form.get('price') else 0
                service.duration = request.form.get('duration')
                service.service_type = request.form.get('service_type', 'consultation')
                service.digital_product_link = request.form.get('digital_product_link')
                service.digital_product_name = request.form.get('digital_product_name')
                service.digital_product_description = request.form.get('digital_product_description')
                service.access_after_payment = request.form.get('access_after_payment') == 'on'
                
                # Handle file upload
                if 'digital_product_file' in request.files:
                    file = request.files['digital_product_file']
                    if file and file.filename != '':
                        service.digital_product_file = save_digital_product(file, current_user.id, service.id)
                
                db.session.commit()
                flash('Service updated successfully!', 'success')
                
        elif action == 'delete':
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first()
            if service:
                service.is_active = False
                db.session.commit()
                flash('Service deactivated!', 'success')
        
        elif action == 'activate':
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first()
            if service:
                service.is_active = True
                db.session.commit()
                flash('Service activated!', 'success')
        
        return redirect(url_for('manage_services'))
    
    # Get all services for this mentor
    services = Service.query.filter_by(mentor_id=current_user.id).order_by(Service.created_at.desc()).all()
    
    return render_template('manage_services.html', services=services)

@app.route('/mentor/bookings')
@login_required
@mentor_required
def mentor_bookings():
    my_bookings = Booking.query.filter_by(mentor_id=current_user.id).order_by(Booking.created_at.desc()).all()
    bookings_with_learners = []
    for booking in my_bookings:
        learner = User.query.get(booking.learner_id)
        bookings_with_learners.append({
            'booking': booking,
            'learner': learner
        })
    
    return render_template('mentor_bookings.html', bookings=bookings_with_learners)

@app.route('/mentor/calendar')
@login_required
@mentor_required
def mentor_calendar():
    # Get all booked slots
    bookings = Booking.query.filter_by(mentor_id=current_user.id).all()
    booked_slots = [{
        'time': b.slot_time,
        'date': b.booking_date.strftime('%Y-%m-%d') if b.booking_date else 'N/A',
        'service': b.service_name,
        'learner': User.query.get(b.learner_id).username if User.query.get(b.learner_id) else 'Unknown'
    } for b in bookings]
    
    return render_template('mentor_calendar.html', booked_slots=booked_slots)

@app.route('/mentor/payouts')
@login_required
@mentor_required
def mentor_payouts():
    # Calculate earnings
    completed_bookings = Booking.query.filter_by(
        mentor_id=current_user.id, 
        payment_status='success'
    ).all()
    
    total_earnings = sum([b.price or current_user.price for b in completed_bookings])
    pending_payout = total_earnings * 0.8  # Assuming 20% platform fee
    
    payout_history = Payment.query.filter_by(
        user_id=current_user.id,
        status='success'
    ).order_by(Payment.created_at.desc()).limit(10).all()
    
    return render_template('mentor_payouts.html', 
                         total_earnings=total_earnings,
                         pending_payout=pending_payout,
                         payout_history=payout_history)

@app.route('/mentor/profile', methods=['GET', 'POST'])
@login_required
@mentor_required
def mentor_profile():
    if request.method == 'POST':
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                image_path = save_profile_image(file, current_user.id)
                if image_path:
                    current_user.profile_image = image_path
        
        # Update mentor profile
        current_user.full_name = request.form.get('full_name')
        current_user.phone = request.form.get('phone')
        current_user.job_title = request.form.get('job_title')
        current_user.company = request.form.get('company')
        current_user.previous_company = request.form.get('previous_company')
        current_user.domain = request.form.get('domain')
        current_user.experience = request.form.get('experience')
        current_user.skills = request.form.get('skills')
        current_user.bio = request.form.get('bio')
        current_user.price = int(request.form.get('price')) if request.form.get('price') else 0
        current_user.availability = request.form.get('availability')
        current_user.facebook_url = request.form.get('facebook_url')
        current_user.instagram_url = request.form.get('instagram_url')
        current_user.youtube_url = request.form.get('youtube_url')
        current_user.linkedin_url = request.form.get('linkedin_url')
        current_user.success_rate = int(request.form.get('success_rate')) if request.form.get('success_rate') else 95
        current_user.response_rate = int(request.form.get('response_rate')) if request.form.get('response_rate') else 98
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('mentor_profile'))
    
    return render_template('mentor_profile.html')

# REGISTER ROUTE
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'learner':
            # Handle learner registration
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validation
            if not all([username, email, password, confirm_password]):
                flash('All fields are required', 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return render_template('register.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return render_template('register.html')
            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'danger')
                return render_template('register.html')
            
            # Create new learner
            user = User(username=username, email=email, role='learner')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(user):
                flash('Registration successful! Please check your email to verify your account.', 'success')
            else:
                flash('Registration successful! Please login to resend verification email.', 'warning')
            
            return redirect(url_for('login'))
            
        elif role == 'mentor':
            # Handle mentor registration
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('full_name')
            
            # Validation
            if not all([username, email, password, confirm_password, full_name]):
                flash('All required fields are missing', 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return render_template('register.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return render_template('register.html')
            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'danger')
                return render_template('register.html')
            
            # Create new mentor
            user = User(
                username=username, 
                email=email, 
                role='mentor',
                full_name=full_name,
                phone=request.form.get('phone'),
                job_title=request.form.get('job_title'),
                company=request.form.get('company'),
                previous_company=request.form.get('previous_company'),
                domain=request.form.get('domain'),
                experience=request.form.get('experience'),
                skills=request.form.get('skills'),
                bio=request.form.get('bio'),
                price=int(request.form.get('price')) if request.form.get('price') else 0,
                availability=request.form.get('availability'),
                is_verified=False
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(user):
                flash('Mentor application submitted! Please check your email to verify your account and wait for admin approval.', 'success')
            else:
                flash('Mentor application submitted! Please login to resend verification email and wait for admin approval.', 'warning')
            
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/enroll', methods=['GET', 'POST'])
def enroll():
    """Enrollment page for mentorship program"""
    if request.method == 'POST':
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        phone = request.form.get('phone')
        education = request.form.get('education')
        
        if not all([full_name, email, phone]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('enroll'))
        
        # Check if user is logged in
        if current_user.is_authenticated:
            user_id = current_user.id
        else:
            # Check if user exists with this email
            user = User.query.filter_by(email=email).first()
            if user:
                user_id = user.id
            else:
                # Create a temporary user record
                username = email.split('@')[0]
                counter = 1
                original_username = username
                while User.query.filter_by(username=username).first():
                    username = f"{original_username}_{counter}"
                    counter += 1
                
                user = User(
                    username=username,
                    email=email,
                    role='learner'
                )
                user.set_password('temp_' + secrets.token_hex(8))
                db.session.add(user)
                db.session.commit()
                user_id = user.id
        
        # Save enrollment record
        enrollment_data = {
            'full_name': full_name,
            'phone': phone,
            'education': education
        }
        
        enrollment = Enrollment(
            user_id=user_id,
            program_name='career_mentorship',
            payment_status='pending',
            payment_amount=499,
            additional_data=json.dumps(enrollment_data)
        )
        db.session.add(enrollment)
        db.session.commit()
        
        flash('Enrollment submitted successfully! Our team will contact you shortly.', 'success')
        return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('index'))
    
    return render_template('enroll.html')

# Update booking status
@app.route('/update-booking-status/<int:booking_id>', methods=['POST'])
@login_required
def update_booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check permissions
    if current_user.role == 'mentor' and booking.mentor_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    elif current_user.role == 'admin':
        pass
    else:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Confirmed', 'Completed', 'Cancelled']:
        booking.status = new_status
        db.session.commit()
        return jsonify({'success': True, 'message': 'Status updated'})
    
    return jsonify({'success': False, 'message': 'Invalid status'}), 400

# HEALTH CHECK
@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        # Check if admin user exists
        admin_exists = User.query.filter_by(role='admin').first() is not None
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'admin_user': admin_exists,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Initialize database
with app.app_context():
    try:
        # Create tables if they don't exist
        db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email=os.environ.get('ADMIN_EMAIL', 'admin@clearq.in'),
                role='admin',
                is_email_verified=True,
                is_verified=True
            )
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created")
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

if __name__ == '__main__':
    # Production settings
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    app.run(
        host=os.environ.get('FLASK_HOST', '0.0.0.0'),
        port=int(os.environ.get('FLASK_PORT', 5000)),
        debug=debug_mode,
        threaded=True
    )
