import os
import json
import random
import re
import uuid
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from itsdangerous import URLSafeTimedSerializer
import razorpay
import requests

# --- FORCE FLASK TO FIND TEMPLATES ---
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
app = Flask(__name__, template_folder=template_dir)
# -------------------------------------

app.config['SECRET_KEY'] = 'clearq-secret-key-change-this-in-prod'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'clearq.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'zip', 'rar'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')

# Payment Gateway Configuration (Razorpay)
app.config['RAZORPAY_KEY_ID'] = os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_KEY_ID')
app.config['RAZORPAY_KEY_SECRET'] = os.environ.get('RAZORPAY_KEY_SECRET', 'YOUR_KEY_SECRET')

# Google Meet/Calendar Integration (Optional)
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Razorpay
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

# Initialize token serializer for email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Helper function for file uploads
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_profile_image(file, user_id):
    if file and file.filename != '' and allowed_file(file.filename):
        # Create unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"user_{user_id}_{timestamp}.{ext}"
        
        # Ensure upload folder exists
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_images')
        os.makedirs(upload_path, exist_ok=True)
        
        filepath = os.path.join(upload_path, filename)
        file.save(filepath)
        
        return f'uploads/profile_images/{filename}'
    return None

def save_digital_product(file, user_id, service_id):
    if file and file.filename != '' and allowed_file(file.filename):
        # Create unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"digital_product_{user_id}_{service_id}_{timestamp}.{ext}"
        
        # Ensure upload folder exists
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'digital_products')
        os.makedirs(upload_path, exist_ok=True)
        
        filepath = os.path.join(upload_path, filename)
        file.save(filepath)
        
        return f'uploads/digital_products/{filename}'
    return None

# Helper function to generate URL-friendly slugs
def generate_slug(text):
    """Generate a URL-friendly slug from text"""
    slug = text.lower()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[-\s]+', '-', slug)
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
    return s.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

def generate_reset_token(email):
    return s.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='password-reset', max_age=expiration)
    except:
        return False
    return email

def send_email(to, subject, body, html_body=None):
    """Send email using external service (Mailgun, SendGrid, etc.)"""
    # In production, use a proper email service
    # For now, we'll just print to console
    print(f"\n=== EMAIL TO: {to} ===")
    print(f"SUBJECT: {subject}")
    print(f"BODY: {body}")
    if html_body:
        print(f"HTML: {html_body}")
    print("=== END EMAIL ===\n")
    
    # Example for Mailgun (uncomment and configure)
    # mailgun_api_key = os.environ.get('MAILGUN_API_KEY')
    # mailgun_domain = os.environ.get('MAILGUN_DOMAIN')
    # if mailgun_api_key and mailgun_domain:
    #     return requests.post(
    #         f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
    #         auth=("api", mailgun_api_key),
    #         data={
    #             "from": f"ClearQ <noreply@{mailgun_domain}>",
    #             "to": [to],
    #             "subject": subject,
    #             "text": body,
    #             "html": html_body
    #         }
    #     )
    
    return True

def send_verification_email(user):
    token = generate_verification_token(user.email)
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = 'Verify Your Email - ClearQ'
    body = f'''Please click the following link to verify your email:
{verification_url}

If you did not create an account, please ignore this email.
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
    html_body = f'''
    <h3>Booking Confirmed! 🎉</h3>
    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h4>Booking Details:</h4>
        <p><strong>Service:</strong> {booking.service_name}</p>
        <p><strong>Mentor:</strong> {mentor.full_name if mentor else 'Unknown'}</p>
        <p><strong>Date:</strong> {booking.booking_date.strftime("%B %d, %Y") if booking.booking_date else 'To be scheduled'}</p>
        <p><strong>Time:</strong> {booking.slot_time}</p>
        <p><strong>Price:</strong> ₹{booking.price or 0}</p>
        <p><strong>Status:</strong> {booking.status}</p>
    </div>
    
    <div style="background-color: #e8f4fd; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h4>Meeting Information:</h4>
        <p><strong>Meeting Link:</strong> {booking.meeting_link or 'Will be provided before the session'}</p>
        <p><strong>Meeting Platform:</strong> {booking.meeting_platform or 'Google Meet'}</p>
        {booking.meeting_id and f'<p><strong>Meeting ID:</strong> {booking.meeting_id}</p>'}
        {booking.meeting_password and f'<p><strong>Password:</strong> {booking.meeting_password}</p>'}
    </div>
    
    <p>You can view and manage your bookings from your <a href="{url_for('dashboard', _external=True)}">dashboard</a>.</p>
    
    <p>Thank you for choosing ClearQ!</p>
    '''
    
    return send_email(user.email, subject, body, html_body)

def send_digital_product_access_email(user, service):
    """Send digital product access email"""
    subject = f'Digital Product Access - {service.name}'
    body = f'''You now have access to the digital product: {service.name}

Product Details:
- Name: {service.name}
- Description: {service.description}
- Access Link: {service.digital_product_link or 'Download from your dashboard'}

You can access this product from your dashboard at any time.

Thank you for your purchase!
'''
    html_body = f'''
    <h3>Digital Product Access Granted! 📦</h3>
    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
        <h4>Product Details:</h4>
        <p><strong>Name:</strong> {service.name}</p>
        <p><strong>Description:</strong> {service.description}</p>
        <p><strong>Access:</strong> {service.digital_product_link or 'Download from your dashboard'}</p>
    </div>
    
    <p>You can access this product from your <a href="{url_for('my_digital_products', _external=True)}">Digital Products</a> page at any time.</p>
    
    <a href="{url_for('my_digital_products', _external=True)}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0;">Access Your Digital Products</a>
    
    <p>Thank you for your purchase!</p>
    '''
    
    return send_email(user.email, subject, body, html_body)

# Meeting link generation
def generate_meeting_link(booking):
    """Generate a meeting link for the booking"""
    # For simplicity, we'll create a unique meeting ID
    # In production, you might integrate with Google Calendar API or Zoom API
    meeting_id = str(uuid.uuid4())[:8]
    
    # Create a simple meeting link structure
    meeting_link = f"https://meet.google.com/new?hs=191&authuser=0"  # Generic Google Meet link
    
    # Alternatively, use Jitsi Meet (open source alternative)
    # meeting_link = f"https://meet.jit.si/ClearQ-{meeting_id}"
    
    booking.meeting_link = meeting_link
    booking.meeting_id = meeting_id
    booking.meeting_platform = 'google_meet'
    
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
        print(f"Razorpay error: {e}")
        return None

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='learner')  # 'learner', 'mentor', 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    
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
    review_count = db.Column(db.Integer, default=24)
    profile_views = db.Column(db.Integer, default=0)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False)  # URL-friendly version of name
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
    
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    mentor = db.relationship('User', backref='mentor_services')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    program_name = db.Column(db.String(100), default='career_mentorship')
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    payment_amount = db.Column(db.Integer, default=499)
    status = db.Column(db.String(20), default='active')  # active, completed, cancelled
    additional_data = db.Column(db.Text)  # Store form data as JSON
    
    user = db.relationship('User', backref='enrollments')

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    learner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    service_name = db.Column(db.String(100))
    slot_time = db.Column(db.String(50))
    booking_date = db.Column(db.Date, nullable=True)  # Date of booking
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    price = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Meeting fields
    meeting_link = db.Column(db.String(500), nullable=True)
    meeting_platform = db.Column(db.String(50), nullable=True)  # 'google_meet', 'zoom', 'custom'
    meeting_id = db.Column(db.String(100), nullable=True)
    meeting_password = db.Column(db.String(100), nullable=True)
    meeting_notes = db.Column(db.Text, nullable=True)
    is_session_completed = db.Column(db.Boolean, default=False)
    session_feedback = db.Column(db.Text, nullable=True)
    session_rating = db.Column(db.Integer, nullable=True)
    
    # Payment fields
    payment_id = db.Column(db.String(100), nullable=True)
    payment_status = db.Column(db.String(20), default='pending')  # pending, success, failed
    razorpay_order_id = db.Column(db.String(100), nullable=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)

    mentor = db.relationship('User', foreign_keys=[mentor_id])
    learner = db.relationship('User', foreign_keys=[learner_id])
    service = db.relationship('Service')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    product_type = db.Column(db.String(50), default='1:1 call')  # '1:1 call', 'Digital Product', 'Webinar', 'Combo'
    duration = db.Column(db.String(50), nullable=True)  # '30 mins', '1 hour', 'Downloadable'
    price = db.Column(db.Integer, nullable=False)
    tag = db.Column(db.String(20), nullable=True)  # 'Best Seller', 'Recommended', 'Popular'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Digital product fields
    digital_product_link = db.Column(db.String(500), nullable=True)
    digital_product_file = db.Column(db.String(500), nullable=True)
    
    mentor = db.relationship('User', backref='products')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    learner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    learner = db.relationship('User', foreign_keys=[learner_id])
    product = db.relationship('Product')
    service = db.relationship('Service')

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollment.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    
    amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    currency = db.Column(db.String(3), default='INR')
    razorpay_order_id = db.Column(db.String(100), nullable=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    
    status = db.Column(db.String(20), default='pending')  # pending, success, failed
    payment_method = db.Column(db.String(50), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='payments')
    booking = db.relationship('Booking', backref='payment_record')
    enrollment = db.relationship('Enrollment')
    service = db.relationship('Service')
    product = db.relationship('Product')

class DigitalProductAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payment.id'), nullable=True)
    access_granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    downloads_count = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', backref='digital_accesses')
    service = db.relationship('Service', backref='accesses')
    product = db.relationship('Product')
    payment = db.relationship('Payment')

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
        print(f"AI Error: {e}")
        return []

@app.template_filter('escapejs')
def escapejs_filter(value):
    """Escape strings for JavaScript - similar to Django's escapejs"""
    if value is None:
        return ''
    
    # Basic escaping for JavaScript strings
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

# --- DATABASE RESET ROUTE (FOR DEVELOPMENT ONLY) ---
@app.route('/reset-db')
def reset_database():
    """Drop and recreate all tables (DEVELOPMENT ONLY)"""
    try:
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(
            username='admin', 
            email='admin@clearq.in', 
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        
        return """
        <h1>Database Reset Successful!</h1>
        <p>All tables have been dropped and recreated with the current schema.</p>
        <p><a href='/'>Go to Home</a></p>
        <p><a href='/add-sample-mentors'>Add Sample Mentors</a></p>
        """
    except Exception as e:
        return f"<h1>Error resetting database:</h1><p>{str(e)}</p>"

# --- DEBUG ROUTES ---
@app.route('/debug-user/<int:user_id>')
def debug_user(user_id):
    """Debug a specific user"""
    user = User.query.get(user_id)
    
    if not user:
        return f"<h1>User ID {user_id} not found</h1>"
    
    result = f"""
    <h1>Debug User ID {user_id}</h1>
    <table border="1">
        <tr><td>ID</td><td>{user.id}</td></tr>
        <tr><td>Username</td><td>{user.username}</td></tr>
        <tr><td>Email</td><td>{user.email}</td></tr>
        <tr><td>Role</td><td>{user.role}</td></tr>
        <tr><td>Full Name</td><td>{user.full_name or 'N/A'}</td></tr>
        <tr><td>Domain</td><td>{user.domain or 'N/A'}</td></tr>
        <tr><td>Company</td><td>{user.company or 'N/A'}</td></tr>
        <tr><td>Verified</td><td>{user.is_verified}</td></tr>
        <tr><td>Created At</td><td>{user.created_at}</td></tr>
    </table>
    
    <h2>Profile URL</h2>
    <p><a href="/mentor/{user.username}">/mentor/{user.username}</a></p>
    
    <h2>All Users</h2>
    <table border="1">
        <tr>
            <th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Verified</th>
        </tr>
    """
    
    all_users = User.query.all()
    for u in all_users:
        result += f"""
        <tr>
            <td>{u.id}</td>
            <td>{u.username}</td>
            <td>{u.email}</td>
            <td>{u.role}</td>
            <td>{u.is_verified}</td>
        </tr>
        """
    
    result += "</table>"
    return result

@app.route('/force-db-reset')
def force_db_reset():
    """FORCE reset database - DANGER: This will DELETE ALL DATA!"""
    try:
        print("Dropping all tables...")
        db.drop_all()
        print("Creating all tables with new schema...")
        db.create_all()
        
        # Create admin user
        admin = User(
            username='admin', 
            email='admin@clearq.in', 
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        
        return """
        <h1>✅ Database Reset Complete!</h1>
        <p>All tables have been dropped and recreated with the current schema.</p>
        <p>Missing columns like 'previous_company' have been added.</p>
        <p><a href='/'>Go to Home</a> | <a href='/add-sample-mentors'>Add Sample Mentors</a></p>
        """
    except Exception as e:
        return f"<h1>❌ Error:</h1><pre>{str(e)}</pre>"

@app.route('/check-data')
def check_data():
    """Check what data exists in database"""
    mentors = User.query.filter_by(role='mentor').all()
    verified_mentors = User.query.filter_by(role='mentor', is_verified=True).all()
    
    result = f"""
    <h2>Database Status</h2>
    <p>Total mentors: {len(mentors)}</p>
    <p>Verified mentors: {len(verified_mentors)}</p>
    <p>Total users: {User.query.count()}</p>
    <hr>
    """
    
    if mentors:
        result += "<h3>All Mentors:</h3>"
        for mentor in mentors:
            result += f"""
            <div style='border:1px solid #ccc; padding:10px; margin:10px;'>
                <strong>{mentor.username}</strong><br>
                Email: {mentor.email}<br>
                Verified: {mentor.is_verified}<br>
                Domain: {mentor.domain or 'Not set'}<br>
                Company: {mentor.company or 'Not set'}<br>
                Previous Company: {mentor.previous_company or 'Not set'}<br>
                Created: {mentor.created_at}
            </div>
            """
    else:
        result += "<p>No mentors found. You need to register as a mentor first.</p>"
        
    return result

@app.route('/check-username/<username>')
def check_username(username):
    """Check if a username exists"""
    user = User.query.filter_by(username=username).first()
    
    if user:
        return f"""
        <h1>User '{username}' Found</h1>
        <p>ID: {user.id}</p>
        <p>Email: {user.email}</p>
        <p>Role: {user.role}</p>
        <p>Verified: {user.is_verified}</p>
        <p><a href='/mentor/{username}'>Go to profile: /mentor/{username}</a></p>
        <p><a href='/{username}'>Test old URL: /{username}</a></p>
        """
    else:
        return f"""
        <h1>User '{username}' Not Found</h1>
        <p>No user with username '{username}' exists in the database.</p>
        <p><a href='/check-data'>See all users</a></p>
        """

@app.route('/add-sample-mentors')
def add_sample_mentors():
    """Add sample mentors for testing with enhanced data"""
    
    sample_mentors = [
        {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password': 'test123',
            'full_name': 'John Doe',
            'domain': 'Data Science',
            'company': 'Google',
            'previous_company': 'Microsoft',
            'job_title': 'Senior Data Scientist',
            'experience': '5 years',
            'skills': 'Python, Machine Learning, SQL, TensorFlow, PyTorch, Data Analysis',
            'services': 'Resume Review, Mock Interview, Career Guidance',
            'bio': 'I help aspiring data scientists land their dream jobs at FAANG companies. With 5+ years at Google and 3 years at Microsoft, I know exactly what hiring managers look for. I\'ve conducted over 200 mock interviews and helped 50+ students get into top tech companies.',
            'price': 1500,
            'availability': 'Weekdays 6-9 PM',
            'is_verified': True,
            'rating': 4.9,
            'review_count': 42,
            'success_rate': 96,
            'response_rate': 99
        },
        {
            'username': 'jane_smith',
            'email': 'jane@example.com',
            'password': 'test123',
            'full_name': 'Jane Smith',
            'domain': 'Product Management',
            'company': 'Microsoft',
            'previous_company': 'Amazon',
            'job_title': 'Senior Product Manager',
            'experience': '7 years',
            'skills': 'Product Strategy, Agile, User Research, Roadmapping, A/B Testing',
            'services': 'Mock Interview, Product Case Studies, Career Transition',
            'bio': 'Ex-Microsoft PM with 7+ years experience. I specialize in helping engineers transition to product management roles. I\'ve successfully mentored 30+ engineers into PM roles at top companies including Google, Meta, and Amazon.',
            'price': 2000,
            'availability': 'Weekends 10 AM - 6 PM',
            'is_verified': True,
            'rating': 4.8,
            'review_count': 35,
            'success_rate': 94,
            'response_rate': 97
        },
        {
            'username': 'alex_wong',
            'email': 'alex@example.com',
            'password': 'test123',
            'full_name': 'Alex Wong',
            'domain': 'Software Engineering',
            'company': 'Amazon',
            'previous_company': 'Google',
            'job_title': 'Senior SDE',
            'experience': '8 years',
            'skills': 'Java, System Design, AWS, Distributed Systems, Microservices, Docker',
            'services': 'Coding Interview Prep, System Design, Resume Review',
            'bio': 'Senior SDE at Amazon with expertise in large-scale distributed systems. I help engineers crack coding interviews at top tech companies. With 8+ years of experience and 500+ mock interviews conducted, I know what it takes to succeed in technical interviews.',
            'price': 1800,
            'availability': 'Mon-Fri 7-10 PM',
            'is_verified': True,
            'rating': 4.95,
            'review_count': 58,
            'success_rate': 98,
            'response_rate': 100
        },
        {
            'username': 'sara_johnson',
            'email': 'sara@example.com',
            'password': 'test123',
            'full_name': 'Sara Johnson',
            'domain': 'UX Design',
            'company': 'Meta',
            'previous_company': 'Apple',
            'job_title': 'Lead UX Designer',
            'experience': '6 years',
            'skills': 'Figma, User Research, Prototyping, Design Systems, UX Writing',
            'services': 'Portfolio Review, Design Critique, Career Coaching',
            'bio': 'Lead UX Designer at Meta with 6+ years of experience. I help designers build compelling portfolios and prepare for design interviews. I\'ve mentored 40+ designers who now work at companies like Google, Airbnb, and Netflix.',
            'price': 1600,
            'availability': 'Tue-Thu 5-9 PM',
            'is_verified': True,
            'rating': 4.7,
            'review_count': 28,
            'success_rate': 92,
            'response_rate': 95
        }
    ]
    
    added_count = 0
    for data in sample_mentors:
        # Check if mentor already exists
        if not User.query.filter_by(email=data['email']).first():
            mentor = User(
                username=data['username'],
                email=data['email'],
                role='mentor',
                full_name=data['full_name'],
                domain=data['domain'],
                company=data['company'],
                previous_company=data['previous_company'],
                job_title=data['job_title'],
                experience=data['experience'],
                skills=data['skills'],
                services=data['services'],
                bio=data['bio'],
                price=data['price'],
                availability=data['availability'],
                is_verified=data['is_verified'],
                rating=data['rating'],
                review_count=data['review_count'],
                success_rate=data['success_rate'],
                response_rate=data['response_rate'],
                is_email_verified=True  # Sample mentors have verified emails
            )
            mentor.set_password(data['password'])
            db.session.add(mentor)
            added_count += 1
    
    db.session.commit()
    
    # Add sample services for these mentors with detailed descriptions
    sample_services = [
        {
            'mentor_username': 'john_doe',
            'name': 'Resume Review',
            'description': 'Detailed feedback on your data science resume',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>ATS optimization check</li><li>Formatting and structure review</li><li>Content improvement suggestions</li><li>Keyword optimization for data science roles</li><li>Industry-specific best practices</li></ul>',
            'price': 500,
            'duration': '24-hour delivery',
            'service_type': 'digital_product',
            'digital_product_link': 'https://drive.google.com/sample-resume-guide',
            'digital_product_name': 'Ultimate Data Science Resume Guide',
            'digital_product_description': 'Complete guide with templates and examples'
        },
        {
            'mentor_username': 'john_doe',
            'name': 'Mock Interview',
            'description': '1-hour technical mock interview',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Technical questions practice</li><li>Behavioral interview preparation</li><li>Communication skills feedback</li><li>Problem-solving approach evaluation</li><li>Post-interview debrief and improvement plan</li></ul>',
            'price': 1500,
            'duration': '1 hour',
            'service_type': 'consultation'
        },
        {
            'mentor_username': 'john_doe',
            'name': 'Career Guidance Session',
            'description': '30-min career path discussion',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Personalized career roadmap</li><li>Skill gap analysis</li><li>Industry insights and trends</li><li>Networking strategies</li><li>Actionable next steps</li></ul>',
            'price': 800,
            'duration': '30 mins',
            'service_type': 'consultation'
        },
        {
            'mentor_username': 'jane_smith',
            'name': 'Product Case Study Review',
            'description': 'In-depth review of product case studies',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Case study structure review</li><li>Framework application guidance</li><li>Presentation skills feedback</li><li>Industry-specific insights</li><li>Mock case study practice</li></ul>',
            'price': 1200,
            'duration': '45 mins',
            'service_type': 'both',
            'digital_product_link': 'https://drive.google.com/product-case-study-templates',
            'digital_product_name': 'Product Case Study Templates',
            'digital_product_description': '10+ templates for product management interviews'
        },
    ]
    
    for service_data in sample_services:
        mentor = User.query.filter_by(username=service_data['mentor_username']).first()
        if mentor and not Service.query.filter_by(mentor_id=mentor.id, name=service_data['name']).first():
            service = Service(
                mentor_id=mentor.id,
                name=service_data['name'],
                slug=generate_slug(service_data['name']),
                description=service_data['description'],
                detailed_description=service_data['detailed_description'],
                price=service_data['price'],
                duration=service_data['duration'],
                service_type=service_data.get('service_type', 'consultation'),
                digital_product_link=service_data.get('digital_product_link'),
                digital_product_name=service_data.get('digital_product_name'),
                digital_product_description=service_data.get('digital_product_description')
            )
            db.session.add(service)
    
    # Add sample products for backward compatibility
    sample_products = [
        {
            'mentor_username': 'john_doe',
            'name': 'Data Science Interview Guide',
            'description': 'Complete guide with 100+ interview questions and solutions',
            'product_type': 'Digital Product',
            'duration': 'Downloadable',
            'price': 999,
            'tag': 'Best Seller',
            'digital_product_link': 'https://drive.google.com/data-science-guide'
        }
    ]
    
    for product_data in sample_products:
        mentor = User.query.filter_by(username=product_data['mentor_username']).first()
        if mentor and not Product.query.filter_by(mentor_id=mentor.id, name=product_data['name']).first():
            product = Product(
                mentor_id=mentor.id,
                name=product_data['name'],
                description=product_data['description'],
                product_type=product_data['product_type'],
                duration=product_data['duration'],
                price=product_data['price'],
                tag=product_data['tag'],
                digital_product_link=product_data.get('digital_product_link')
            )
            db.session.add(product)
    
    db.session.commit()
    
    return f"Added {added_count} sample mentors with services! <a href='/explore'>Go to Explore</a>"

# --- NEW FEATURE ROUTES ---

# 1. EMAIL AUTHENTICATION ROUTES
@app.route('/verify-email/<token>')
@login_required
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
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
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# 2. PAYMENT GATEWAY ROUTES
@app.route('/create-payment/<int:booking_id>')
@login_required
def create_payment(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if user is authorized
    if booking.learner_id != current_user.id:
        flash('Unauthorized access.', 'danger')
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
def payment_success():
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')
    
    # Verify payment signature
    params_dict = {
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_order_id': razorpay_order_id,
        'razorpay_signature': razorpay_signature
    }
    
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # Find booking by order ID
        booking = Booking.query.filter_by(razorpay_order_id=razorpay_order_id).first()
        
        if booking:
            # Update booking
            booking.razorpay_payment_id = razorpay_payment_id
            booking.razorpay_signature = razorpay_signature
            booking.payment_status = 'success'
            booking.status = 'Paid'
            
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
                amount=booking.price * 100,
                razorpay_order_id=razorpay_order_id,
                razorpay_payment_id=razorpay_payment_id,
                razorpay_signature=razorpay_signature,
                status='success'
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
        
    except Exception as e:
        print(f"Payment verification failed: {e}")
        flash('Payment verification failed. Please contact support.', 'danger')
    
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

# 3. MEETING LINK ROUTES
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
    if not booking.meeting_link and booking.status == 'Paid':
        generate_meeting_link(booking)
        db.session.commit()
    
    return render_template('meeting.html', booking=booking)

@app.route('/api/start-meeting/<int:booking_id>', methods=['POST'])
@login_required
def start_meeting(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Only mentor can start the meeting
    if current_user.id != booking.mentor_id and current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Generate meeting link if not exists
    if not booking.meeting_link:
        generate_meeting_link(booking)
        db.session.commit()
    
    return jsonify({
        'success': True,
        'meeting_link': booking.meeting_link,
        'meeting_id': booking.meeting_id
    })

@app.route('/complete-session/<int:booking_id>', methods=['POST'])
@login_required
def complete_session(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    if current_user.id != booking.mentor_id and current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    booking.is_session_completed = True
    booking.status = 'Completed'
    db.session.commit()
    
    flash('Session marked as completed!', 'success')
    return redirect(url_for('dashboard'))

# 4. DIGITAL PRODUCT ROUTES
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

# --- EXISTING ROUTES (UPDATED) ---

@app.route('/')
def index():
    return render_template('index.html')

# --- BACKWARD COMPATIBILITY for old /username URLs ---
@app.route('/<username>')
def redirect_old_profile(username):
    """Redirect old /username URLs to new /mentor/username URLs"""
    # Check if it's a file extension we should ignore
    if '.' in username and username.split('.')[-1] in ['ico', 'png', 'jpg', 'css', 'js', 'json']:
        return '', 404
    
    # Redirect to new mentor profile URL
    return redirect(url_for('mentor_public_profile', username=username))

# --- Static file handlers to prevent conflicts with dynamic routes ---
@app.route('/favicon.ico')
def favicon():
    return '', 404  # Return 404 or serve actual favicon if available

@app.route('/robots.txt')
def robots():
    return '', 404

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
                print(f"AI error: {e}")
                # Fallback: simple text matching
                mentors = User.query.filter_by(role='mentor', is_verified=True).all()
                for mentor in mentors:
                    mentor_text = f"{mentor.domain or ''} {mentor.bio or ''} {mentor.skills or ''}".lower()
                    if query.lower() in mentor_text:
                        recommendations.append(mentor)
    
    # Get all verified mentors
    all_mentors = User.query.filter_by(role='mentor', is_verified=True).all()
    
    # Get top companies mentors
    top_companies = ['Google', 'Microsoft', 'Amazon', 'Meta', 'Apple', 'Netflix']
    top_mentors = [m for m in all_mentors if m.company in top_companies]
    
    return render_template('mentors.html', 
                         mentors=all_mentors, 
                         recommendations=recommendations, 
                         query=query,
                         top_mentors=top_mentors)

# Handle URLs with username-ID format (for backward compatibility with old share links)
@app.route('/mentor/<username>-<int:id>')
def mentor_profile_with_id(username, id):
    """
    Handle URLs with both username and ID like /mentor/username-id
    This supports old share links while redirecting to clean URLs
    """
    # Check if user exists with this username and ID
    user = User.query.filter_by(username=username, id=id).first()
    
    if user:
        # User exists, redirect to clean username-only URL
        return redirect(url_for('mentor_public_profile', username=username))
    else:
        # User not found with this combination, try username only
        return redirect(url_for('mentor_public_profile', username=username))

# Username-based profile routes
@app.route('/mentor/<username>')
def mentor_public_profile(username):
    # Try to find the user
    mentor = User.query.filter_by(username=username).first()
    
    # If not found or not a mentor
    if not mentor:
        return f"""
        <h1>User '{username}' not found</h1>
        <p><a href='/explore'>Back to Explore</a></p>
        <p>Debug: <a href='/check-username/{username}'>Check username</a></p>
        """, 404
    
    if mentor.role != 'mentor':
        return f"""
        <h1>User '{username}' is not a mentor</h1>
        <p>Role: {mentor.role}</p>
        <p><a href='/explore'>Back to Explore</a></p>
        """, 404
    
    # Increment profile views
    mentor.profile_views = (mentor.profile_views or 0) + 1
    db.session.commit()
    
    # Get mentor's services
    services = Service.query.filter_by(mentor_id=mentor.id, is_active=True).all()
    
    # Get mentor's products (for backward compatibility)
    products = Product.query.filter_by(mentor_id=mentor.id, is_active=True).all()
    
    # Get reviews
    reviews = Review.query.filter_by(mentor_id=mentor.id).all()
    
    # Get available dates for quick booking
    available_dates = get_available_dates(mentor.id, days_ahead=7)
    
    # Categorize products by type
    product_types = {}
    for product in products:
        if product.product_type not in product_types:
            product_types[product.product_type] = []
        product_types[product.product_type].append(product)
    
    # Calculate total sessions
    total_sessions = Booking.query.filter_by(mentor_id=mentor.id).count()
    
    return render_template('mentor_public_profile.html',
                         mentor=mentor,
                         services=services,
                         products=products,
                         product_types=product_types,
                         reviews=reviews,
                         total_sessions=total_sessions,
                         available_dates=available_dates)

# Service detail route
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

# API endpoint for getting time slots
@app.route('/api/get-time-slots/<int:mentor_id>', methods=['POST'])
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
        return jsonify({'success': False, 'error': str(e)}), 500

# Book service with date
@app.route('/book-service/<int:service_id>', methods=['POST'])
@login_required
def book_service(service_id):
    service = Service.query.get_or_404(service_id)
    mentor = User.query.get(service.mentor_id)
    
    if current_user.role == 'mentor':
        flash('Mentors cannot book their own services')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    # Check if it's a digital product and user already has access
    if service.service_type == 'digital_product' and service.access_after_payment:
        # Check if user already has access
        access = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            service_id=service.id,
            is_active=True
        ).first()
        
        if access:
            flash('You already have access to this digital product.', 'info')
            return redirect(url_for('my_digital_products'))
    
    # For digital products without consultation, redirect to payment
    if service.service_type == 'digital_product' and not service.service_type == 'both':
        return redirect(url_for('create_service_payment', service_id=service.id))
    
    # For consultation or both, proceed with booking
    slot = request.form.get('slot')
    date_str = request.form.get('date')
    notes = request.form.get('notes', '')
    
    if not slot and service.service_type != 'digital_product':
        flash('Please select a time slot')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    if not date_str and service.service_type != 'digital_product':
        flash('Please select a date')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    # Convert date string to date object
    booking_date = None
    if date_str:
        try:
            booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format')
            return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
        
        # Check if slot is already booked
        existing_booking = Booking.query.filter_by(
            mentor_id=service.mentor_id,
            booking_date=booking_date,
            slot_time=slot
        ).first()
        
        if existing_booking:
            flash('This time slot is already booked. Please select another time.')
            return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
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

# Product booking/purchase
@app.route('/book-product/<int:product_id>', methods=['POST'])
@login_required
def book_product(product_id):
    product = Product.query.get_or_404(product_id)
    mentor = User.query.get(product.mentor_id)
    
    if product.product_type in ['1:1 call', 'Webinar']:
        slot = request.form.get('slot')
        
        # Create booking
        booking = Booking(
            mentor_id=product.mentor_id,
            learner_id=current_user.id,
            service_name=product.name,
            slot_time=slot,
            price=product.price,
            status='Pending Payment'
        )
        db.session.add(booking)
        db.session.commit()
        
        return redirect(url_for('create_payment', booking_id=booking.id))
    else:
        # Handle digital product purchase
        # Check if user already has access
        access = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            product_id=product.id,
            is_active=True
        ).first()
        
        if access:
            flash('You already have access to this digital product.', 'info')
            return redirect(url_for('my_digital_products'))
        
        # Create booking for payment tracking
        booking = Booking(
            mentor_id=product.mentor_id,
            learner_id=current_user.id,
            service_name=product.name,
            price=product.price,
            status='Pending Payment'
        )
        db.session.add(booking)
        db.session.commit()
        
        return redirect(url_for('create_payment', booking_id=booking.id))

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
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!')
            
            # Check if email is verified
            if not user.is_email_verified:
                flash('Please verify your email address for full access.', 'warning')
            
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
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
        
        # Add additional mentor stats
        total_bookings = len(my_bookings)
        pending_bookings = len([b for b in my_bookings if b.status in ['Pending', 'Pending Payment']])
        completed_bookings = len([b for b in my_bookings if b.status == 'Completed'])
        revenue = sum([b.price or current_user.price for b in my_bookings if b.payment_status == 'success'])
        
        # Get upcoming meetings
        today = datetime.now().date()
        upcoming_meetings = [b for b in my_bookings if b.booking_date and b.booking_date >= today and b.status == 'Paid']
        
        return render_template('dashboard.html', 
                             bookings=bookings_with_learners, 
                             type='mentor',
                             total_bookings=total_bookings,
                             pending_bookings=pending_bookings,
                             completed_bookings=completed_bookings,
                             revenue=revenue,
                             services_count=services_count,
                             upcoming_meetings=upcoming_meetings[:5])
        
    else:  # Learner
        my_bookings = Booking.query.filter_by(learner_id=current_user.id).all()
        bookings_with_mentors = []
        for booking in my_bookings:
            mentor = User.query.get(booking.mentor_id)
            bookings_with_mentors.append({
                'booking': booking,
                'mentor': mentor
            })
        # Add enrollment info for learner
        enrollment = Enrollment.query.filter_by(user_id=current_user.id).first()
        
        # Get digital products count
        digital_products_count = DigitalProductAccess.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).count()
        
        # Get upcoming meetings
        today = datetime.now().date()
        upcoming_meetings = [b for b in my_bookings if b.booking_date and b.booking_date >= today and b.status == 'Paid']
        
        return render_template('dashboard.html', 
                             bookings=bookings_with_mentors, 
                             type='learner',
                             enrollment=enrollment,
                             digital_products_count=digital_products_count,
                             upcoming_meetings=upcoming_meetings[:5])

@app.route('/verify/<int:id>')
@login_required
def verify_mentor(id):
    if current_user.role != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('dashboard'))
    
    mentor = User.query.get(id)
    if not mentor:
        flash('Mentor not found')
        return redirect(url_for('dashboard'))
    
    if mentor.role != 'mentor':
        flash('User is not a mentor')
        return redirect(url_for('dashboard'))
    
    mentor.is_verified = True
    db.session.commit()
    flash(f'{mentor.username} has been verified!')
    return redirect(url_for('dashboard'))

@app.route('/reject-mentor/<int:id>', methods=['POST'])
@login_required
def reject_mentor(id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    mentor = User.query.get(id)
    if not mentor:
        return jsonify({'success': False, 'message': 'Mentor not found'}), 404
    
    if mentor.role != 'mentor':
        return jsonify({'success': False, 'message': 'User is not a mentor'}), 400
    
    # Delete the mentor application (or mark as rejected)
    db.session.delete(mentor)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Mentor application rejected'})

# Product management for mentors
@app.route('/mentor/products', methods=['GET', 'POST'])
@login_required
def mentor_products():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
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
        flash('Product added successfully!')
        return redirect(url_for('mentor_products'))
    
    # Get mentor's products
    products = Product.query.filter_by(mentor_id=current_user.id).all()
    return render_template('mentor_products.html', products=products)

# Service management for mentors (UPDATED FOR DIGITAL PRODUCTS)
@app.route('/mentor/manage-services', methods=['GET', 'POST'])
@login_required
def manage_services():
    if current_user.role != 'mentor':
        flash('Only mentors can access this page')
        return redirect(url_for('dashboard'))
    
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
                    digital_product_file = save_digital_product(file, current_user.id, 0)  # 0 for new service
            
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
            flash('Service added successfully!')
            
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
                flash('Service updated successfully!')
                
        elif action == 'delete':
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first()
            if service:
                service.is_active = False
                db.session.commit()
                flash('Service deactivated!')
        
        elif action == 'activate':
            service_id = request.form.get('service_id')
            service = Service.query.filter_by(id=service_id, mentor_id=current_user.id).first()
            if service:
                service.is_active = True
                db.session.commit()
                flash('Service activated!')
        
        return redirect(url_for('manage_services'))
    
    # Get all services for this mentor
    services = Service.query.filter_by(mentor_id=current_user.id).order_by(Service.created_at.desc()).all()
    
    return render_template('manage_services.html', services=services)

# New routes for mentor dashboard sections
@app.route('/mentor/bookings')
@login_required
def mentor_bookings():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
    my_bookings = Booking.query.filter_by(mentor_id=current_user.id).order_by(Booking.created_at.desc()).all()
    bookings_with_learners = []
    for booking in my_bookings:
        learner = User.query.get(booking.learner_id)
        bookings_with_learners.append({
            'booking': booking,
            'learner': learner
        })
    
    return render_template('mentor_bookings.html', bookings=bookings_with_learners)

@app.route('/mentor/services', methods=['GET', 'POST'])
@login_required
def mentor_services():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Update mentor services
        current_user.services = request.form.get('services')
        current_user.price = int(request.form.get('price')) if request.form.get('price') else 0
        current_user.availability = request.form.get('availability')
        db.session.commit()
        flash('Services updated successfully!')
        return redirect(url_for('mentor_services'))
    
    return render_template('mentor_services.html')

@app.route('/mentor/calendar')
@login_required
def mentor_calendar():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
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
def mentor_payouts():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
    # Calculate earnings
    completed_bookings = Booking.query.filter_by(
        mentor_id=current_user.id, 
        payment_status='success'
    ).all()
    
    total_earnings = sum([b.price or current_user.price for b in completed_bookings])
    pending_payout = total_earnings * 0.8  # Assuming 20% platform fee
    
    payout_history = [
        {'date': '2024-01-01', 'amount': 1000, 'status': 'Paid'},
        {'date': '2023-12-01', 'amount': 1500, 'status': 'Paid'},
    ]
    
    return render_template('mentor_payouts.html', 
                         total_earnings=total_earnings,
                         pending_payout=pending_payout,
                         payout_history=payout_history)

@app.route('/mentor/profile', methods=['GET', 'POST'])
@login_required
def mentor_profile():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                image_path = save_profile_image(file, current_user.id)
                if image_path:
                    current_user.profile_image = image_path
        
        # Update mentor profile with all new fields
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
        flash('Profile updated successfully!')
        return redirect(url_for('mentor_profile'))
    
    return render_template('mentor_profile.html')

@app.route('/mentor/settings', methods=['GET', 'POST'])
@login_required
def mentor_settings():
    if current_user.role != 'mentor':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle settings update
        if request.form.get('action') == 'update_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            
            if current_user.check_password(current_password):
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully!')
            else:
                flash('Current password is incorrect')
        
        elif request.form.get('action') == 'update_notifications':
            # Handle notification preferences
            flash('Notification settings updated!')
        
        elif request.form.get('action') == 'update_privacy':
            # Handle privacy settings
            flash('Privacy settings updated!')
        
        return redirect(url_for('mentor_settings'))
    
    return render_template('mentor_settings.html')

# New routes for learner
@app.route('/learner/enrollments')
@login_required
def learner_enrollments():
    if current_user.role != 'learner':
        return redirect(url_for('dashboard'))
    
    enrollments = Enrollment.query.filter_by(user_id=current_user.id).all()
    return render_template('learner_enrollments.html', enrollments=enrollments)

@app.route('/learner/saved-mentors')
@login_required
def saved_mentors():
    if current_user.role != 'learner':
        return redirect(url_for('dashboard'))
    
    # In a real app, this would query a SavedMentor model
    saved_mentors_list = []
    return render_template('saved_mentors.html', saved_mentors=saved_mentors_list)

@app.route('/learner/profile', methods=['GET', 'POST'])
@login_required
def learner_profile():
    if current_user.role != 'learner':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                image_path = save_profile_image(file, current_user.id)
                if image_path:
                    current_user.profile_image = image_path
        
        # Update learner profile
        current_user.full_name = request.form.get('full_name')
        current_user.phone = request.form.get('phone')
        current_user.domain = request.form.get('domain')  # Career interest
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('learner_profile'))
    
    return render_template('learner_profile.html')

# New routes for admin
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/enrollments')
@login_required
def admin_enrollments():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    enrollments = Enrollment.query.all()
    enrollment_users = []
    for enrollment in enrollments:
        user = User.query.get(enrollment.user_id)
        enrollment_users.append({
            'enrollment': enrollment,
            'user': user
        })
    
    return render_template('admin_enrollments.html', enrollments=enrollment_users)

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    # Basic analytics
    total_users = User.query.count()
    total_mentors = User.query.filter_by(role='mentor').count()
    total_learners = User.query.filter_by(role='learner').count()
    total_bookings = Booking.query.count()
    
    # Revenue calculation
    completed_payments = Payment.query.filter_by(status='success').all()
    revenue = sum([p.amount for p in completed_payments]) / 100  # Convert from paise
    
    # Monthly growth (simplified)
    monthly_data = [
        {'month': 'Jan', 'users': 100, 'revenue': 50000},
        {'month': 'Feb', 'users': 150, 'revenue': 75000},
        {'month': 'Mar', 'users': 200, 'revenue': 100000},
    ]
    
    return render_template('admin_analytics.html',
                         total_users=total_users,
                         total_mentors=total_mentors,
                         total_learners=total_learners,
                         total_bookings=total_bookings,
                         revenue=revenue,
                         monthly_data=monthly_data)

# Update booking status
@app.route('/update-booking-status/<int:booking_id>', methods=['POST'])
@login_required
def update_booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check permissions
    if current_user.role == 'mentor' and booking.mentor_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    elif current_user.role == 'admin':
        pass  # Admin can update any booking
    else:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Paid', 'Completed', 'Cancelled']:
        booking.status = new_status
        db.session.commit()
        return jsonify({'success': True, 'message': 'Status updated'})
    
    return jsonify({'success': False, 'message': 'Invalid status'}), 400

# Register route (UPDATED FOR EMAIL VERIFICATION)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'learner':
            # Handle learner registration
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Check if passwords match
            if password != confirm_password:
                flash('Passwords do not match!')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return render_template('register.html')
            if User.query.filter_by(username=username).first():
                flash('Username already taken')
                return render_template('register.html')
            
            # Create new learner
            user = User(username=username, email=email, role='learner')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(user):
                flash('Registration successful! Please check your email to verify your account.')
            else:
                flash('Registration successful! Please login to resend verification email.')
            
            return redirect(url_for('login'))
            
        elif role == 'mentor':
            # Handle mentor registration with new fields
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            job_title = request.form.get('job_title')
            company = request.form.get('company')
            previous_company = request.form.get('previous_company')
            domain = request.form.get('domain')
            experience = request.form.get('experience')
            skills = request.form.get('skills') or ''
            price = request.form.get('price')
            availability = request.form.get('availability')
            bio = request.form.get('bio')
            
            # Get services as list and convert to string
            services_list = request.form.getlist('services')
            services = ', '.join(services_list) if services_list else ""
            
            # Social media links
            facebook_url = request.form.get('facebook_url')
            instagram_url = request.form.get('instagram_url')
            youtube_url = request.form.get('youtube_url')
            linkedin_url = request.form.get('linkedin_url')
            
            # Check if passwords match
            if password != confirm_password:
                flash('Passwords do not match!')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return render_template('register.html')
            if User.query.filter_by(username=username).first():
                flash('Username already taken')
                return render_template('register.html')
            
            # Create new mentor (unverified by default)
            if not username and full_name:
                username = full_name.lower().replace(' ', '_')
            
            user = User(
                username=username, 
                email=email, 
                role='mentor',
                full_name=full_name,
                phone=phone,
                job_title=job_title,
                company=company,
                previous_company=previous_company,
                domain=domain,
                experience=experience,
                skills=skills,
                services=services,
                bio=bio,
                price=int(price) if price else 0,
                availability=availability,
                facebook_url=facebook_url,
                instagram_url=instagram_url,
                youtube_url=youtube_url,
                linkedin_url=linkedin_url,
                is_verified=False
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(user):
                flash('Mentor application submitted! Please check your email to verify your account and wait for admin approval.')
            else:
                flash('Mentor application submitted! Please login to resend verification email and wait for admin approval.')
            
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/enroll', methods=['GET', 'POST'])
def enroll():
    """Enrollment page for mentorship program"""
    if request.method == 'POST':
        # Handle enrollment form submission
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        phone = request.form.get('phone')
        education = request.form.get('education')
        
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
                # Ensure username is unique
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
                user.set_password('temp_' + str(random.randint(1000, 9999)))
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
        
        flash('Enrollment submitted successfully! Our team will contact you shortly.')
        return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('index'))
    
    return render_template('enroll.html')

# These routes are now handled by the new payment system
@app.route('/process-payment/<int:booking_id>', methods=['POST'])
@login_required
def process_payment(booking_id):
    """Legacy payment processing - redirect to new system"""
    return redirect(url_for('create_payment', booking_id=booking_id))

@app.route('/process-enrollment-payment/<int:enrollment_id>', methods=['POST'])
@login_required
def process_enrollment_payment(enrollment_id):
    """Legacy enrollment payment - to be integrated with new system"""
    enrollment = Enrollment.query.get_or_404(enrollment_id)
    
    # Check if current user owns this enrollment
    if enrollment.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Update enrollment payment status
    enrollment.payment_status = 'completed'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Payment completed successfully'})

# DEBUG ROUTE
@app.route('/debug')
def debug_paths():
    output = "<h2>Current Directory Files:</h2>"
    
    cwd = os.getcwd()
    output += f"<b>Current Folder:</b> {cwd}<br><br>"
    
    try:
        files = os.listdir(cwd)
        output += "<br>".join(files)
    except Exception as e:
        output += f"Error listing files: {e}"

    output += f"<br><br><h2>Looking for templates at: {template_dir}</h2>"
    
    if os.path.exists(template_dir):
        output += "<b>Found templates folder! Contents:</b><br>"
        try:
            tpl_files = os.listdir(template_dir)
            output += "<br>".join(tpl_files)
        except Exception as e:
            output += f"Error reading templates folder: {e}"
    else:
        output += "<b style='color:red'>Templates folder NOT found here!</b>"
        
    return output

# Initialize database with proper error handling
with app.app_context():
    try:
        # Check if database exists and has tables
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        if not tables:
            print("Creating fresh database...")
            db.create_all()
            
            # Create admin user
            admin = User(
                username='admin', 
                email='admin@clearq.in', 
                role='admin',
                is_email_verified=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Database and admin user created successfully")
        else:
            print(f"Database exists with {len(tables)} tables")
            
            # Check for new tables
            required_tables = ['user', 'service', 'booking', 'product', 'review', 'enrollment', 'payment', 'digital_product_access']
            for table in required_tables:
                if table not in tables:
                    print(f"Creating {table} table...")
                    if table == 'user':
                        User.__table__.create(db.engine)
                    elif table == 'service':
                        Service.__table__.create(db.engine)
                    elif table == 'booking':
                        Booking.__table__.create(db.engine)
                    elif table == 'product':
                        Product.__table__.create(db.engine)
                    elif table == 'review':
                        Review.__table__.create(db.engine)
                    elif table == 'enrollment':
                        Enrollment.__table__.create(db.engine)
                    elif table == 'payment':
                        Payment.__table__.create(db.engine)
                    elif table == 'digital_product_access':
                        DigitalProductAccess.__table__.create(db.engine)
                    print(f"{table} table created")
            
            # Check for new columns in user table
            columns = inspector.get_columns('user')
            column_names = [col['name'] for col in columns]
            
            new_columns = ['is_email_verified', 'email_verification_token', 'reset_token', 'reset_token_expiry']
            for col in new_columns:
                if col not in column_names:
                    print(f"WARNING: Missing column '{col}' in user table.")
                    print("Please visit /force-db-reset to recreate database with current schema.")
                    break
            else:
                print("Database schema is up to date.")
                
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Try to create tables anyway
        try:
            db.create_all()
            print("Database created as fallback")
        except Exception as e2:
            print(f"Could not create database: {e2}")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
