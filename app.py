import os
import json
import random
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

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
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads', 'profile_images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        return f'uploads/profile_images/{filename}'
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

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='learner')  # 'learner', 'mentor', 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    
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
                response_rate=data['response_rate']
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
            'duration': '24-hour delivery'
        },
        {
            'mentor_username': 'john_doe',
            'name': 'Mock Interview',
            'description': '1-hour technical mock interview',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Technical questions practice</li><li>Behavioral interview preparation</li><li>Communication skills feedback</li><li>Problem-solving approach evaluation</li><li>Post-interview debrief and improvement plan</li></ul>',
            'price': 1500,
            'duration': '1 hour'
        },
        {
            'mentor_username': 'john_doe',
            'name': 'Career Guidance Session',
            'description': '30-min career path discussion',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Personalized career roadmap</li><li>Skill gap analysis</li><li>Industry insights and trends</li><li>Networking strategies</li><li>Actionable next steps</li></ul>',
            'price': 800,
            'duration': '30 mins'
        },
        {
            'mentor_username': 'jane_smith',
            'name': 'Product Case Study Review',
            'description': 'In-depth review of product case studies',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Case study structure review</li><li>Framework application guidance</li><li>Presentation skills feedback</li><li>Industry-specific insights</li><li>Mock case study practice</li></ul>',
            'price': 1200,
            'duration': '45 mins'
        },
        {
            'mentor_username': 'jane_smith',
            'name': 'Product Manager Mock Interview',
            'description': 'Full PM interview simulation',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Complete PM interview simulation</li><li>Behavioral questions practice</li><li>Product design exercises</li><li>Strategy questions discussion</li><li>Detailed feedback and improvement plan</li></ul>',
            'price': 1800,
            'duration': '1 hour'
        },
        {
            'mentor_username': 'alex_wong',
            'name': 'Coding Interview Prep',
            'description': 'Technical coding interview preparation',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Data structures and algorithms review</li><li>Coding problem solving</li><li>Time complexity analysis</li><li>System design fundamentals</li><li>Mock coding interviews</li></ul>',
            'price': 1600,
            'duration': '1 hour'
        },
        {
            'mentor_username': 'sara_johnson',
            'name': 'Design Portfolio Review',
            'description': 'Comprehensive UX portfolio feedback',
            'detailed_description': '<h3>What You\'ll Get:</h3><ul><li>Portfolio structure and flow review</li><li>Case study presentation feedback</li><li>Visual design critique</li><li>User research methodology evaluation</li><li>Industry portfolio standards</li></ul>',
            'price': 1400,
            'duration': '1 hour'
        }
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
                duration=service_data['duration']
            )
            db.session.add(service)
    
    # Add sample products for backward compatibility
    sample_products = [
        {
            'mentor_username': 'john_doe',
            'name': 'Resume Review',
            'description': 'Detailed feedback on your resume with ATS optimization tips',
            'product_type': 'Digital Product',
            'duration': '24-hour delivery',
            'price': 500,
            'tag': 'Best Seller'
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
                tag=product_data['tag']
            )
            db.session.add(product)
    
    db.session.commit()
    
    return f"Added {added_count} sample mentors with services! <a href='/explore'>Go to Explore</a>"

# --- ROUTES ---

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
    
    return render_template('service_detail.html',
                         mentor=mentor,
                         service=service,
                         reviews=reviews,
                         avg_rating=avg_rating,
                         available_dates=available_dates,
                         available_slots=available_slots,
                         today_date=today_date,
                         other_services=other_services)

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
    
    slot = request.form.get('slot')
    date_str = request.form.get('date')
    notes = request.form.get('notes', '')
    
    if not slot:
        flash('Please select a time slot')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    if not date_str:
        flash('Please select a date')
        return redirect(url_for('service_detail', username=mentor.username, service_slug=service.slug))
    
    # Convert date string to date object
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
        status='Pending'
    )
    db.session.add(booking)
    db.session.commit()
    
    flash(f'Booking created for {service.name} on {booking_date.strftime("%b %d, %Y")} at {slot}!')
    return redirect(url_for('dashboard'))

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
            status='Pending'
        )
        db.session.add(booking)
        db.session.commit()
        
        flash(f'Booking created for {product.name}! Please complete payment of ₹{product.price}.')
    else:
        # Handle digital product purchase
        flash(f'{product.name} purchased successfully for ₹{product.price}!')
    
    return redirect(url_for('dashboard'))

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
        bookings = Booking.query.limit(5).all()
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
        pending_bookings = len([b for b in my_bookings if b.status == 'Pending'])
        completed_bookings = len([b for b in my_bookings if b.status == 'Completed'])
        revenue = sum([b.price or current_user.price for b in my_bookings if b.status == 'Paid'])
        
        return render_template('dashboard.html', 
                             bookings=bookings_with_learners, 
                             type='mentor',
                             total_bookings=total_bookings,
                             pending_bookings=pending_bookings,
                             completed_bookings=completed_bookings,
                             revenue=revenue,
                             services_count=services_count)
        
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
        
        return render_template('dashboard.html', 
                             bookings=bookings_with_mentors, 
                             type='learner',
                             enrollment=enrollment)

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
        
        product = Product(
            mentor_id=current_user.id,
            name=name,
            description=description,
            product_type=product_type,
            duration=duration,
            price=int(price) if price else 0,
            tag=tag
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!')
        return redirect(url_for('mentor_products'))
    
    # Get mentor's products
    products = Product.query.filter_by(mentor_id=current_user.id).all()
    return render_template('mentor_products.html', products=products)

# Service management for mentors
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
            
            service = Service(
                mentor_id=current_user.id,
                name=name,
                slug=generate_slug(name),
                description=description,
                detailed_description=detailed_description,
                price=int(price) if price else 0,
                duration=duration
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
        status='Paid'
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
    completed_bookings = Booking.query.filter_by(status='Paid').all()
    revenue = 0
    for booking in completed_bookings:
        revenue += booking.price or 0
    
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

# Register route
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
            
            flash('Registration successful! Please login.')
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
            
            flash('Mentor application submitted! Please wait for admin approval.')
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

@app.route('/process-payment/<int:booking_id>', methods=['POST'])
@login_required
def process_payment(booking_id):
    """Process payment for a booking"""
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if current user is the learner
    if booking.learner_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Update booking status
    booking.status = 'Paid'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Payment processed successfully'})

@app.route('/process-enrollment-payment/<int:enrollment_id>', methods=['POST'])
@login_required
def process_enrollment_payment(enrollment_id):
    """Process payment for enrollment"""
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
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Database and admin user created successfully")
        else:
            print(f"Database exists with {len(tables)} tables")
            
            # Check if Service table exists
            if 'service' not in tables:
                print("Creating Service table...")
                Service.__table__.create(db.engine)
                print("Service table created")
                
            # Check for other new columns
            columns = inspector.get_columns('user')
            column_names = [col['name'] for col in columns]
            if 'profile_image' not in column_names:
                print("WARNING: Database schema is outdated. Some columns may be missing.")
                print("Please visit /force-db-reset to recreate database with current schema.")
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
