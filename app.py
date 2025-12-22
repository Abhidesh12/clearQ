import os
import json
import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
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

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='learner')  # 'learner', 'mentor', 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)  # Make nullable for existing DB
    
    # Mentor Specific Fields
    full_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    job_title = db.Column(db.String(100), nullable=True)
    domain = db.Column(db.String(100), nullable=True)  # e.g., Data Science, SDE
    company = db.Column(db.String(100), nullable=True)
    experience = db.Column(db.String(50), nullable=True)
    skills = db.Column(db.Text, nullable=True)
    services = db.Column(db.Text, nullable=True)  # Resume Review, Mock Interview
    bio = db.Column(db.Text, nullable=True)  # Used for AI matching
    price = db.Column(db.Integer, default=0, nullable=True)
    availability = db.Column(db.String(50), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    service_name = db.Column(db.String(100))
    slot_time = db.Column(db.String(50))
    status = db.Column(db.String(20), default='Pending')  # Pending, Paid, Completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)

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
            if score > 0.1:  # Threshold to filter completely irrelevant matches
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

# --- DEBUG ROUTES ---
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
                Created: {mentor.created_at}
            </div>
            """
    else:
        result += "<p>No mentors found. You need to register as a mentor first.</p>"
        
    return result

@app.route('/add-sample-mentors')
def add_sample_mentors():
    """Add sample mentors for testing"""
    
    sample_mentors = [
        {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password': 'test123',
            'full_name': 'John Doe',
            'domain': 'Data Science',
            'company': 'Google',
            'job_title': 'Senior Data Scientist',
            'experience': '5 years',
            'skills': 'Python, Machine Learning, SQL, TensorFlow',
            'services': 'Resume Review, Mock Interview, Career Guidance',
            'bio': 'I help aspiring data scientists land their dream jobs at FAANG companies. With 5+ years at Google, I know exactly what hiring managers look for.',
            'price': 1500,
            'availability': 'Weekdays 6-9 PM',
            'is_verified': True
        },
        {
            'username': 'jane_smith',
            'email': 'jane@example.com',
            'password': 'test123',
            'full_name': 'Jane Smith',
            'domain': 'Product Management',
            'company': 'Microsoft',
            'job_title': 'Product Manager',
            'experience': '7 years',
            'skills': 'Product Strategy, Agile, User Research, Roadmapping',
            'services': 'Mock Interview, Product Case Studies, Career Transition',
            'bio': 'Ex-Microsoft PM with 7+ years experience. I specialize in helping engineers transition to product management roles.',
            'price': 2000,
            'availability': 'Weekends 10 AM - 6 PM',
            'is_verified': True
        },
        {
            'username': 'alex_wong',
            'email': 'alex@example.com',
            'password': 'test123',
            'full_name': 'Alex Wong',
            'domain': 'Software Engineering',
            'company': 'Amazon',
            'job_title': 'Senior SDE',
            'experience': '8 years',
            'skills': 'Java, System Design, AWS, Distributed Systems',
            'services': 'Coding Interview Prep, System Design, Resume Review',
            'bio': 'Senior SDE at Amazon with expertise in large-scale distributed systems. I help engineers crack coding interviews at top tech companies.',
            'price': 1800,
            'availability': 'Mon-Fri 7-10 PM',
            'is_verified': True
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
                job_title=data['job_title'],
                experience=data['experience'],
                skills=data['skills'],
                services=data['services'],
                bio=data['bio'],
                price=data['price'],
                availability=data['availability'],
                is_verified=data['is_verified']
            )
            mentor.set_password(data['password'])
            db.session.add(mentor)
            added_count += 1
    
    db.session.commit()
    
    return f"Added {added_count} sample mentors! <a href='/explore'>Go to Explore</a>"

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/explore', methods=['GET', 'POST'])
def explore():
    recommendations = []
    query = ""
    
    # Debug logging
    print("=== EXPLORE ROUTE ===")
    
    if request.method == 'POST':
        query = request.form.get('goal')
        print(f"Search query: {query}")
        if query:
            try:
                recommendations = get_ai_recommendations(query)
                print(f"AI found {len(recommendations)} recommendations")
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
    
    # Debug logging
    print(f"Total verified mentors: {len(all_mentors)}")
    for mentor in all_mentors:
        print(f"  - {mentor.username}: {mentor.domain}")
    
    return render_template('mentors.html', 
                         mentors=all_mentors, 
                         recommendations=recommendations, 
                         query=query)

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
            domain = request.form.get('domain')
            experience = request.form.get('experience')
            skills = request.form.get('skills') or ''
            price = request.form.get('price')
            availability = request.form.get('availability')
            bio = request.form.get('bio')
            
            # Get services as list and convert to string
            services_list = request.form.getlist('services')
            services = ', '.join(services_list) if services_list else ""
            
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
                domain=domain,
                experience=experience,
                skills=skills,
                services=services,
                bio=bio,
                price=int(price) if price else 0,
                availability=availability,
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

# Optional: Add edit profile route
@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Handle profile updates
        if current_user.role == 'mentor':
            current_user.full_name = request.form.get('full_name')
            current_user.domain = request.form.get('domain')
            current_user.price = int(request.form.get('price')) if request.form.get('price') else 0
            current_user.bio = request.form.get('bio')
            current_user.availability = request.form.get('availability')
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_profile.html')
    
@app.route('/process-enrollment', methods=['POST'])
def process_enrollment():
    """API endpoint to process enrollment (for AJAX)"""
    try:
        data = request.get_json()
        
        # Extract data
        full_name = data.get('fullName')
        email = data.get('email')
        phone = data.get('phone')
        education = data.get('education')
        
        # Validation
        if not all([full_name, email, phone]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Create user account if email doesn't exist
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            # Create new user
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
            user.set_password('temp123')
            db.session.add(user)
            db.session.commit()
            user_id = user.id
        else:
            user_id = existing_user.id
        
        # Save enrollment
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
        
        return jsonify({
            'success': True,
            'message': 'Enrollment successful! Check your email for confirmation.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

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
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/mentor/<int:id>', methods=['GET', 'POST'])
def mentor_detail(id):
    mentor = User.query.get_or_404(id)
    if mentor.role != 'mentor':
        flash('User is not a mentor')
        return redirect(url_for('explore'))
    
    # Basic slots logic
    slots = ["10:00 AM", "11:00 AM", "2:00 PM", "3:00 PM", "5:00 PM", "6:00 PM"]
    
    # Remove slots that are already booked for this mentor
    booked_slots = [b.slot_time for b in Booking.query.filter_by(mentor_id=id).all()]
    available_slots = [s for s in slots if s not in booked_slots]

    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Please login to book a session')
            return redirect(url_for('login'))
            
        service = request.form.get('service')
        slot = request.form.get('slot')
        
        # Check if slot is still available
        if slot not in available_slots:
            flash('Selected slot is no longer available')
            return redirect(url_for('mentor_detail', id=id))
        
        # Create booking
        booking = Booking(
            mentor_id=id, 
            learner_id=current_user.id, 
            service_name=service, 
            slot_time=slot, 
            status='Paid'
        )
        db.session.add(booking)
        db.session.commit()
        
        flash('Booking Confirmed! Payment Successful.')
        return redirect(url_for('dashboard'))

    # Parse services
    services = [s.strip() for s in mentor.services.split(',')] if mentor.services else []
    
    return render_template('mentor_detail.html', mentor=mentor, slots=available_slots, services=services)

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
                'amount': mentor.price if mentor else 0,
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
        return render_template('dashboard.html', bookings=bookings_with_learners, type='mentor')
        
    else:  # Learner
        my_bookings = Booking.query.filter_by(learner_id=current_user.id).all()
        bookings_with_mentors = []
        for booking in my_bookings:
            mentor = User.query.get(booking.mentor_id)
            bookings_with_mentors.append({
                'booking': booking,
                'mentor': mentor
            })
        return render_template('dashboard.html', bookings=bookings_with_mentors, type='learner')

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

# Create DB on first run - with error handling for existing columns
with app.app_context():
    try:
        db.create_all()
        # Try to add admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@clearq.in', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Database and admin user created successfully")
    except Exception as e:
        print(f"Database initialization error (may be expected if tables exist): {e}")
        # Continue anyway - the app might still work

if __name__ == '__main__':
    app.run(debug=True)
