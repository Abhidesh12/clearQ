#!/usr/bin/env python3
import os
import sys

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, Service, Booking, Payment, Review, DigitalProductAccess, Enrollment, Notification

def initialize_database():
    """Initialize the database with all tables."""
    print("Initializing database...")
    
    with app.app_context():
        try:
            # Drop all tables (optional - for fresh start)
            # db.drop_all()
            # print("Dropped all existing tables")
            
            # Create all tables
            db.create_all()
            print("✅ All tables created successfully!")
            
            # Check if admin user exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
            
            admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                admin = User(
                    username='admin',
                    email=admin_email,
                    role='admin',
                    is_email_verified=True,
                    is_verified=True,
                    is_active=True,
                    full_name='Administrator'
                )
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created")
            else:
                print("ℹ️ Admin user already exists")
            
            # Create sample mentors for development
            if app.debug:
                create_sample_data()
            
            print("✅ Database initialization complete!")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

def create_sample_data():
    """Create sample data for development."""
    print("Creating sample data...")
    
    # Check if we already have mentors
    if User.query.filter_by(role='mentor').count() < 2:
        sample_mentors = [
            {
                'username': 'john_doe',
                'email': 'john.doe@example.com',
                'full_name': 'John Doe',
                'role': 'mentor',
                'password': 'mentor123',
                'domain': 'Data Science',
                'company': 'Google',
                'job_title': 'Senior Data Scientist',
                'experience': '5 years',
                'skills': 'Python, Machine Learning, SQL, TensorFlow',
                'bio': 'I help aspiring data scientists land jobs at top tech companies.',
                'price': 1500,
                'rating': 4.9,
                'is_verified': True,
                'is_email_verified': True,
                'is_active': True
            },
            {
                'username': 'jane_smith',
                'email': 'jane.smith@example.com',
                'full_name': 'Jane Smith',
                'role': 'mentor',
                'password': 'mentor123',
                'domain': 'Product Management',
                'company': 'Microsoft',
                'job_title': 'Senior Product Manager',
                'experience': '7 years',
                'skills': 'Product Strategy, Agile, User Research',
                'bio': 'I help engineers transition to product management roles.',
                'price': 2000,
                'rating': 4.8,
                'is_verified': True,
                'is_email_verified': True,
                'is_active': True
            }
        ]
        
        for data in sample_mentors:
            if not User.query.filter_by(email=data['email']).first():
                mentor = User(
                    username=data['username'],
                    email=data['email'],
                    role=data['role'],
                    full_name=data['full_name'],
                    domain=data['domain'],
                    company=data['company'],
                    job_title=data['job_title'],
                    experience=data['experience'],
                    skills=data['skills'],
                    bio=data['bio'],
                    price=data['price'],
                    rating=data['rating'],
                    is_verified=data['is_verified'],
                    is_email_verified=data['is_email_verified'],
                    is_active=data['is_active']
                )
                mentor.set_password(data['password'])
                db.session.add(mentor)
        
        db.session.commit()
        print("✅ Sample mentors created")
    
    # Create sample services
    mentors = User.query.filter_by(role='mentor').all()
    for mentor in mentors:
        if Service.query.filter_by(mentor_id=mentor.id).count() == 0:
            services = [
                {
                    'name': 'Career Guidance Session',
                    'description': 'One-on-one career guidance and roadmap planning',
                    'price': 1000,
                    'duration': '1 hour',
                    'service_type': 'consultation'
                },
                {
                    'name': 'Resume Review',
                    'description': 'Detailed resume review and optimization',
                    'price': 800,
                    'duration': '45 minutes',
                    'service_type': 'consultation'
                },
                {
                    'name': 'Mock Interview',
                    'description': 'Realistic mock interview with feedback',
                    'price': 1200,
                    'duration': '1 hour',
                    'service_type': 'consultation'
                }
            ]
            
            for service_data in services:
                from datetime import datetime
                service = Service(
                    mentor_id=mentor.id,
                    name=service_data['name'],
                    slug=service_data['name'].lower().replace(' ', '-'),
                    description=service_data['description'],
                    price=service_data['price'],
                    duration=service_data['duration'],
                    service_type=service_data['service_type'],
                    is_active=True,
                    created_at=datetime.utcnow()
                )
                db.session.add(service)
            
            db.session.commit()
            print(f"✅ Sample services created for {mentor.username}")

if __name__ == '__main__':
    initialize_database()
