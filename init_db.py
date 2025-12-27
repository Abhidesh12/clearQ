#!/usr/bin/env python3
"""
Database Initialization Script
===============================
This script creates all database tables and sets up initial data.
Run this when:
1. First setting up the project
2. Moving to a new database
3. After making changes to database models

Usage:
    python init_db.py
"""

import sys
import traceback
from datetime import datetime

from app import app, db, User

def create_tables():
    """Create all database tables."""
    print("=" * 60)
    print("DATABASE INITIALIZATION")
    print("=" * 60)
    
    try:
        # Drop all tables (use with caution in production!)
        if len(sys.argv) > 1 and sys.argv[1] == '--reset':
            print("⚠️  WARNING: Dropping all existing tables...")
            db.drop_all()
            print("✅ All tables dropped.")
        
        # Create all tables
        print("\n📁 Creating database tables...")
        db.create_all()
        print("✅ Database tables created successfully!")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Could not create database tables.")
        print(f"   Reason: {e}")
        traceback.print_exc()
        return False

def create_admin_user():
    """Create admin user if it doesn't exist."""
    print("\n👤 Checking admin user...")
    
    admin_email = 'admin@clearq.in'
    admin = User.query.filter_by(email=admin_email).first()
    
    if admin:
        print(f"✅ Admin user already exists: {admin.username}")
        return True
    
    try:
        # Create admin user
        admin = User(
            username='admin',
            email=admin_email,
            role='admin',
            is_email_verified=True,
            is_verified=True,
            is_active=True,
            created_at=datetime.utcnow()
        )
        admin.set_password('admin123')
        
        db.session.add(admin)
        db.session.commit()
        
        print("✅ Admin user created successfully!")
        print(f"   Username: admin")
        print(f"   Email: {admin_email}")
        print(f"   Password: admin123")
        print("\n⚠️  IMPORTANT: Change the admin password immediately!")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Could not create admin user.")
        print(f"   Reason: {e}")
        db.session.rollback()
        return False

def verify_tables():
    """Verify that all tables were created."""
    print("\n🔍 Verifying table creation...")
    
    from sqlalchemy import inspect
    
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    
    expected_tables = [
        'users', 'services', 'bookings', 'enrollments',
        'payments', 'digital_product_access', 'reviews', 'notifications'
    ]
    
    created_tables = []
    missing_tables = []
    
    for table in expected_tables:
        if table in tables:
            created_tables.append(table)
        else:
            missing_tables.append(table)
    
    if created_tables:
        print("✅ Created tables:")
        for table in created_tables:
            print(f"   - {table}")
    
    if missing_tables:
        print("\n❌ Missing tables:")
        for table in missing_tables:
            print(f"   - {table}")
    
    return len(missing_tables) == 0

def create_sample_data():
    """Create sample data for development/testing."""
    if not app.debug:
        print("\n⚠️  Skipping sample data creation (not in debug mode)")
        return True
    
    print("\n🎨 Creating sample data...")
    
    try:
        # Check if we already have mentors
        mentor_count = User.query.filter_by(role='mentor').count()
        
        if mentor_count > 0:
            print(f"✅ Already have {mentor_count} mentor(s), skipping sample data")
            return True
        
        # Create sample mentors
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
                print(f"   Created mentor: {mentor.username}")
        
        db.session.commit()
        print("✅ Sample mentors created!")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Could not create sample data.")
        print(f"   Reason: {e}")
        db.session.rollback()
        return False

def main():
    """Main initialization function."""
    print("🚀 Starting database initialization...")
    print(f"   Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    with app.app_context():
        # Step 1: Create tables
        if not create_tables():
            print("\n❌ Database initialization failed at table creation.")
            return False
        
        # Step 2: Create admin user
        if not create_admin_user():
            print("\n❌ Database initialization failed at admin creation.")
            return False
        
        # Step 3: Verify tables
        if not verify_tables():
            print("\n❌ Some tables are missing!")
            return False
        
        # Step 4: Create sample data (development only)
        if not create_sample_data():
            print("\n⚠️  Sample data creation failed, but database is ready.")
            # Don't fail the whole process for sample data
        
        print("\n" + "=" * 60)
        print("🎉 DATABASE INITIALIZATION COMPLETE!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Run the application: python app.py")
        print("2. Access the site: http://localhost:5000")
        print("3. Login with admin credentials")
        print("4. Create additional users as needed")
        
        return True

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Initialization interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
