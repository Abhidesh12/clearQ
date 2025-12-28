#!/usr/bin/env python3
"""
Database initialization script for ClearQ
Run this once before starting the application
"""

import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from app import app, db, User
from werkzeug.security import generate_password_hash

def init_database():
    """Initialize database with required tables and admin user."""
    print("🚀 Initializing ClearQ Database...")
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Check if admin exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
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
                admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
                admin.set_password(admin_password)
                
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created")
                print(f"   Email: {admin_email}")
                print(f"   Password: {admin_password}")
            else:
                print("✅ Admin user already exists")
            
            print("\n🎉 Database initialization complete!")
            print("\n📝 Next steps:")
            print("1. Run: python app.py")
            print("2. Visit: http://localhost:5000")
            print("3. Login with admin credentials")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            db.session.rollback()
            sys.exit(1)

if __name__ == '__main__':
    init_database()
