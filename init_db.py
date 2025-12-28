# init_db.py
import os
import sys

# Add this at the top to ensure SECRET_KEY is set
os.environ.setdefault('SECRET_KEY', 'temporary-dev-key-for-init')

from app import app, db, User

with app.app_context():
    print("🚀 Initializing database...")
    
    try:
        # Create tables
        db.create_all()
        
        # Check if admin exists
        admin_email = 'support@indomitablearrows.in'
        if not User.query.filter_by(email=admin_email).first():
            admin = User(
                username='admin',
                email=admin_email,
                role='admin',
                full_name='Administrator',
                is_active=True,
                is_email_verified=True
            )
            # Get password from env or use default
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
            admin.set_password(admin_password)
            
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created")
        else:
            print("✅ Admin user already exists")
            
        print("✅ Database initialization complete!")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
