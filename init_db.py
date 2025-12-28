# init_db.py
import os
import sys
from app import app, db, User
from werkzeug.security import generate_password_hash

def init_database():
    """Initialize the database with all tables."""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Check if admin user exists
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
            admin = User.query.filter_by(email=admin_email).first()
            
            if not admin:
                # Create admin user
                admin = User(
                    username='admin',
                    email=admin_email,
                    role='admin',
                    full_name='Administrator',
                    is_email_verified=True,
                    is_verified=True,
                    is_active=True
                )
                admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print(f"✅ Admin user created: {admin_email}")
            else:
                print("✅ Admin user already exists")
                
            print("🎉 Database initialization complete!")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    init_database()
