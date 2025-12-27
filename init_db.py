from app import app, db
from app import User  # Import models

with app.app_context():
    # Drop all tables (if you want fresh start)
    # db.drop_all()
    
    # Create all tables
    db.create_all()
    print("Database tables created successfully!")
