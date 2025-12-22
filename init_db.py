from app import app, db

# This script manually creates the database tables.
# Run this once when you first set up the project or move to a new database.

with app.app_context():
    try:
        db.create_all()
        print("SUCCESS: Database tables created successfully!")
    except Exception as e:
        print(f"ERROR: Could not create database. Reason: {e}")
