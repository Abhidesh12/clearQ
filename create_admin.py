import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal, engine, Base
from models import User, UserRole
from auth import get_password_hash

# Create tables if not exist
Base.metadata.create_all(bind=engine)

db = SessionLocal()

# Check if admin exists
admin = db.query(User).filter(User.username == "admin").first()
if admin:
    print("Admin already exists:")
    print(f"  Username: {admin.username}")
    print(f"  Email: {admin.email}")
    print(f"  Role: {admin.role}")
else:
    # Create new admin
    new_admin = User(
        username="admin",
        email="admin@clearq.com",
        hashed_password=get_password_hash("Admin123!"),
        full_name="System Administrator",
        role=UserRole.ADMIN,
        is_active=True
    )
    db.add(new_admin)
    db.commit()
    print("Admin created successfully!")
    print("Username: admin")
    print("Password: Admin123!")

db.close()
