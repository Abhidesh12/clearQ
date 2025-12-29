import os
import uuid
import json
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey, JSON, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, backref
from sqlalchemy.sql import func
import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
import razorpay
from PIL import Image
import io

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="ClearQ Mentorship Platform")

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/mentorship")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Templates
templates = Jinja2Templates(directory="templates")

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create uploads directory
os.makedirs("static/uploads/profile_pics", exist_ok=True)
os.makedirs("static/uploads/digital_products", exist_ok=True)

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
security = HTTPBearer()

# Razorpay Configuration
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)) if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET else None

# Database Models - FIXED with explicit foreign_keys
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    password_hash = Column(String(255))
    role = Column(Enum("learner", "mentor", "admin", name="user_roles"), default="learner")
    full_name = Column(String(100))
    profile_image = Column(String(255))
    phone = Column(String(20))
    bio = Column(Text)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships - SIMPLIFIED to avoid ambiguity
    bookings_as_user = relationship("Booking", back_populates="user", foreign_keys="[Booking.user_id]")
    reviews_written = relationship("Review", back_populates="user", foreign_keys="[Review.user_id]")
    notifications = relationship("Notification", back_populates="user", foreign_keys="[Notification.user_id]")

class Mentor(Base):
    __tablename__ = "mentors"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    experience = Column(Integer)  # Years of experience
    industry = Column(String(100))
    job_title = Column(String(100))
    company = Column(String(100))
    skills = Column(Text)  # Comma separated skills
    linkedin_url = Column(String(255))
    twitter_url = Column(String(255))
    github_url = Column(String(255))
    website_url = Column(String(255))
    hourly_rate = Column(Float, default=0)
    rating = Column(Float, default=0)
    total_reviews = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)
    is_approved = Column(Boolean, default=False)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships with explicit foreign_keys
    user = relationship("User", foreign_keys=[user_id], backref=backref("mentor_profile", uselist=False))
    services = relationship("Service", back_populates="mentor")
    availabilities = relationship("Availability", back_populates="mentor")
    bookings = relationship("Booking", back_populates="mentor")
    reviews = relationship("Review", back_populates="mentor")
    approver = relationship("User", foreign_keys=[approved_by])

class Learner(Base):
    __tablename__ = "learners"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    education = Column(String(100))
    career_goals = Column(Text)
    interests = Column(Text)  # Comma separated interests
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], backref=backref("learner_profile", uselist=False))
    bookings = relationship("Booking", back_populates="learner")

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    name = Column(String(100))
    description = Column(Text)
    category = Column(Enum(
        "mock_interview", "resume_review", "career_guidance", 
        "coding_help", "portfolio_review", "salary_negotiation",
        "leadership_coaching", "skill_development", name="service_categories"
    ))
    price = Column(Float)
    duration = Column(Integer)  # in minutes
    is_digital = Column(Boolean, default=False)
    digital_product_url = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    mentor = relationship("Mentor", back_populates="services")

class Availability(Base):
    __tablename__ = "availabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    day_of_week = Column(Integer)  # 0-6 (Monday-Sunday)
    start_time = Column(String(8))  # HH:MM:SS
    end_time = Column(String(8))  # HH:MM:SS
    is_recurring = Column(Boolean, default=True)
    
    # Relationships
    mentor = relationship("Mentor", back_populates="availabilities")

class Booking(Base):
    __tablename__ = "bookings"
    
    id = Column(Integer, primary_key=True, index=True)
    booking_uid = Column(String(50), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    learner_id = Column(Integer, ForeignKey("learners.id"))
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    service_id = Column(Integer, ForeignKey("services.id"))
    scheduled_for = Column(DateTime(timezone=True))
    scheduled_until = Column(DateTime(timezone=True))
    status = Column(Enum(
        "pending", "confirmed", "completed", "cancelled", "no_show",
        name="booking_status"
    ), default="pending")
    meeting_link = Column(String(255))
    amount = Column(Float)
    razorpay_order_id = Column(String(100))
    razorpay_payment_id = Column(String(100))
    razorpay_signature = Column(String(255))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships with explicit foreign_keys
    user = relationship("User", foreign_keys=[user_id], back_populates="bookings_as_user")
    learner = relationship("Learner", back_populates="bookings")
    mentor = relationship("Mentor", back_populates="bookings")
    service = relationship("Service")
    review = relationship("Review", back_populates="booking", uselist=False)

class Review(Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    booking_id = Column(Integer, ForeignKey("bookings.id"), unique=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)  # 1-5
    comment = Column(Text)
    is_verified = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships with explicit foreign_keys
    booking = relationship("Booking", back_populates="review")
    mentor = relationship("Mentor", back_populates="reviews")
    user = relationship("User", foreign_keys=[user_id], back_populates="reviews_written")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(100))
    message = Column(Text)
    type = Column(String(50))  # info, success, warning, error
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="notifications")

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication functions
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        # Add is_authenticated attribute to user object
        user.is_authenticated = True
    return user

# Utility functions
def save_profile_image(file: UploadFile, user_id: int):
    # Generate unique filename
    ext = file.filename.split('.')[-1]
    filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = f"static/uploads/profile_pics/{filename}"
    
    # Open and process image
    image = Image.open(file.file)
    # Resize if too large
    if image.size[0] > 800 or image.size[1] > 800:
        image.thumbnail((800, 800))
    
    # Convert to RGB if necessary
    if image.mode in ('RGBA', 'LA'):
        background = Image.new('RGB', image.size, (255, 255, 255))
        background.paste(image, mask=image.split()[-1])
        image = background
    
    # Save image
    image.save(filepath, "JPEG", quality=85)
    
    return f"/static/uploads/profile_pics/{filename}"

def generate_booking_uid():
    return f"BK{uuid.uuid4().hex[:8].upper()}"

def create_admin_user(db: Session):
    """Create initial admin user if not exists"""
    admin_email = "admin@clearq.in"
    admin_username = "admin"
    
    # Check if admin already exists
    existing_admin = db.query(User).filter(
        (User.email == admin_email) | (User.username == admin_username)
    ).first()
    
    if not existing_admin:
        # Create admin user
        admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=hash_password("Admin@123"),  # Change this in production!
            full_name="ClearQ Administrator",
            role="admin",
            is_verified=True,
            is_active=True
        )
        
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        print("=" * 60)
        print("ADMIN USER CREATED SUCCESSFULLY")
        print("=" * 60)
        print(f"Email: {admin_email}")
        print(f"Password: Admin@123")
        print("=" * 60)
        print("IMPORTANT: Change this password immediately after first login!")
        print("=" * 60)
        
        return admin
    return existing_admin

def require_admin(current_user: User = Depends(get_current_user)):
    """Dependency to require admin role"""
    if not current_user or current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# Add this to ensure admin is created on startup
@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    try:
        admin = create_admin_user(db)
        if admin:
            print(f"✅ Admin user created: {admin.email}")
        else:
            print("✅ Admin user already exists")
        
        # Check if we have any mentors for sample data
        mentor_count = db.query(User).filter(User.role == "mentor").count()
        if mentor_count == 0:
            print("ℹ️  No mentors found. Add mentors through admin panel.")
        
        print("✅ ClearQ platform is ready!")
    except Exception as e:
        print(f"⚠️  Startup error: {e}")
    finally:
        db.close()

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Get featured mentors
    featured_mentors = db.query(Mentor).filter(
        Mentor.is_approved == True
    ).order_by(Mentor.rating.desc()).limit(6).all()
    
    # Get user info for each mentor
    for mentor in featured_mentors:
        user = db.query(User).filter(User.id == mentor.user_id, User.is_active == True).first()
        if user:
            setattr(mentor, 'user', user)
    
    # Get top services
    top_services = db.query(Service).filter(
        Service.is_active == True
    ).order_by(Service.price).limit(8).all()
    
    # Get mentor info for each service
    for service in top_services:
        mentor = db.query(Mentor).filter(Mentor.id == service.mentor_id).first()
        if mentor:
            setattr(service, 'mentor', mentor)
            user = db.query(User).filter(User.id == mentor.user_id).first()
            if user:
                setattr(mentor, 'user', user)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user,
        "featured_mentors": featured_mentors,
        "top_services": top_services,
        "now": datetime.now()
    })

@app.get("/admin/setup", response_class=HTMLResponse)
async def admin_setup_page(request: Request, db: Session = Depends(get_db)):
    # Check if admin already exists
    admin = db.query(User).filter(User.email == "admin@clearq.in").first()
    
    if not admin:
        # Create admin if doesn't exist
        admin = create_admin_user(db)
    
    return templates.TemplateResponse("admin_setup.html", {
        "request": request,
        "admin": admin
    })
    
@app.get("/enroll", response_class=HTMLResponse, name="enroll")
async def enroll_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse("enroll.html", {
        "request": request,
        "current_user": current_user
    })
    
@app.get("/explore", name="explore", response_class=HTMLResponse)
async def explore_mentors(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: str = None,
    industry: str = None,
    min_price: float = None,
    max_price: float = None,
    search: str = None
):
    # Start with approved mentors
    mentor_query = db.query(Mentor).filter(Mentor.is_approved == True)
    
    if industry:
        mentor_query = mentor_query.filter(Mentor.industry.ilike(f"%{industry}%"))
    
    mentors_result = mentor_query.all()
    
    # Filter by active users and search criteria
    mentors = []
    for mentor in mentors_result:
        user = db.query(User).filter(User.id == mentor.user_id, User.is_active == True).first()
        if user:
            # Set user as attribute
            setattr(mentor, 'user', user)
            
            # Apply category filter if specified
            if category:
                services = db.query(Service).filter(
                    Service.mentor_id == mentor.id,
                    Service.category == category,
                    Service.is_active == True
                ).first()
                if not services:
                    continue
            
            # Apply search filter if specified
            if search:
                search_lower = search.lower()
                if not (
                    (user.full_name and search_lower in user.full_name.lower()) or
                    (mentor.job_title and search_lower in mentor.job_title.lower()) or
                    (mentor.skills and search_lower in mentor.skills.lower())
                ):
                    continue
            
            mentors.append(mentor)
    
    # Get unique industries
    industries = db.query(Mentor.industry).distinct().filter(Mentor.industry.isnot(None)).all()
    industries = [i[0] for i in industries if i[0]]
    
    return templates.TemplateResponse("explore.html", {
        "request": request,
        "current_user": current_user,
        "mentors": mentors,
        "industries": industries,
        "search_query": search,
        "category": category
    })

@app.get("/mentor/{username}", response_class=HTMLResponse)
async def mentor_profile(request: Request, username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = db.query(User).filter(
        User.username == username,
        User.role == "mentor",
        User.is_active == True
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    mentor = db.query(Mentor).filter(
        Mentor.user_id == user.id,
        Mentor.is_approved == True
    ).first()
    
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    # Set user as attribute
    setattr(mentor, 'user', user)
    
    services = db.query(Service).filter(
        Service.mentor_id == mentor.id,
        Service.is_active == True
    ).all()
    
    reviews = db.query(Review).filter(
        Review.mentor_id == mentor.id,
        Review.is_verified == True
    ).order_by(Review.created_at.desc()).limit(10).all()
    
    # Get user info for each review
    for review in reviews:
        review_user = db.query(User).filter(User.id == review.user_id).first()
        if review_user:
            setattr(review, 'user', review_user)
    
    # Get upcoming availability (next 7 days)
    availabilities = []
    for i in range(7):
        date = datetime.now() + timedelta(days=i)
        availabilities.append({
            "date": date,
            "day_name": date.strftime("%A"),
            "day_num": date.day,
            "month": date.strftime("%B")
        })
    
    return templates.TemplateResponse("mentor_profile.html", {
        "request": request,
        "current_user": current_user,
        "mentor": mentor,
        "services": services,
        "reviews": reviews,
        "available_dates": availabilities
    })

@app.get("/service/{service_id}", response_class=HTMLResponse)
async def service_detail(request: Request, service_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    mentor = db.query(Mentor).filter(Mentor.id == service.mentor_id).first()
    if mentor:
        user = db.query(User).filter(User.id == mentor.user_id).first()
        if user:
            setattr(mentor, 'user', user)
    
    return templates.TemplateResponse("service_detail.html", {
        "request": request,
        "current_user": current_user,
        "service": service,
        "mentor": mentor
    })

@app.get("/api/available-dates/{mentor_id}")
async def get_available_dates(mentor_id: int, db: Session = Depends(get_db)):
    mentor = db.query(Mentor).filter(Mentor.id == mentor_id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    # Generate next 14 days
    available_dates = []
    today = datetime.now().date()
    
    for i in range(1, 15):
        date = today + timedelta(days=i)
        # Check if mentor has availability for this day
        day_of_week = date.weekday()  # Monday=0, Sunday=6
        
        # Check mentor's recurring availability
        availability = db.query(Availability).filter(
            Availability.mentor_id == mentor_id,
            Availability.day_of_week == day_of_week
        ).first()
        
        if availability:
            available_dates.append({
                "full_date": date.isoformat(),
                "day": date.day,
                "month": date.strftime("%B"),
                "dayName": date.strftime("%A")
            })
    
    return {"success": True, "dates": available_dates}

@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Get role-specific profile if exists
    mentor_profile = None
    learner_profile = None
    
    if current_user.role == "mentor":
        mentor_profile = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    elif current_user.role == "learner":
        learner_profile = db.query(Learner).filter(Learner.user_id == current_user.id).first()
    
    return templates.TemplateResponse("edit_profile.html", {
        "request": request,
        "current_user": current_user,
        "mentor_profile": mentor_profile,
        "learner_profile": learner_profile
    })

@app.post("/profile/update")
async def update_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    full_name: str = Form(None),
    bio: str = Form(None),
    phone: str = Form(None),
    profile_image: UploadFile = File(None)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Update user details
    if full_name:
        current_user.full_name = full_name
    if bio:
        current_user.bio = bio
    if phone:
        current_user.phone = phone
    
    # Update profile image if provided
    if profile_image and profile_image.filename:
        image_path = save_profile_image(profile_image, current_user.id)
        current_user.profile_image = image_path
    
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/mentor/profile/update")
async def update_mentor_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    experience: int = Form(...),
    industry: str = Form(...),
    job_title: str = Form(...),
    company: str = Form(None),
    skills: str = Form(...),
    linkedin_url: str = Form(None),
    twitter_url: str = Form(None),
    github_url: str = Form(None),
    website_url: str = Form(None),
    hourly_rate: float = Form(...)
):
    if not current_user or current_user.role != "mentor":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        # Create mentor profile if doesn't exist
        mentor = Mentor(user_id=current_user.id)
        db.add(mentor)
    
    # Update mentor details
    mentor.experience = experience
    mentor.industry = industry
    mentor.job_title = job_title
    mentor.company = company
    mentor.skills = skills
    mentor.linkedin_url = linkedin_url
    mentor.twitter_url = twitter_url
    mentor.github_url = github_url
    mentor.website_url = website_url
    mentor.hourly_rate = hourly_rate
    
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/api/services/create")
async def create_service(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    price: float = Form(...),
    duration: int = Form(...),
    is_digital: bool = Form(False),
    digital_product_url: str = Form(None)
):
    if not current_user or current_user.role != "mentor":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    service = Service(
        mentor_id=mentor.id,
        name=name,
        description=description,
        category=category,
        price=price,
        duration=duration,
        is_digital=is_digital,
        digital_product_url=digital_product_url
    )
    
    db.add(service)
    db.commit()
    
    return {"success": True, "service_id": service.id}

@app.post("/api/availability/update")
async def update_availability(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    availability_data: str = Form(...)  # JSON string of availability slots
):
    if not current_user or current_user.role != "mentor":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    # Parse availability data
    try:
        availability = json.loads(availability_data)
        
        # Delete existing availability
        db.query(Availability).filter(Availability.mentor_id == mentor.id).delete()
        
        # Add new availability
        for slot in availability:
            avail = Availability(
                mentor_id=mentor.id,
                day_of_week=slot["day"],
                start_time=slot["start"],
                end_time=slot["end"],
                is_recurring=True
            )
            db.add(avail)
        
        db.commit()
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid availability data: {str(e)}")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    stats = {}
    
    if current_user.role == "mentor":
        mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
        if mentor:
            # Calculate earnings for last 30 days
            thirty_days_ago = datetime.now() - timedelta(days=30)
            recent_earnings = db.query(func.sum(Booking.amount)).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed",
                Booking.created_at >= thirty_days_ago
            ).scalar() or 0
            
            # Get total sessions
            total_sessions = db.query(Booking).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed"
            ).count()
            
            # Get upcoming sessions
            upcoming_sessions = db.query(Booking).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "confirmed",
                Booking.scheduled_for >= datetime.now()
            ).count()
            
            stats = {
                "recent_earnings": recent_earnings,
                "total_sessions": total_sessions,
                "upcoming_sessions": upcoming_sessions,
                "conversion_rate": 0.75  # This would be calculated from actual data
            }
    
    elif current_user.role == "learner":
        learner = db.query(Learner).filter(Learner.user_id == current_user.id).first()
        if learner:
            # Get learner stats
            total_bookings = db.query(Booking).filter(
                Booking.learner_id == learner.id
            ).count()
            
            completed_sessions = db.query(Booking).filter(
                Booking.learner_id == learner.id,
                Booking.status == "completed"
            ).count()
            
            upcoming_sessions = db.query(Booking).filter(
                Booking.learner_id == learner.id,
                Booking.status == "confirmed",
                Booking.scheduled_for >= datetime.now()
            ).count()
            
            total_spent = db.query(func.sum(Booking.amount)).filter(
                Booking.learner_id == learner.id,
                Booking.status == "completed"
            ).scalar() or 0
            
            stats = {
                "total_bookings": total_bookings,
                "completed_sessions": completed_sessions,
                "upcoming_sessions": upcoming_sessions,
                "total_spent": total_spent
            }
    
    return {"success": True, "stats": stats}

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, current_user: User = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_user(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    phone: str = Form(None),
    bio: str = Form(None),
    profile_image: UploadFile = File(None)
):
    # Check if user exists
    existing_user = db.query(User).filter(
        (User.email == email) | (User.username == username)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
        role=role,
        phone=phone,
        bio=bio,
        is_verified=role != "mentor"  # Mentors need admin verification
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Save profile image if uploaded
    if profile_image and profile_image.filename:
        image_path = save_profile_image(profile_image, user.id)
        user.profile_image = image_path
        db.commit()
    
    # Create role-specific profile
    if role == "mentor":
        mentor = Mentor(user_id=user.id)
        db.add(mentor)
    elif role == "learner":
        learner = Learner(user_id=user.id)
        db.add(learner)
    
    db.commit()
    
    # Create access token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=os.getenv("ENVIRONMENT") == "production",
        samesite="lax"
    )
    
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: User = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_user(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...)
):
    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create access token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=os.getenv("ENVIRONMENT") == "production",
        samesite="lax"
    )
    
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    if current_user.role == "admin":
        return RedirectResponse(url="/admin/dashboard", status_code=303)
    
    # Get user's bookings
    bookings = db.query(Booking).filter(Booking.user_id == current_user.id).order_by(Booking.scheduled_for.desc()).limit(10).all()
    
    # Get notifications
    notifications = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).order_by(Notification.created_at.desc()).all()
    
    if current_user.role == "mentor":
        # Get mentor-specific data
        mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
        if mentor:
            upcoming_sessions = db.query(Booking).filter(
                Booking.mentor_id == mentor.id,
                Booking.status.in_(["confirmed"]),
                Booking.scheduled_for >= datetime.now()
            ).order_by(Booking.scheduled_for).limit(10).all()
            
            earnings = db.query(func.sum(Booking.amount)).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed"
            ).scalar() or 0
            
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "current_user": current_user,
                "bookings": bookings,
                "notifications": notifications,
                "upcoming_sessions": upcoming_sessions,
                "earnings": earnings,
                "is_mentor": True,
                "mentor": mentor
            })
    
    # Learner dashboard or fallback for mentor without profile
    upcoming_sessions = db.query(Booking).filter(
        Booking.user_id == current_user.id,
        Booking.status.in_(["confirmed"]),
        Booking.scheduled_for >= datetime.now()
    ).order_by(Booking.scheduled_for).limit(10).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "bookings": bookings,
        "notifications": notifications,
        "upcoming_sessions": upcoming_sessions,
        "is_mentor": False
    })

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    # Get pending mentor approvals
    pending_mentors_query = db.query(Mentor).filter(Mentor.is_approved == False).all()
    pending_mentors = []
    
    for mentor in pending_mentors_query:
        user = db.query(User).filter(User.id == mentor.user_id, User.is_active == True).first()
        if user:
            setattr(mentor, 'user', user)
            pending_mentors.append(mentor)
    
    # Get recent bookings
    recent_bookings = db.query(Booking).order_by(Booking.created_at.desc()).limit(10).all()
    
    # Get user info for each booking
    for booking in recent_bookings:
        user = db.query(User).filter(User.id == booking.user_id).first()
        if user:
            setattr(booking, 'user', user)
        
        mentor = db.query(Mentor).filter(Mentor.id == booking.mentor_id).first()
        if mentor:
            setattr(booking, 'mentor', mentor)
            mentor_user = db.query(User).filter(User.id == mentor.user_id).first()
            if mentor_user:
                setattr(mentor, 'user', mentor_user)
    
    # Get platform stats
    total_users = db.query(User).count()
    total_mentors = db.query(User).filter(User.role == "mentor").count()
    total_learners = db.query(User).filter(User.role == "learner").count()
    total_bookings = db.query(Booking).count()
    total_revenue = db.query(func.sum(Booking.amount)).filter(Booking.status == "completed").scalar() or 0
    
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "current_user": current_user,
        "pending_mentors": pending_mentors,
        "recent_bookings": recent_bookings,
        "stats": {
            "total_users": total_users,
            "total_mentors": total_mentors,
            "total_learners": total_learners,
            "total_bookings": total_bookings,
            "total_revenue": total_revenue
        }
    })

@app.post("/api/mentor/{mentor_id}/approve")
async def approve_mentor(
    mentor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    mentor = db.query(Mentor).filter(Mentor.id == mentor_id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    mentor.is_approved = True
    mentor.approved_by = current_user.id
    mentor.approved_at = datetime.now()
    
    # Update user verification status
    user = db.query(User).filter(User.id == mentor.user_id).first()
    if user:
        user.is_verified = True
    
    db.commit()
    
    # Create notification for mentor
    notification = Notification(
        user_id=mentor.user_id,
        title="Account Approved",
        message="Your mentor account has been approved by admin. You can now start accepting bookings.",
        type="success"
    )
    db.add(notification)
    db.commit()
    
    return {"success": True, "message": "Mentor approved successfully"}

@app.post("/api/create-booking")
async def create_booking(
    request: Request,
    service_id: int = Form(...),
    scheduled_for: str = Form(...),
    time_slot: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "learner":
        raise HTTPException(status_code=403, detail="Only learners can book sessions")
    
    # Parse date and time
    from dateutil import parser
    scheduled_datetime = parser.parse(f"{scheduled_for} {time_slot}")
    
    # Check if time slot is available
    conflicting_booking = db.query(Booking).filter(
        Booking.service_id == service_id,
        Booking.scheduled_for == scheduled_datetime,
        Booking.status.in_(["confirmed", "pending"])
    ).first()
    
    if conflicting_booking:
        raise HTTPException(status_code=400, detail="Time slot already booked")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get learner profile
    learner = db.query(Learner).filter(Learner.user_id == current_user.id).first()
    if not learner:
        raise HTTPException(status_code=400, detail="Learner profile not found")
    
    # Create booking
    booking = Booking(
        booking_uid=generate_booking_uid(),
        user_id=current_user.id,
        learner_id=learner.id,
        mentor_id=service.mentor_id,
        service_id=service_id,
        scheduled_for=scheduled_datetime,
        scheduled_until=scheduled_datetime + timedelta(minutes=service.duration),
        amount=service.price,
        status="pending"
    )
    
    db.add(booking)
    db.commit()
    
    # Create Razorpay order
    order_data = {
        'amount': int(service.price * 100),  # Convert to paise
        'currency': 'INR',
        'receipt': booking.booking_uid,
        'notes': {
            'booking_id': str(booking.id),
            'service': service.name,
            'mentor': "Mentor"  # We'll get this from the service later
        }
    }
    
    # Get mentor info for the note
    mentor = db.query(Mentor).filter(Mentor.id == service.mentor_id).first()
    if mentor:
        user = db.query(User).filter(User.id == mentor.user_id).first()
        if user:
            order_data['notes']['mentor'] = user.full_name
    
    try:
        if razorpay_client:
            order = razorpay_client.order.create(data=order_data)
            booking.razorpay_order_id = order['id']
            db.commit()
        else:
            # For testing without Razorpay
            booking.razorpay_order_id = f"test_order_{booking.id}"
            booking.status = "confirmed"
            db.commit()
            return {
                "success": True,
                "booking_id": booking.id,
                "order_id": booking.razorpay_order_id,
                "amount": service.price,
                "currency": "INR",
                "key_id": "test_key",
                "test_mode": True
            }
    except Exception as e:
        db.delete(booking)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Payment gateway error: {str(e)}")
    
    return {
        "success": True,
        "booking_id": booking.id,
        "order_id": order['id'],
        "amount": service.price,
        "currency": "INR",
        "key_id": RAZORPAY_KEY_ID
    }

@app.post("/api/verify-payment")
async def verify_payment(
    request: Request,
    razorpay_order_id: str = Form(...),
    razorpay_payment_id: str = Form(...),
    razorpay_signature: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # For testing without Razorpay
    if razorpay_order_id.startswith("test_order_"):
        # Update booking for test mode
        booking = db.query(Booking).filter(
            Booking.razorpay_order_id == razorpay_order_id,
            Booking.user_id == current_user.id
        ).first()
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        booking.razorpay_payment_id = "test_payment"
        booking.razorpay_signature = "test_signature"
        booking.status = "confirmed"
        booking.meeting_link = f"https://meet.clearq.in/{booking.booking_uid}"
        
        db.commit()
        
        # Create notifications
        mentor = db.query(Mentor).filter(Mentor.id == booking.mentor_id).first()
        if mentor:
            mentor_user = db.query(User).filter(User.id == mentor.user_id).first()
            mentor_name = mentor_user.full_name if mentor_user else "mentor"
            
            # For learner
            learner_notification = Notification(
                user_id=current_user.id,
                title="Booking Confirmed",
                message=f"Your booking with {mentor_name} is confirmed for {booking.scheduled_for.strftime('%d %B %Y at %I:%M %p')}",
                type="success"
            )
            
            # For mentor
            mentor_notification = Notification(
                user_id=mentor.user_id,
                title="New Booking",
                message=f"{current_user.full_name} has booked a session with you on {booking.scheduled_for.strftime('%d %B %Y at %I:%M %p')}",
                type="info"
            )
            
            db.add(learner_notification)
            db.add(mentor_notification)
            db.commit()
        
        return {"success": True, "message": "Payment verified successfully", "test_mode": True}
    
    # Verify payment signature for production
    if not razorpay_client:
        raise HTTPException(status_code=500, detail="Payment gateway not configured")
    
    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }
    
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    
    # Update booking
    booking = db.query(Booking).filter(
        Booking.razorpay_order_id == razorpay_order_id,
        Booking.user_id == current_user.id
    ).first()
    
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    booking.razorpay_payment_id = razorpay_payment_id
    booking.razorpay_signature = razorpay_signature
    booking.status = "confirmed"
    
    # Create meeting link (in production, integrate with Zoom/Google Meet API)
    booking.meeting_link = f"https://meet.clearq.in/{booking.booking_uid}"
    
    db.commit()
    
    # Create notifications
    mentor = db.query(Mentor).filter(Mentor.id == booking.mentor_id).first()
    if mentor:
        mentor_user = db.query(User).filter(User.id == mentor.user_id).first()
        mentor_name = mentor_user.full_name if mentor_user else "mentor"
        
        # For learner
        learner_notification = Notification(
            user_id=current_user.id,
            title="Booking Confirmed",
            message=f"Your booking with {mentor_name} is confirmed for {booking.scheduled_for.strftime('%d %B %Y at %I:%M %p')}",
            type="success"
        )
        
        # For mentor
        mentor_notification = Notification(
            user_id=mentor.user_id,
            title="New Booking",
            message=f"{current_user.full_name} has booked a session with you on {booking.scheduled_for.strftime('%d %B %Y at %I:%M %p')}",
            type="info"
        )
        
        db.add(learner_notification)
        db.add(mentor_notification)
        db.commit()
    
    return {"success": True, "message": "Payment verified successfully"}

@app.get("/api/available-slots/{mentor_id}")
async def get_available_slots(
    mentor_id: int,
    date: str,
    db: Session = Depends(get_db)
):
    from dateutil import parser
    selected_date = parser.parse(date).date()
    
    # Get mentor's services
    services = db.query(Service).filter(
        Service.mentor_id == mentor_id,
        Service.is_active == True
    ).all()
    
    # Get existing bookings for the date
    bookings = db.query(Booking).filter(
        Booking.mentor_id == mentor_id,
        func.date(Booking.scheduled_for) == selected_date,
        Booking.status.in_(["confirmed", "pending"])
    ).all()
    
    # Generate available slots (simplified logic)
    available_slots = []
    for service in services:
        # Assuming 1-hour slots from 9 AM to 6 PM
        for hour in range(9, 18):
            slot_time = datetime.combine(selected_date, datetime.min.time()) + timedelta(hours=hour)
            
            # Check if slot is available
            slot_available = True
            for booking in bookings:
                if booking.scheduled_for.hour == hour:
                    slot_available = False
                    break
            
            if slot_available:
                available_slots.append({
                    "time": f"{hour:02d}:00",
                    "service_id": service.id,
                    "service_name": service.name,
                    "price": service.price
                })
    
    return {"success": True, "slots": available_slots}

@app.post("/api/submit-review")
async def submit_review(
    request: Request,
    booking_id: int = Form(...),
    rating: int = Form(...),
    comment: str = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if booking exists and belongs to user
    booking = db.query(Booking).filter(
        Booking.id == booking_id,
        Booking.user_id == current_user.id,
        Booking.status == "completed"
    ).first()
    
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Check if review already exists
    existing_review = db.query(Review).filter(Review.booking_id == booking_id).first()
    if existing_review:
        raise HTTPException(status_code=400, detail="Review already submitted")
    
    # Create review
    review = Review(
        booking_id=booking_id,
        mentor_id=booking.mentor_id,
        user_id=current_user.id,
        rating=rating,
        comment=comment
    )
    
    db.add(review)
    
    # Update mentor rating
    mentor = db.query(Mentor).filter(Mentor.id == booking.mentor_id).first()
    if mentor:
        total_reviews = mentor.total_reviews + 1
        mentor.rating = ((mentor.rating * mentor.total_reviews) + rating) / total_reviews
        mentor.total_reviews = total_reviews
    
    db.commit()
    
    return {"success": True, "message": "Review submitted successfully"}

@app.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request, current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("terms.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request, current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("privacy.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/mentorship-program", response_class=HTMLResponse)
async def mentorship_program(request: Request, current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("mentorship_program.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, current_user: User = Depends(require_admin)):
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "current_user": current_user
    })

@app.post("/admin/change-password")
async def change_password(
    request: Request,
    current_user: User = Depends(require_admin),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Verify current password
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Check if new passwords match
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")
    
    # Validate new password strength
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Update password
    current_user.password_hash = hash_password(new_password)
    db.commit()
    
    # Create notification
    notification = Notification(
        user_id=current_user.id,
        title="Password Changed",
        message="Your admin password has been successfully changed.",
        type="success"
    )
    db.add(notification)
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=303)

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    # Try to get current_user
    try:
        db_gen = get_db()
        db = next(db_gen)
        current_user = get_current_user(request, db)
    except:
        current_user = None
        db = None
    
    try:
        return templates.TemplateResponse("404.html", {
            "request": request,
            "current_user": current_user,
            "now": datetime.now(),
            "detail": exc.detail
        }, status_code=404)
    finally:
        if db:
            try:
                next(db_gen)
            except StopIteration:
                pass

@app.exception_handler(500)
async def internal_exception_handler(request: Request, exc: HTTPException):
    # Try to get current_user
    try:
        db_gen = get_db()
        db = next(db_gen)
        current_user = get_current_user(request, db)
    except:
        current_user = None
        db = None
    
    try:
        return templates.TemplateResponse("500.html", {
            "request": request,
            "current_user": current_user,
            "now": datetime.now()
        }, status_code=500)
    finally:
        if db:
            try:
                next(db_gen)
            except StopIteration:
                pass

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)



