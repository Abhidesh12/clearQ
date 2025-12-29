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
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey, JSON, Enum, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, backref
from sqlalchemy.sql import func
import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
import razorpay
from PIL import Image
import io
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def url_for(endpoint: str, **kwargs) -> str:
    """
    Flask-style url_for for Jinja2 templates.
    Map endpoint names to URLs.
    """
    routes = {
        'home': '/',
        'dashboard': '/dashboard',
        'mentorship_program': '/mentorship-program',
        'enroll': '/enroll',
        'login': '/login',
        'register': '/register',
        'logout': '/logout',
        'explore': '/explore',
        'profile_edit': '/profile/edit',
        'settings': '/settings',
        'mentor_profile': '/mentor/{username}',
        # Add all your other routes here
    }
    
    # Handle routes with parameters
    if endpoint == 'mentor_profile' and 'username' in kwargs:
        return f"/mentor/{kwargs['username']}"
    
    return routes.get(endpoint, '/')

# Add Flask-like globals to Jinja2 environment
templates.env.globals.update({
    "url_for": url_for,
    "get_flashed_messages": lambda: [],  # Returns empty list for flash messages
})

# Static files
static_dir = Path("static")
uploads_dir = static_dir / "uploads" / "profile_pics"
uploads_dir.mkdir(parents=True, exist_ok=True)

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

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum("learner", "mentor", "admin", name="user_roles"), default="learner")
    full_name = Column(String(100))
    profile_image = Column(String(255))
    phone = Column(String(20))
    bio = Column(Text)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    mentor_profile = relationship("Mentor", back_populates="user", uselist=False)
    learner_profile = relationship("Learner", back_populates="user", uselist=False)
    bookings_as_user = relationship("Booking", back_populates="user", foreign_keys="[Booking.user_id]")
    reviews_written = relationship("Review", back_populates="reviewer", foreign_keys="[Review.user_id]")
    notifications = relationship("Notification", back_populates="user")

class Mentor(Base):
    __tablename__ = "mentors"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    experience = Column(Integer)
    industry = Column(String(100))
    job_title = Column(String(100))
    company = Column(String(100))
    skills = Column(Text)
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
    
    # Relationships
    user = relationship("User", back_populates="mentor_profile")
    services = relationship("Service", back_populates="mentor", cascade="all, delete-orphan")
    availabilities = relationship("Availability", back_populates="mentor", cascade="all, delete-orphan")
    bookings = relationship("Booking", back_populates="mentor", foreign_keys="[Booking.mentor_id]")
    reviews = relationship("Review", back_populates="mentor", foreign_keys="[Review.mentor_id]")
    approver = relationship("User", foreign_keys=[approved_by])

class Learner(Base):
    __tablename__ = "learners"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    education = Column(String(100))
    career_goals = Column(Text)
    interests = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="learner_profile")
    bookings = relationship("Booking", back_populates="learner", foreign_keys="[Booking.learner_id]")

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(Enum(
        "mock_interview", "resume_review", "career_guidance", 
        "coding_help", "portfolio_review", "salary_negotiation",
        "leadership_coaching", "skill_development", name="service_categories"
    ), default="career_guidance")
    price = Column(Float, nullable=False)
    duration = Column(Integer, default=60)
    is_digital = Column(Boolean, default=False)
    digital_product_url = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    mentor = relationship("Mentor", back_populates="services")
    bookings = relationship("Booking", back_populates="service")

class Availability(Base):
    __tablename__ = "availabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    day_of_week = Column(Integer)
    start_time = Column(String(8))
    end_time = Column(String(8))
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
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="bookings_as_user")
    learner = relationship("Learner", foreign_keys=[learner_id], back_populates="bookings")
    mentor = relationship("Mentor", foreign_keys=[mentor_id], back_populates="bookings")
    service = relationship("Service", back_populates="bookings")
    review = relationship("Review", back_populates="booking", uselist=False, cascade="all, delete-orphan")

class Review(Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    booking_id = Column(Integer, ForeignKey("bookings.id"), unique=True)
    mentor_id = Column(Integer, ForeignKey("mentors.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)
    comment = Column(Text)
    is_verified = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    booking = relationship("Booking", back_populates="review")
    mentor = relationship("Mentor", foreign_keys=[mentor_id], back_populates="reviews")
    reviewer = relationship("User", foreign_keys=[user_id], back_populates="reviews_written")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(100))
    message = Column(Text)
    type = Column(String(50))
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="notifications")

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
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

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
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    return user

# Utility functions
def save_profile_image(file: UploadFile, user_id: int):
    try:
        # Generate unique filename
        ext = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{ext}"
        filepath = f"static/uploads/profile_pics/{filename}"
        
        # Read file content
        contents = file.file.read()
        
        # Open and process image
        image = Image.open(io.BytesIO(contents))
        
        # Convert to RGB if necessary
        if image.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else image.split()[0])
            image = background
        
        # Resize if too large
        max_size = (800, 800)
        image.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save image
        image.save(filepath, "JPEG", quality=85)
        
        return f"/static/uploads/profile_pics/{filename}"
    except Exception as e:
        logger.error(f"Error saving profile image: {e}")
        return None

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
            password_hash=hash_password("Admin@123"),
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

# Startup event
@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    try:
        admin = create_admin_user(db)
        if admin:
            logger.info(f"✅ Admin user created: {admin.email}")
        else:
            logger.info("✅ Admin user already exists")
        
        logger.info("✅ ClearQ platform is ready!")
    except Exception as e:
        logger.error(f"⚠️ Startup error: {e}")
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

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "current_user": current_user
    })

@app.get("/explore", response_class=HTMLResponse)
async def explore_mentors(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    search: Optional[str] = None,
    industry: Optional[str] = None,
    category: Optional[str] = None,
    min_rating: Optional[int] = None,
    max_price: Optional[int] = None
):
    # Start with approved mentors
    query = db.query(Mentor).filter(Mentor.is_approved == True)
    
    # Apply filters
    if search:
        search_filter = f"%{search}%"
        # Join with User table for search
        query = query.join(User).filter(
            (User.full_name.ilike(search_filter)) |
            (User.username.ilike(search_filter)) |
            (Mentor.skills.ilike(search_filter)) |
            (Mentor.job_title.ilike(search_filter)) |
            (Mentor.industry.ilike(search_filter))
        )
    
    if industry and industry != "all":
        query = query.filter(Mentor.industry.ilike(f"%{industry}%"))
    
    if category and category != "all":
        query = query.join(Service).filter(Service.category == category)
    
    if min_rating:
        query = query.filter(Mentor.rating >= min_rating)
    
    if max_price:
        query = query.filter(Mentor.hourly_rate <= max_price)
    
    mentors_result = query.distinct().all()
    
    # Get user info for each mentor
    mentors = []
    for mentor in mentors_result:
        user = db.query(User).filter(User.id == mentor.user_id, User.is_active == True).first()
        if user:
            setattr(mentor, 'user', user)
            mentors.append(mentor)
    
    # Get unique industries for filter dropdown
    industries = db.query(Mentor.industry).distinct().filter(Mentor.industry.isnot(None)).all()
    industries = [i[0] for i in industries if i[0]]
    
    return templates.TemplateResponse("explore.html", {
        "request": request,
        "current_user": current_user,
        "mentors": mentors,
        "industries": industries,
        "search_query": search
    })

@app.get("/mentor/{username}", response_class=HTMLResponse)
async def mentor_profile(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get user by username
    user = db.query(User).filter(
        User.username == username,
        User.role == "mentor",
        User.is_active == True
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    # Get mentor profile
    mentor = db.query(Mentor).filter(
        Mentor.user_id == user.id,
        Mentor.is_approved == True
    ).first()
    
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    # Set user attribute
    setattr(mentor, 'user', user)
    
    # Get mentor services
    services = db.query(Service).filter(
        Service.mentor_id == mentor.id,
        Service.is_active == True
    ).all()
    
    # Get reviews
    reviews = db.query(Review).filter(
        Review.mentor_id == mentor.id,
        Review.is_verified == True
    ).order_by(Review.created_at.desc()).limit(10).all()
    
    # Get reviewer info for each review
    for review in reviews:
        reviewer = db.query(User).filter(User.id == review.user_id).first()
        if reviewer:
            setattr(review, 'reviewer', reviewer)
    
    # Check if current user is viewing their own profile
    is_own_profile = current_user and current_user.id == user.id
    
    return templates.TemplateResponse("mentor_profile.html", {
        "request": request,
        "current_user": current_user,
        "mentor": mentor,
        "services": services,
        "reviews": reviews,
        "is_own_profile": is_own_profile
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    section: Optional[str] = "overview"
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    if current_user.role == "admin":
        return RedirectResponse(url="/admin/dashboard", status_code=303)
    
    # Get user's bookings
    bookings = db.query(Booking).filter(Booking.user_id == current_user.id).order_by(Booking.scheduled_for.desc()).all()
    
    # Get notifications
    notifications = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).order_by(Notification.created_at.desc()).all()
    
    # Initialize variables
    mentor = None
    learner = None
    upcoming_sessions = []
    earnings = 0
    total_earnings = 0
    monthly_earnings = 0
    completed_sessions = 0
    avg_earnings = 0
    available_balance = 0
    transactions = []
    services = []
    reviews = []
    average_rating = 0
    total_reviews = 0
    rating_distribution = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
    
    if current_user.role == "mentor":
        # Get mentor profile
        mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
        if mentor:
            # Get upcoming sessions
            upcoming_sessions = db.query(Booking).filter(
                Booking.mentor_id == mentor.id,
                Booking.status.in_(["confirmed", "pending"]),
                Booking.scheduled_for >= datetime.now()
            ).order_by(Booking.scheduled_for).limit(10).all()
            
            # Calculate earnings
            earnings_result = db.query(func.sum(Booking.amount)).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed"
            ).scalar()
            earnings = earnings_result or 0
            
            # Calculate monthly earnings (last 30 days)
            thirty_days_ago = datetime.now() - timedelta(days=30)
            monthly_result = db.query(func.sum(Booking.amount)).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed",
                Booking.created_at >= thirty_days_ago
            ).scalar()
            monthly_earnings = monthly_result or 0
            
            # Get completed sessions
            completed_sessions = db.query(Booking).filter(
                Booking.mentor_id == mentor.id,
                Booking.status == "completed"
            ).count()
            
            # Calculate average earnings
            avg_earnings = round(earnings / completed_sessions, 2) if completed_sessions > 0 else 0
            
            # Available balance (80% after platform fee)
            available_balance = round(earnings * 0.8, 2)
            
            # Get services
            services = db.query(Service).filter(Service.mentor_id == mentor.id).all()
            
            # Get reviews
            reviews = db.query(Review).filter(Review.mentor_id == mentor.id).all()
            
            # Calculate average rating
            if reviews:
                total_reviews = len(reviews)
                total_rating = sum(review.rating for review in reviews)
                average_rating = round(total_rating / total_reviews, 1)
                
                # Calculate rating distribution
                for review in reviews:
                    if 1 <= review.rating <= 5:
                        rating_distribution[review.rating] += 1
            
            total_earnings = earnings
    
    elif current_user.role == "learner":
        # Get learner profile
        learner = db.query(Learner).filter(Learner.user_id == current_user.id).first()
        
        # Get upcoming sessions
        upcoming_sessions = db.query(Booking).filter(
            Booking.user_id == current_user.id,
            Booking.status.in_(["confirmed", "pending"]),
            Booking.scheduled_for >= datetime.now()
        ).order_by(Booking.scheduled_for).limit(10).all()
        
        # Get reviews written by learner
        reviews = db.query(Review).filter(Review.user_id == current_user.id).all()
        
        if reviews:
            total_reviews = len(reviews)
            total_rating = sum(review.rating for review in reviews)
            average_rating = round(total_rating / total_reviews, 1) if total_reviews > 0 else 0
    
    # Get total bookings count
    total_bookings = len(bookings)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "section": section,
        "notifications": notifications,
        "bookings": bookings,
        "total_bookings": total_bookings,
        "upcoming_sessions": upcoming_sessions,
        "services": services,
        "earnings": earnings,
        "total_earnings": total_earnings,
        "monthly_earnings": monthly_earnings,
        "completed_sessions": completed_sessions,
        "avg_earnings": avg_earnings,
        "available_balance": available_balance,
        "transactions": transactions,
        "reviews": reviews,
        "average_rating": average_rating,
        "total_reviews": total_reviews,
        "rating_distribution": rating_distribution,
        "mentor": mentor,
        "learner": learner
    })

@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Get role-specific profiles
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

@app.post("/profile/update", response_class=HTMLResponse)
async def update_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    full_name: str = Form(None),
    email: str = Form(None),
    phone: str = Form(None),
    bio: str = Form(None),
    profile_image: UploadFile = File(None)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Update basic user info
    if full_name:
        current_user.full_name = full_name
    if email:
        # Check if email is unique
        existing_user = db.query(User).filter(User.email == email, User.id != current_user.id).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = email
    if phone:
        current_user.phone = phone
    if bio:
        current_user.bio = bio
    
    # Handle profile image upload
    if profile_image and profile_image.filename:
        image_path = save_profile_image(profile_image, current_user.id)
        if image_path:
            current_user.profile_image = image_path
    
    db.commit()
    
    return RedirectResponse(url="/dashboard?section=overview&success=Profile updated successfully", status_code=303)

@app.post("/mentor/profile/update", response_class=HTMLResponse)
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
    
    return RedirectResponse(url="/dashboard?section=overview&success=Mentor profile updated", status_code=303)

@app.post("/services/create", response_class=HTMLResponse)
async def create_service(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    price: float = Form(...),
    duration: int = Form(60)
):
    if not current_user or current_user.role != "mentor":
        return RedirectResponse(url="/login", status_code=303)
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    # Create service
    service = Service(
        mentor_id=mentor.id,
        name=name,
        description=description,
        category=category,
        price=price,
        duration=duration
    )
    
    db.add(service)
    db.commit()
    
    return RedirectResponse(url="/dashboard?section=services&success=Service created successfully", status_code=303)

@app.post("/services/{service_id}/update", response_class=HTMLResponse)
async def update_service(
    service_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    price: float = Form(...),
    duration: int = Form(60)
):
    if not current_user or current_user.role != "mentor":
        return RedirectResponse(url="/login", status_code=303)
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.mentor_id == mentor.id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Update service
    service.name = name
    service.description = description
    service.category = category
    service.price = price
    service.duration = duration
    service.updated_at = datetime.now()
    
    db.commit()
    
    return RedirectResponse(url="/dashboard?section=services&success=Service updated successfully", status_code=303)

@app.post("/services/{service_id}/delete", response_class=HTMLResponse)
async def delete_service(
    service_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "mentor":
        return RedirectResponse(url="/login", status_code=303)
    
    mentor = db.query(Mentor).filter(Mentor.user_id == current_user.id).first()
    if not mentor:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.mentor_id == mentor.id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Delete service
    db.delete(service)
    db.commit()
    
    return RedirectResponse(url="/dashboard?section=services&success=Service deleted successfully", status_code=303)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, current_user: User = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=303)
    
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    phone: str = Form(None),
    bio: str = Form(None)
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
        is_verified=role != "mentor"
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
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

@app.post("/login", response_class=HTMLResponse)
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

@app.get("/logout", response_class=HTMLResponse)
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
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
            user = db.query(User).filter(User.id == mentor.user_id).first()
            if user:
                setattr(mentor, 'user', user)
        
        service = db.query(Service).filter(Service.id == booking.service_id).first()
        if service:
            setattr(booking, 'service', service)
    
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

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
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
            "current_user": current_user
        }, status_code=500)
    finally:
        if db:
            try:
                next(db_gen)
            except StopIteration:
                pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
