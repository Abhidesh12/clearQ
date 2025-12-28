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
from sqlalchemy.orm import sessionmaker, Session, relationship
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
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Database Models
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
    
    # Relationships
    mentor = relationship("Mentor", back_populates="user", uselist=False)
    learner = relationship("Learner", back_populates="user", uselist=False)
    bookings = relationship("Booking", back_populates="user")

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
    
    # Relationships
    user = relationship("User", back_populates="mentor")
    services = relationship("Service", back_populates="mentor")
    availabilities = relationship("Availability", back_populates="mentor")
    bookings = relationship("Booking", back_populates="mentor")
    reviews = relationship("Review", back_populates="mentor")

class Learner(Base):
    __tablename__ = "learners"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    education = Column(String(100))
    career_goals = Column(Text)
    interests = Column(Text)  # Comma separated interests
    
    # Relationships
    user = relationship("User", back_populates="learner")
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
    bookings = relationship("Booking", back_populates="service")

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
    
    # Relationships
    user = relationship("User", back_populates="bookings")
    learner = relationship("Learner", back_populates="bookings")
    mentor = relationship("Mentor", back_populates="bookings")
    service = relationship("Service", back_populates="bookings")
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
    
    # Relationships
    booking = relationship("Booking", back_populates="review")
    mentor = relationship("Mentor", back_populates="reviews")
    user = relationship("User")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(100))
    message = Column(Text)
    type = Column(String(50))  # info, success, warning, error
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

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

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Get featured mentors
    featured_mentors = db.query(Mentor).join(User).filter(
        Mentor.is_approved == True,
        User.is_active == True
    ).order_by(Mentor.rating.desc()).limit(6).all()
    
    # Get top services
    top_services = db.query(Service).join(Mentor).filter(
        Service.is_active == True,
        Mentor.is_approved == True
    ).order_by(Service.price).limit(8).all()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user,
        "featured_mentors": featured_mentors,
        "top_services": top_services,
        "now": datetime.now()
    })

@app.get("/explore", response_class=HTMLResponse)
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
    query = db.query(Mentor).join(User).filter(
        Mentor.is_approved == True,
        User.is_active == True
    )
    
    if category:
        query = query.join(Service).filter(Service.category == category)
    
    if industry:
        query = query.filter(Mentor.industry.ilike(f"%{industry}%"))
    
    if search:
        query = query.filter(
            (User.full_name.ilike(f"%{search}%")) |
            (Mentor.job_title.ilike(f"%{search}%")) |
            (Mentor.skills.ilike(f"%{search}%"))
        )
    
    mentors = query.distinct().all()
    
    # Get unique industries
    industries = db.query(Mentor.industry).distinct().filter(Mentor.industry.isnot(None)).all()
    industries = [i[0] for i in industries]
    
    return templates.TemplateResponse("explore.html", {
        "request": request,
        "current_user": current_user,
        "mentors": mentors,
        "industries": industries,
        "search_query": search
    })

@app.get("/mentor/{username}", response_class=HTMLResponse)
async def mentor_profile(request: Request, username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    mentor = db.query(User).filter(
        User.username == username,
        User.role == "mentor",
        User.is_active == True
    ).first()
    
    if not mentor or not mentor.mentor or not mentor.mentor.is_approved:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    services = db.query(Service).filter(
        Service.mentor_id == mentor.mentor.id,
        Service.is_active == True
    ).all()
    
    reviews = db.query(Review).filter(
        Review.mentor_id == mentor.mentor.id,
        Review.is_verified == True
    ).order_by(Review.created_at.desc()).limit(10).all()
    
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
# Add these endpoints to your app.py

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
    
    return templates.TemplateResponse("edit_profile.html", {
        "request": request,
        "current_user": current_user
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
    
    mentor = current_user.mentor
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
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
    
    mentor = current_user.mentor
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
    
    mentor = current_user.mentor
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
        mentor = current_user.mentor
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
        # Get learner stats
        total_bookings = db.query(Booking).filter(
            Booking.user_id == current_user.id
        ).count()
        
        completed_sessions = db.query(Booking).filter(
            Booking.user_id == current_user.id,
            Booking.status == "completed"
        ).count()
        
        upcoming_sessions = db.query(Booking).filter(
            Booking.user_id == current_user.id,
            Booking.status == "confirmed",
            Booking.scheduled_for >= datetime.now()
        ).count()
        
        stats = {
            "total_bookings": total_bookings,
            "completed_sessions": completed_sessions,
            "upcoming_sessions": upcoming_sessions,
            "total_spent": 0  # This would be calculated from actual data
        }
    
    return {"success": True, "stats": stats}

@app.get("/service/{service_id}", response_class=HTMLResponse)
async def service_detail(request: Request, service_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    return templates.TemplateResponse("service_detail.html", {
        "request": request,
        "current_user": current_user,
        "service": service,
        "mentor": service.mentor.user
    })

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
        mentor = current_user.mentor
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
            "is_mentor": True
        })
    else:
        # Learner dashboard
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
async def admin_dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get pending mentor approvals
    pending_mentors = db.query(Mentor).join(User).filter(
        Mentor.is_approved == False,
        User.is_active == True
    ).all()
    
    # Get recent bookings
    recent_bookings = db.query(Booking).order_by(Booking.created_at.desc()).limit(10).all()
    
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
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    mentor = db.query(Mentor).filter(Mentor.id == mentor_id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    mentor.is_approved = True
    mentor.approved_by = current_user.id
    mentor.approved_at = datetime.now()
    
    # Update user verification status
    mentor.user.is_verified = True
    
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
    
    # Create booking
    booking = Booking(
        booking_uid=generate_booking_uid(),
        user_id=current_user.id,
        learner_id=current_user.learner.id,
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
            'mentor': service.mentor.user.full_name
        }
    }
    
    try:
        order = razorpay_client.order.create(data=order_data)
        booking.razorpay_order_id = order['id']
        db.commit()
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
    # Verify payment signature
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
    # For learner
    learner_notification = Notification(
        user_id=current_user.id,
        title="Booking Confirmed",
        message=f"Your booking with {booking.mentor.user.full_name} is confirmed for {booking.scheduled_for.strftime('%d %B %Y at %I:%M %p')}",
        type="success"
    )
    
    # For mentor
    mentor_notification = Notification(
        user_id=booking.mentor.user_id,
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
    
    # Get mentor's availability
    availabilities = db.query(Availability).filter(Availability.mentor_id == mentor_id).all()
    
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
    mentor = booking.mentor
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

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("404.html", {
        "request": request,
        "detail": exc.detail
    }, status_code=404)

@app.exception_handler(500)
async def internal_exception_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("500.html", {
        "request": request
    }, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

