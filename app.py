"""
ClearQ Mentorship Platform - Complete Backend with FastAPI
Author: Expert Web Developer
Date: 2025-12-29
"""

import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr, validator
import asyncpg
from passlib.context import CryptContext
import jwt
from dotenv import load_dotenv
import shutil
from pathlib import Path

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="ClearQ Mentorship Platform", version="1.0.0")

# Security
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection pool
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/clearq")

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# File upload configuration
UPLOAD_DIR = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Create upload directory
Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Pydantic Models for Validation
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    role: str = "learner"  # learner, mentor, admin
    phone: Optional[str] = None
    
    @validator('role')
    def validate_role(cls, v):
        if v not in ['learner', 'mentor', 'admin']:
            raise ValueError('Role must be learner, mentor, or admin')
        return v

class MentorProfile(BaseModel):
    experience: int
    industry: str
    job_title: Optional[str] = None
    company: Optional[str] = None
    bio: Optional[str] = None
    skills: str
    linkedin_url: Optional[str] = None
    github_url: Optional[str] = None
    twitter_url: Optional[str] = None

class ServiceCreate(BaseModel):
    name: str
    description: str
    price: float
    duration: str = "1 hour"
    category: str  # mock_interview, resume_review, career_guidance, etc.
    digital_product_link: Optional[str] = None
    is_active: bool = True

class BookingCreate(BaseModel):
    service_id: int
    mentor_id: int
    booking_date: str
    booking_time: str
    notes: Optional[str] = None

class ReviewCreate(BaseModel):
    booking_id: int
    rating: int
    comment: str
    
    @validator('rating')
    def validate_rating(cls, v):
        if v < 1 or v > 5:
            raise ValueError('Rating must be between 1 and 5')
        return v

# Database connection helper
async def get_db_connection():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            return None
    except jwt.PyJWTError:
        return None
    
    # Get user from database
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await conn.fetchrow(
            "SELECT * FROM users WHERE id = $1",
            user_id
        )
        return dict(user) if user else None
    finally:
        await conn.close()

# File upload helper
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

async def save_upload_file(upload_file: UploadFile) -> Optional[str]:
    if not allowed_file(upload_file.filename):
        return None
    
    # Generate unique filename
    file_ext = upload_file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)
    
    return f"uploads/{filename}"

async def init_db():
    """Initialize database tables"""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'learner',
                phone VARCHAR(20),
                profile_image VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Mentor profiles table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS mentor_profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                experience INTEGER NOT NULL,
                industry VARCHAR(100) NOT NULL,
                job_title VARCHAR(100),
                company VARCHAR(100),
                bio TEXT,
                skills TEXT,
                linkedin_url VARCHAR(255),
                github_url VARCHAR(255),
                twitter_url VARCHAR(255),
                rating DECIMAL(3,2) DEFAULT 0.0,
                review_count INTEGER DEFAULT 0,
                total_sessions INTEGER DEFAULT 0,
                success_rate INTEGER DEFAULT 0,
                is_approved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Services table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                mentor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                price DECIMAL(10,2) NOT NULL,
                duration VARCHAR(50) DEFAULT '1 hour',
                category VARCHAR(50) NOT NULL,
                digital_product_link VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Time slots table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS time_slots (
                id SERIAL PRIMARY KEY,
                mentor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
                slot_date DATE NOT NULL,
                start_time TIME NOT NULL,
                end_time TIME NOT NULL,
                is_booked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Bookings table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS bookings (
                id SERIAL PRIMARY KEY,
                learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                mentor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
                time_slot_id INTEGER REFERENCES time_slots(id) ON DELETE CASCADE,
                booking_date DATE NOT NULL,
                booking_time TIME NOT NULL,
                status VARCHAR(50) DEFAULT 'pending', -- pending, confirmed, completed, cancelled
                payment_status VARCHAR(50) DEFAULT 'pending', -- pending, paid, failed, refunded
                razorpay_order_id VARCHAR(255),
                razorpay_payment_id VARCHAR(255),
                amount DECIMAL(10,2) NOT NULL,
                notes TEXT,
                meeting_link VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Reviews table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
                learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                mentor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Earnings table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS earnings (
                id SERIAL PRIMARY KEY,
                mentor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
                amount DECIMAL(10,2) NOT NULL,
                platform_fee DECIMAL(10,2) NOT NULL,
                mentor_amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending', -- pending, processed, paid
                processed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Admin user (if not exists)
        admin_exists = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        )
        
        if admin_exists == 0:
            admin_password = get_password_hash("admin123")
            await conn.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, is_verified, is_active)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, "admin", "admin@clearq.in", admin_password, "Administrator", "admin", True, True)
        
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
    finally:
        await conn.close()

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    await init_db()

# Homepage
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    current_user = await get_current_user(request)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user,
        "now": datetime.now()
    })

# Mentorship Program Page
@app.get("/mentorship-program", response_class=HTMLResponse)
async def mentorship_program(request: Request):
    current_user = await get_current_user(request)
    return templates.TemplateResponse("mentorship_program.html", {
        "request": request,
        "current_user": current_user
    })

# Explore Mentors
@app.get("/explore", response_class=HTMLResponse)
async def explore_mentors(request: Request, category: Optional[str] = None):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Build query based on category
        query = """
            SELECT u.id, u.username, u.full_name, u.profile_image,
                   mp.experience, mp.industry, mp.job_title, mp.company,
                   mp.rating, mp.review_count, mp.total_sessions,
                   COUNT(DISTINCT s.id) as service_count
            FROM users u
            JOIN mentor_profiles mp ON u.id = mp.user_id
            LEFT JOIN services s ON u.id = s.mentor_id AND s.is_active = TRUE
            WHERE u.role = 'mentor' 
              AND mp.is_approved = TRUE
              AND u.is_active = TRUE
        """
        
        params = []
        if category:
            query += " AND mp.industry ILIKE $1"
            params.append(f"%{category}%")
        
        query += " GROUP BY u.id, mp.id ORDER BY mp.rating DESC NULLS LAST"
        
        mentors = await conn.fetch(query, *params)
        
        # Get categories for filter
        categories = await conn.fetch("""
            SELECT DISTINCT industry FROM mentor_profiles 
            WHERE is_approved = TRUE ORDER BY industry
        """)
        
        return templates.TemplateResponse("explore.html", {
            "request": request,
            "mentors": [dict(mentor) for mentor in mentors],
            "categories": [cat['industry'] for cat in categories],
            "selected_category": category,
            "current_user": await get_current_user(request)
        })
    finally:
        await conn.close()

# Mentor Public Profile
@app.get("/mentor/{username}", response_class=HTMLResponse)
async def mentor_public_profile(request: Request, username: str):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Get mentor details
        mentor = await conn.fetchrow("""
            SELECT u.*, mp.* 
            FROM users u
            JOIN mentor_profiles mp ON u.id = mp.user_id
            WHERE u.username = $1 AND u.role = 'mentor' 
              AND mp.is_approved = TRUE AND u.is_active = TRUE
        """, username)
        
        if not mentor:
            raise HTTPException(status_code=404, detail="Mentor not found")
        
        # Get mentor's services
        services = await conn.fetch("""
            SELECT * FROM services 
            WHERE mentor_id = $1 AND is_active = TRUE
            ORDER BY created_at DESC
        """, mentor['user_id'])
        
        # Get available dates (next 7 days)
        available_dates = []
        for i in range(7):
            date = datetime.now() + timedelta(days=i)
            available_dates.append({
                "day_name": date.strftime("%a"),
                "day_num": date.day,
                "month": date.strftime("%b"),
                "full_date": date.strftime("%Y-%m-%d")
            })
        
        return templates.TemplateResponse("mentor_profile.html", {
            "request": request,
            "mentor": dict(mentor),
            "services": [dict(service) for service in services],
            "available_dates": available_dates,
            "current_user": await get_current_user(request)
        })
    finally:
        await conn.close()

# Service Detail
@app.get("/service/{service_id}", response_class=HTMLResponse)
async def service_detail(request: Request, service_id: int):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        service = await conn.fetchrow("""
            SELECT s.*, u.username, u.full_name, u.profile_image,
                   mp.experience, mp.industry, mp.rating, mp.review_count
            FROM services s
            JOIN users u ON s.mentor_id = u.id
            JOIN mentor_profiles mp ON u.id = mp.user_id
            WHERE s.id = $1 AND s.is_active = TRUE
        """, service_id)
        
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        
        # Get available time slots for next 7 days
        time_slots = await conn.fetch("""
            SELECT * FROM time_slots 
            WHERE service_id = $1 AND slot_date >= CURRENT_DATE 
              AND slot_date <= CURRENT_DATE + INTERVAL '7 days'
              AND is_booked = FALSE
            ORDER BY slot_date, start_time
        """, service_id)
        
        return templates.TemplateResponse("service_detail.html", {
            "request": request,
            "service": dict(service),
            "time_slots": [dict(slot) for slot in time_slots],
            "current_user": await get_current_user(request)
        })
    finally:
        await conn.close()

# Registration Page
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    current_user = await get_current_user(request)
    if current_user:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse("register.html", {
        "request": request,
        "current_user": current_user
    })

# User Registration
@app.post("/register")
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form("learner"),
    phone: Optional[str] = Form(None),
    profile_image: Optional[UploadFile] = File(None)
):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Check if user exists
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1 OR username = $2",
            email, username
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail="Username or email already registered"
            )
        
        # Hash password
        password_hash = get_password_hash(password)
        
        # Handle profile image upload
        profile_image_path = None
        if profile_image and profile_image.filename:
            profile_image_path = await save_upload_file(profile_image)
        
        # Create user
        user_id = await conn.fetchval("""
            INSERT INTO users (username, email, password_hash, full_name, 
                             role, phone, profile_image, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        """, username, email, password_hash, full_name, role, phone, 
           profile_image_path, role != 'mentor')
        
        # If mentor, create mentor profile (pending approval)
        if role == 'mentor':
            await conn.execute("""
                INSERT INTO mentor_profiles (user_id, experience, industry, 
                                           is_approved)
                VALUES ($1, 0, 'General', FALSE)
            """, user_id)
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user_id)}, 
            expires_delta=access_token_expires
        )
        
        # Set cookie and redirect
        response = RedirectResponse("/dashboard", status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Login Page
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    current_user = await get_current_user(request)
    if current_user:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "current_user": current_user
    })

# User Login
@app.post("/login")
async def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Get user
        user = await conn.fetchrow(
            "SELECT * FROM users WHERE email = $1 AND is_active = TRUE",
            email
        )
        
        if not user or not verify_password(password, user['password_hash']):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user['id'])}, 
            expires_delta=access_token_expires
        )
        
        # Set cookie and redirect
        response = RedirectResponse("/dashboard", status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Logout
@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response

# Dashboard
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse("/login", status_code=303)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        if current_user['role'] == 'learner':
            # Get learner's bookings
            bookings = await conn.fetch("""
                SELECT b.*, s.name as service_name, s.price,
                       u.full_name as mentor_name, u.profile_image as mentor_image
                FROM bookings b
                JOIN services s ON b.service_id = s.id
                JOIN users u ON b.mentor_id = u.id
                WHERE b.learner_id = $1
                ORDER BY b.created_at DESC
                LIMIT 10
            """, current_user['id'])
            
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "current_user": current_user,
                "bookings": [dict(booking) for booking in bookings],
                "user_type": "learner"
            })
            
        elif current_user['role'] == 'mentor':
            # Get mentor profile
            mentor_profile = await conn.fetchrow(
                "SELECT * FROM mentor_profiles WHERE user_id = $1",
                current_user['id']
            )
            
            # Get mentor's bookings
            bookings = await conn.fetch("""
                SELECT b.*, s.name as service_name, s.price,
                       u.full_name as learner_name, u.profile_image as learner_image
                FROM bookings b
                JOIN services s ON b.service_id = s.id
                JOIN users u ON b.learner_id = u.id
                WHERE b.mentor_id = $1
                ORDER BY b.created_at DESC
                LIMIT 10
            """, current_user['id'])
            
            # Get mentor's services
            services = await conn.fetch("""
                SELECT * FROM services WHERE mentor_id = $1
                ORDER BY created_at DESC
            """, current_user['id'])
            
            # Get earnings summary
            earnings = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_bookings,
                    SUM(amount) as total_earnings,
                    SUM(mentor_amount) as mentor_earnings,
                    SUM(platform_fee) as platform_fees
                FROM earnings 
                WHERE mentor_id = $1 AND status = 'paid'
            """, current_user['id'])
            
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "current_user": current_user,
                "mentor_profile": dict(mentor_profile) if mentor_profile else None,
                "bookings": [dict(booking) for booking in bookings],
                "services": [dict(service) for service in services],
                "earnings": dict(earnings) if earnings else {},
                "user_type": "mentor"
            })
            
        elif current_user['role'] == 'admin':
            # Admin dashboard
            return RedirectResponse("/admin/dashboard", status_code=303)
            
    finally:
        await conn.close()

# Create Booking
@app.post("/api/create-booking")
async def create_booking(
    request: Request,
    service_id: int = Form(...),
    booking_date: str = Form(...),
    booking_time: str = Form(...),
    notes: Optional[str] = Form(None)
):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'learner':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Get service details
        service = await conn.fetchrow("""
            SELECT s.*, u.id as mentor_id, u.full_name as mentor_name
            FROM services s
            JOIN users u ON s.mentor_id = u.id
            WHERE s.id = $1 AND s.is_active = TRUE
        """, service_id)
        
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        
        # Create booking
        booking_id = await conn.fetchval("""
            INSERT INTO bookings (
                learner_id, mentor_id, service_id, booking_date, 
                booking_time, amount, status, payment_status, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'pending', 'pending', $7)
            RETURNING id
        """, current_user['id'], service['mentor_id'], service_id, 
           booking_date, booking_time, service['price'], notes)
        
        # For now, return booking ID
        # In production, integrate with Razorpay here
        
        return JSONResponse({
            "success": True,
            "booking_id": booking_id,
            "amount": float(service['price']),
            "message": "Booking created. Redirect to payment..."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Get Available Time Slots API
@app.post("/api/time-slots/{mentor_id}")
async def get_time_slots(
    mentor_id: int,
    date: str = Form(...)
):
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Get available time slots for the date
        slots = await conn.fetch("""
            SELECT ts.id, ts.start_time, ts.end_time
            FROM time_slots ts
            WHERE ts.mentor_id = $1 
              AND ts.slot_date = $2::DATE
              AND ts.is_booked = FALSE
            ORDER BY ts.start_time
        """, mentor_id, date)
        
        # Generate time slots if none exist (for demo)
        if not slots:
            # Generate sample time slots (9 AM to 6 PM)
            slots_data = []
            for hour in range(9, 18):
                slots_data.append(f"{hour:02d}:00")
            
            return JSONResponse({
                "success": True,
                "slots": slots_data
            })
        
        slots_data = [f"{slot['start_time']}" for slot in slots]
        return JSONResponse({
            "success": True,
            "slots": slots_data
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Payment Page
@app.get("/payment/{booking_id}", response_class=HTMLResponse)
async def payment_page(request: Request, booking_id: int):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(f"/login?next=/payment/{booking_id}", status_code=303)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        booking = await conn.fetchrow("""
            SELECT b.*, s.name as service_name, u.full_name as mentor_name
            FROM bookings b
            JOIN services s ON b.service_id = s.id
            JOIN users u ON b.mentor_id = u.id
            WHERE b.id = $1 AND b.learner_id = $2
        """, booking_id, current_user['id'])
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        return templates.TemplateResponse("payment.html", {
            "request": request,
            "current_user": current_user,
            "booking": dict(booking)
        })
    finally:
        await conn.close()

# Process Payment (Razorpay Integration)
@app.post("/api/process-payment")
async def process_payment(
    request: Request,
    booking_id: int = Form(...),
    razorpay_payment_id: str = Form(...),
    razorpay_order_id: str = Form(...),
    razorpay_signature: str = Form(...)
):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Note: In production, verify Razorpay signature here
    # razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Update booking payment status
        await conn.execute("""
            UPDATE bookings 
            SET payment_status = 'paid',
                razorpay_payment_id = $1,
                razorpay_order_id = $2,
                status = 'confirmed',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 AND learner_id = $4
        """, razorpay_payment_id, razorpay_order_id, booking_id, current_user['id'])
        
        # Create earning record
        booking = await conn.fetchrow(
            "SELECT * FROM bookings WHERE id = $1", booking_id
        )
        
        if booking:
            platform_fee = float(booking['amount']) * 0.20  # 20% platform fee
            mentor_amount = float(booking['amount']) - platform_fee
            
            await conn.execute("""
                INSERT INTO earnings (
                    mentor_id, booking_id, amount, 
                    platform_fee, mentor_amount, status
                )
                VALUES ($1, $2, $3, $4, $5, 'pending')
            """, booking['mentor_id'], booking_id, booking['amount'], 
               platform_fee, mentor_amount)
        
        return JSONResponse({
            "success": True,
            "message": "Payment processed successfully"
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Mentor Profile Update
@app.post("/mentor/profile/update")
async def update_mentor_profile(
    request: Request,
    experience: int = Form(...),
    industry: str = Form(...),
    job_title: Optional[str] = Form(None),
    company: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    skills: str = Form(...),
    linkedin_url: Optional[str] = Form(None),
    github_url: Optional[str] = Form(None),
    twitter_url: Optional[str] = Form(None)
):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'mentor':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Update mentor profile
        await conn.execute("""
            UPDATE mentor_profiles 
            SET experience = $1, industry = $2, job_title = $3,
                company = $4, bio = $5, skills = $6,
                linkedin_url = $7, github_url = $8, twitter_url = $9,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $10
        """, experience, industry, job_title, company, bio, skills,
           linkedin_url, github_url, twitter_url, current_user['id'])
        
        return RedirectResponse("/dashboard", status_code=303)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Create Service
@app.post("/mentor/service/create")
async def create_service(
    request: Request,
    name: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    duration: str = Form("1 hour"),
    category: str = Form(...),
    digital_product_link: Optional[str] = Form(None)
):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'mentor':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Create service
        await conn.execute("""
            INSERT INTO services (
                mentor_id, name, description, price, 
                duration, category, digital_product_link
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, current_user['id'], name, description, price, 
           duration, category, digital_product_link)
        
        return RedirectResponse("/dashboard", status_code=303)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Add Time Slots
@app.post("/mentor/time-slots/add")
async def add_time_slots(
    request: Request,
    service_id: int = Form(...),
    slot_date: str = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...)
):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'mentor':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Add time slot
        await conn.execute("""
            INSERT INTO time_slots (
                mentor_id, service_id, slot_date, start_time, end_time
            )
            VALUES ($1, $2, $3, $4, $5)
        """, current_user['id'], service_id, slot_date, start_time, end_time)
        
        return JSONResponse({
            "success": True,
            "message": "Time slot added successfully"
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Admin Dashboard
@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Get pending mentor approvals
        pending_mentors = await conn.fetch("""
            SELECT u.id, u.username, u.email, u.full_name, u.created_at,
                   mp.experience, mp.industry, mp.skills
            FROM users u
            JOIN mentor_profiles mp ON u.id = mp.user_id
            WHERE u.role = 'mentor' AND mp.is_approved = FALSE
            ORDER BY u.created_at DESC
        """)
        
        # Get recent bookings
        recent_bookings = await conn.fetch("""
            SELECT b.*, 
                   u1.full_name as learner_name,
                   u2.full_name as mentor_name,
                   s.name as service_name
            FROM bookings b
            JOIN users u1 ON b.learner_id = u1.id
            JOIN users u2 ON b.mentor_id = u2.id
            JOIN services s ON b.service_id = s.id
            ORDER BY b.created_at DESC
            LIMIT 20
        """)
        
        # Get platform statistics
        stats = await conn.fetchrow("""
            SELECT 
                (SELECT COUNT(*) FROM users WHERE role = 'learner') as total_learners,
                (SELECT COUNT(*) FROM users WHERE role = 'mentor' AND is_active = TRUE) as total_mentors,
                (SELECT COUNT(*) FROM bookings WHERE payment_status = 'paid') as total_bookings,
                (SELECT SUM(amount) FROM bookings WHERE payment_status = 'paid') as total_revenue,
                (SELECT COUNT(*) FROM mentor_profiles WHERE is_approved = FALSE) as pending_approvals
        """)
        
        return templates.TemplateResponse("admin_dashboard.html", {
            "request": request,
            "current_user": current_user,
            "pending_mentors": [dict(mentor) for mentor in pending_mentors],
            "recent_bookings": [dict(booking) for booking in recent_bookings],
            "stats": dict(stats) if stats else {}
        })
    finally:
        await conn.close()

# Approve Mentor
@app.post("/admin/mentor/{mentor_id}/approve")
async def approve_mentor(mentor_id: int, request: Request):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("""
            UPDATE mentor_profiles 
            SET is_approved = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1
        """, mentor_id)
        
        return JSONResponse({
            "success": True,
            "message": "Mentor approved successfully"
        })
    finally:
        await conn.close()

# Terms and Conditions
@app.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request):
    return templates.TemplateResponse("terms.html", {
        "request": request,
        "current_user": await get_current_user(request)
    })

# Privacy Policy
@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request):
    return templates.TemplateResponse("terms.html", {
        "request": request,
        "current_user": await get_current_user(request),
        "page_type": "privacy"
    })


# Booking Confirmation Page
@app.get("/booking/{booking_id}/confirmation", response_class=HTMLResponse)
async def booking_confirmation(request: Request, booking_id: int):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(f"/login?next=/booking/{booking_id}/confirmation", status_code=303)
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        booking = await conn.fetchrow("""
            SELECT b.*, s.name as service_name, s.price as amount,
                   u1.full_name as mentor_name, u1.profile_image as mentor_image,
                   u2.full_name as learner_name
            FROM bookings b
            JOIN services s ON b.service_id = s.id
            JOIN users u1 ON b.mentor_id = u1.id
            JOIN users u2 ON b.learner_id = u2.id
            WHERE b.id = $1 AND (b.learner_id = $2 OR b.mentor_id = $2)
        """, booking_id, current_user['id'])
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        return templates.TemplateResponse("booking_confirmation.html", {
            "request": request,
            "current_user": current_user,
            "booking": dict(booking)
        })
    finally:
        await conn.close()

# Update user profile
@app.post("/profile/update")
async def update_profile(
    request: Request,
    full_name: str = Form(...),
    phone: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    profile_image: Optional[UploadFile] = File(None)
):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Handle profile image upload
        profile_image_path = current_user.get('profile_image')
        if profile_image and profile_image.filename:
            profile_image_path = await save_upload_file(profile_image)
        
        # Update user
        await conn.execute("""
            UPDATE users 
            SET full_name = $1, phone = $2, profile_image = $3, updated_at = CURRENT_TIMESTAMP
            WHERE id = $4
        """, full_name, phone, profile_image_path, current_user['id'])
        
        # If mentor, update mentor profile bio
        if current_user['role'] == 'mentor' and bio:
            await conn.execute("""
                UPDATE mentor_profiles 
                SET bio = $1, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = $2
            """, bio, current_user['id'])
        
        return RedirectResponse("/dashboard", status_code=303)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

# Submit review
@app.post("/review/submit")
async def submit_review(
    request: Request,
    booking_id: int = Form(...),
    rating: int = Form(...),
    comment: str = Form(...)
):
    current_user = await get_current_user(request)
    if not current_user or current_user['role'] != 'learner':
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Check if review already exists
        existing = await conn.fetchrow(
            "SELECT id FROM reviews WHERE booking_id = $1",
            booking_id
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="Review already submitted")
        
        # Get booking details
        booking = await conn.fetchrow("""
            SELECT mentor_id, service_id FROM bookings 
            WHERE id = $1 AND learner_id = $2 AND status = 'completed'
        """, booking_id, current_user['id'])
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        # Create review
        await conn.execute("""
            INSERT INTO reviews (booking_id, learner_id, mentor_id, service_id, rating, comment)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, booking_id, current_user['id'], booking['mentor_id'], booking['service_id'], rating, comment)
        
        # Update mentor rating
        await update_mentor_rating(conn, booking['mentor_id'])
        
        return JSONResponse({
            "success": True,
            "message": "Review submitted successfully"
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()

async def update_mentor_rating(conn, mentor_id):
    """Update mentor's average rating"""
    result = await conn.fetchrow("""
        SELECT 
            AVG(rating) as avg_rating,
            COUNT(*) as review_count
        FROM reviews 
        WHERE mentor_id = $1
    """, mentor_id)
    
    if result and result['avg_rating']:
        await conn.execute("""
            UPDATE mentor_profiles 
            SET rating = $1, review_count = $2, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $3
        """, float(result['avg_rating']), result['review_count'], mentor_id)

# Cancel booking
@app.post("/booking/{booking_id}/cancel")
async def cancel_booking(booking_id: int, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Check if user owns the booking
        booking = await conn.fetchrow("""
            SELECT * FROM bookings 
            WHERE id = $1 AND (learner_id = $2 OR mentor_id = $2)
              AND status NOT IN ('cancelled', 'completed')
        """, booking_id, current_user['id'])
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found or cannot be cancelled")
        
        # Check cancellation window (24 hours)
        booking_time = datetime.combine(
            booking['booking_date'], 
            booking['booking_time']
        )
        time_diff = booking_time - datetime.now()
        
        if time_diff.total_seconds() < 24 * 3600:
            raise HTTPException(
                status_code=400, 
                detail="Cancellation must be made at least 24 hours before the session"
            )
        
        # Update booking status
        await conn.execute("""
            UPDATE bookings 
            SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, booking_id)
        
        # Refund if paid
        if booking['payment_status'] == 'paid':
            await conn.execute("""
                UPDATE bookings 
                SET payment_status = 'refunded', updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
            """, booking_id)
        
        return JSONResponse({
            "success": True,
            "message": "Booking cancelled successfully"
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await conn.close()
