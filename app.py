from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func
from datetime import datetime, timedelta
import os
from typing import Optional, List
import uuid
import json
from fastapi import Query
from urllib.parse import quote
from jose import JWTError, jwt

from database import get_db, Base, engine
from models import *
from auth import *
from payment import *

# Create database tables
Base.metadata.create_all(bind=engine)

# ======= START: ADMIN CREATION CODE =======
# Import SessionLocal if not already imported
# Add this at the top of your imports if needed:
# from database import SessionLocal

try:
    # 1. Create a database session
    db = SessionLocal()  # Gets a connection to your database
    
    # 2. Check if an admin user already exists
    admin_exists = db.query(User).filter(User.role == UserRole.ADMIN).first()
    
    if not admin_exists:
        # 3. Create a new admin user
        admin_user = User(
            username="admin",                    # Login username
            email="admin@clearq.com",            # Admin email
            hashed_password=get_password_hash("Admin123!"),  # Hashed password
            full_name="System Administrator",    # Display name
            role=UserRole.ADMIN,                 # Set role as ADMIN
            is_active=True                       # Activate the account
        )
        
        # 4. Save to database
        db.add(admin_user)
        db.commit()  # Save changes
        
        # 5. Print confirmation (visible in Render logs)
        print("✅ Default admin user created")
        print("   Username: admin")
        print("   Password: Admin123!")
        print("   Login at: /login")
    else:
        # 6. If admin already exists
        print("✅ Admin user already exists")
        print(f"   Username: {admin_exists.username}")
        print(f"   Email: {admin_exists.email}")
    
    # 7. Close database connection
    db.close()
    
except Exception as e:
    # 8. Handle any errors gracefully
    print(f"⚠️ Error checking/creating admin: {e}")
    print("Continuing without admin creation...")

app = FastAPI(title="ClearQ Mentorship Platform")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Upload directory
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Dependency for templates
@app.middleware("http")
async def add_user_to_request(request: Request, call_next):
    request.state.db = next(get_db())
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            user = request.state.db.query(User).filter(User.username == username).first()
            if user:
                # Add is_authenticated attribute for templates
                user.is_authenticated = True
                request.state.current_user = user
            else:
                request.state.current_user = None
        except:
            request.state.current_user = None
    else:
        request.state.current_user = None
    
    response = await call_next(request)
    return response

# Helper functions
def save_upload_file(file: UploadFile, user_id: int) -> str:
    filename = f"user_{user_id}_{int(datetime.now().timestamp())}_{file.filename}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "wb") as buffer:
        content = file.file.read()
        buffer.write(content)
    return f"uploads/{filename}"

def generate_booking_id():
    return f"BK{int(datetime.now().timestamp())}{uuid.uuid4().hex[:6].upper()}"

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None)
    })

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None)
    })
@app.post("/mentor/profile/update")
async def update_mentor_profile(
    request: Request,
    job_title: Optional[str] = Form(None),
    company: Optional[str] = Form(None),
    experience_years: Optional[int] = Form(None),
    industry: Optional[str] = Form(None),
    skills: Optional[str] = Form(None),
    hourly_rate: Optional[float] = Form(None),
    linkedin_url: Optional[str] = Form(None),
    twitter_url: Optional[str] = Form(None),
    github_url: Optional[str] = Form(None),
    portfolio_url: Optional[str] = Form(None),
    youtube_url: Optional[str] = Form(None),
    facebook_url: Optional[str] = Form(None),
    instagram_url: Optional[str] = Form(None),
    website_url: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.MENTOR:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    mentor = db.query(MentorProfile).filter(MentorProfile.user_id == current_user.id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    # Update mentor profile fields if provided
    if job_title is not None:
        mentor.job_title = job_title
    if company is not None:
        mentor.company = company
    if experience_years is not None:
        mentor.experience_years = experience_years
    if industry is not None:
        mentor.industry = industry
    if skills is not None:
        mentor.skills = skills
    if hourly_rate is not None:
        mentor.hourly_rate = hourly_rate
    
    # Social URLs
    if linkedin_url is not None:
        mentor.linkedin_url = linkedin_url
    if twitter_url is not None:
        mentor.twitter_url = twitter_url
    if github_url is not None:
        mentor.github_url = github_url
    if portfolio_url is not None:
        mentor.portfolio_url = portfolio_url
    if youtube_url is not None:
        mentor.youtube_url = youtube_url
    if facebook_url is not None:
        mentor.facebook_url = facebook_url
    if instagram_url is not None:
        mentor.instagram_url = instagram_url
    if website_url is not None:
        mentor.website_url = website_url
    
    db.commit()
    
    return JSONResponse({"success": True, "message": "Profile updated successfully"})
@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if user exists
    existing_user = db.query(User).filter(
        or_(User.username == username, User.email == email)
    ).first()
    
    if existing_user:
        return RedirectResponse(
            url=f"/register?message={quote('Username or email already exists')}&type=error",
            status_code=303
        )
    
    # Create user
    try:
        user_role = UserRole(role)
    except ValueError:
        return RedirectResponse(
            url=f"/register?message={quote('Invalid role selected')}&type=error",
            status_code=303
        )
    
    user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        full_name=full_name,
        role=user_role
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create profile based on role
    if user_role == UserRole.LEARNER:
        learner_profile = LearnerProfile(user_id=user.id)
        db.add(learner_profile)
    elif user_role == UserRole.MENTOR:
        mentor_profile = MentorProfile(user_id=user.id)
        db.add(mentor_profile)
    
    db.commit()
    
    # Create token and set cookie
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, message: Optional[str] = Query(None), type: Optional[str] = Query(None)):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None),
        "message": message,
        "message_type": type
    })

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, username, password)
    if not user:
        # Redirect with error message
        return RedirectResponse(
            url=f"/login?message={quote('Incorrect username or password')}&type=error",
            status_code=303
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie(key="access_token")
    return response

@app.get("/explore", response_class=HTMLResponse)
async def explore(
    request: Request,
    category: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(User).join(MentorProfile).filter(
        User.role == UserRole.MENTOR,
        MentorProfile.is_verified == True,
        User.is_active == True
    )
    
    if search:
        query = query.filter(
            or_(
                User.full_name.ilike(f"%{search}%"),
                MentorProfile.skills.ilike(f"%{search}%"),
                MentorProfile.industry.ilike(f"%{search}%")
            )
        )
    
    mentors = query.all()
    
    # Add mentor_profile to each user if not present
    for mentor in mentors:
        if not hasattr(mentor, 'mentor_profile'):
            mentor.mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == mentor.id).first()
    
    return templates.TemplateResponse("explore.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None),
        "mentors": mentors,
        "search": search,
        "category": category
    })

@app.get("/mentor/{mentor_username}", response_class=HTMLResponse)
async def mentor_profile(
    request: Request,
    mentor_username: str,
    db: Session = Depends(get_db)
):
    mentor = db.query(User).filter(
        User.username == mentor_username,
        User.role == UserRole.MENTOR
    ).first()
    
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    # Get mentor profile
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == mentor.id).first()
    if not mentor_profile:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    mentor.mentor_profile = mentor_profile
    
    services = db.query(Service).filter(
        Service.mentor_id == mentor_profile.id,
        Service.is_active == True
    ).all()
    
    # Get available dates (next 7 days)
    available_dates = []
    for i in range(7):
        date = datetime.now() + timedelta(days=i)
        available_dates.append({
            "full_date": date.strftime("%Y-%m-%d"),
            "day_name": date.strftime("%a"),
            "day_num": date.day,
            "month": date.strftime("%b")
        })
    
    return templates.TemplateResponse("mentor_profile.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None),
        "mentor": mentor,
        "services": services,
        "available_dates": available_dates
    })

@app.get("/service/{service_id}", response_class=HTMLResponse)
async def service_detail(
    request: Request,
    service_id: int,
    db: Session = Depends(get_db)
):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get mentor
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.id == service.mentor_id).first()
    if not mentor_profile:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    mentor = db.query(User).filter(User.id == mentor_profile.user_id).first()
    
    return templates.TemplateResponse("service_detail.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None),
        "service": service,
        "mentor": mentor
    })

@app.get("/book/{service_id}", response_class=HTMLResponse)
async def booking_page(
    request: Request,
    service_id: int,
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.LEARNER:
        return RedirectResponse(url="/login")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get available time slots
    time_slots = db.query(TimeSlot).filter(
        TimeSlot.service_id == service_id,
        TimeSlot.is_booked == False,
        TimeSlot.is_available == True,
        TimeSlot.start_time >= datetime.now()
    ).order_by(TimeSlot.start_time).all()
    
    return templates.TemplateResponse("booking.html", {
        "request": request,
        "current_user": current_user,
        "service": service,
        "time_slots": time_slots
    })

@app.post("/api/create-booking")
async def create_booking(
    request: Request,
    service_id: int = Form(...),
    time_slot_id: int = Form(...),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.LEARNER:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get service and time slot
    service = db.query(Service).filter(Service.id == service_id).first()
    time_slot = db.query(TimeSlot).filter(
        TimeSlot.id == time_slot_id,
        TimeSlot.is_booked == False
    ).first()
    
    if not service or not time_slot:
        raise HTTPException(status_code=404, detail="Service or time slot not available")
    
    # Get mentor
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.id == service.mentor_id).first()
    if not mentor_profile:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    # Create booking
    booking = Booking(
        booking_id=generate_booking_id(),
        learner_id=current_user.id,
        mentor_id=mentor_profile.user_id,
        service_id=service_id,
        time_slot_id=time_slot_id,
        amount=service.price,
        scheduled_for=time_slot.start_time,
        notes=notes,
        status="pending"
    )
    
    # Mark time slot as booked
    time_slot.is_booked = True
    
    db.add(booking)
    db.commit()
    db.refresh(booking)
    
    # Create Razorpay order
    try:
        order = create_order(service.price, receipt=booking.booking_id)
        
        # Update booking with order ID
        booking.razorpay_order_id = order["id"]
        db.commit()
        
        return JSONResponse({
            "success": True,
            "booking_id": booking.id,
            "razorpay_order_id": order["id"],
            "razorpay_key": RAZORPAY_KEY_ID,
            "amount": service.price * 100  # In paise
        })
    except Exception as e:
        # Rollback booking if payment order creation fails
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create payment order: {str(e)}")

@app.get("/payment/{booking_id}", response_class=HTMLResponse)
async def payment_page(
    request: Request,
    booking_id: int,
    db: Session = Depends(get_db)
):
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Get service details
    service = db.query(Service).filter(Service.id == booking.service_id).first()
    mentor = db.query(User).filter(User.id == booking.mentor_id).first()
    
    return templates.TemplateResponse("payment.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None),
        "booking": booking,
        "service": service,
        "mentor": mentor,
        "razorpay_key": RAZORPAY_KEY_ID
    })

@app.post("/api/verify-payment")
async def verify_payment(
    request: Request,
    razorpay_order_id: str = Form(...),
    razorpay_payment_id: str = Form(...),
    razorpay_signature: str = Form(...),
    db: Session = Depends(get_db)
):
    # Verify signature
    if not verify_payment_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    
    # Update booking
    booking = db.query(Booking).filter(
        Booking.razorpay_order_id == razorpay_order_id
    ).first()
    
    if booking:
        booking.razorpay_payment_id = razorpay_payment_id
        booking.razorpay_signature = razorpay_signature
        booking.status = "confirmed"
        db.commit()
    
    return JSONResponse({"success": True, "message": "Payment verified successfully"})

# Dashboard Routes
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user:
        return RedirectResponse(url="/login")
    
    if current_user.role == UserRole.LEARNER:
        return RedirectResponse(url="/dashboard/learner")
    elif current_user.role == UserRole.MENTOR:
        return RedirectResponse(url="/dashboard/mentor")
    elif current_user.role == UserRole.ADMIN:
        return RedirectResponse(url="/dashboard/admin")
    
    return RedirectResponse(url="/")

@app.get("/dashboard/learner", response_class=HTMLResponse)
async def learner_dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.LEARNER:
        return RedirectResponse(url="/login")
    
    # Get bookings
    bookings = db.query(Booking).filter(
        Booking.learner_id == current_user.id
    ).order_by(Booking.created_at.desc()).all()
    
    # Get details for each booking
    for booking in bookings:
        booking.service = db.query(Service).filter(Service.id == booking.service_id).first()
        booking.mentor = db.query(User).filter(User.id == booking.mentor_id).first()
        booking.time_slot = db.query(TimeSlot).filter(TimeSlot.id == booking.time_slot_id).first()
    
    return templates.TemplateResponse("dashboard_learner.html", {
        "request": request,
        "current_user": current_user,
        "bookings": bookings
    })

@app.get("/dashboard/mentor", response_class=HTMLResponse)
async def mentor_dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.MENTOR:
        return RedirectResponse(url="/login")
    
    # Get mentor profile
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == current_user.id).first()
    if not mentor_profile:
        # Create mentor profile if it doesn't exist
        mentor_profile = MentorProfile(user_id=current_user.id)
        db.add(mentor_profile)
        db.commit()
        db.refresh(mentor_profile)
    
    current_user.mentor_profile = mentor_profile
    
    # Get bookings
    bookings = db.query(Booking).filter(
        Booking.mentor_id == current_user.id
    ).order_by(Booking.created_at.desc()).all()
    
    # Get details for each booking
    for booking in bookings:
        booking.service = db.query(Service).filter(Service.id == booking.service_id).first()
        booking.learner = db.query(User).filter(User.id == booking.learner_id).first()
        booking.time_slot = db.query(TimeSlot).filter(TimeSlot.id == booking.time_slot_id).first()
    
    # Get services
    services = db.query(Service).filter(
        Service.mentor_id == mentor_profile.id
    ).all()
    
    # Get earnings
    total_earnings = db.query(func.sum(Booking.amount)).filter(
        Booking.mentor_id == current_user.id,
        Booking.status.in_(["confirmed", "completed"])
    ).scalar() or 0
    
    # Get reviews
    reviews = db.query(Review).filter(
        Review.mentor_id == current_user.id
    ).order_by(Review.created_at.desc()).all()
    
    # Add learner details to reviews
    for review in reviews:
        review.learner = db.query(User).filter(User.id == review.learner_id).first()
    
    current_user.reviews_received = reviews[:3]  # Only show 3 recent reviews
    
    return templates.TemplateResponse("dashboard_mentor.html", {
        "request": request,
        "current_user": current_user,
        "bookings": bookings,
        "services": services,
        "total_earnings": total_earnings
    })

@app.get("/dashboard/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.ADMIN:
        return RedirectResponse(url="/login")
    
    # Get pending mentor verifications
    pending_mentors = db.query(User).join(MentorProfile).filter(
        User.role == UserRole.MENTOR,
        MentorProfile.verification_status == "pending"
    ).all()
    
    # Add mentor_profile to each user
    for mentor in pending_mentors:
        mentor.mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == mentor.id).first()
    
    # Get statistics
    total_users = db.query(User).count()
    total_mentors = db.query(User).filter(User.role == UserRole.MENTOR).count()
    total_learners = db.query(User).filter(User.role == UserRole.LEARNER).count()
    total_bookings = db.query(Booking).count()
    total_revenue = db.query(func.sum(Booking.amount)).filter(
        Booking.status.in_(["confirmed", "completed"])
    ).scalar() or 0
    
    return templates.TemplateResponse("dashboard_admin.html", {
        "request": request,
        "current_user": current_user,
        "pending_mentors": pending_mentors,
        "stats": {
            "total_users": total_users,
            "total_mentors": total_mentors,
            "total_learners": total_learners,
            "total_bookings": total_bookings,
            "total_revenue": total_revenue
        }
    })

@app.post("/api/admin/verify-mentor/{mentor_id}")
async def verify_mentor(
    request: Request,
    mentor_id: int,
    status: str = Form(...),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    mentor = db.query(MentorProfile).filter(MentorProfile.user_id == mentor_id).first()
    if not mentor:
        raise HTTPException(status_code=404, detail="Mentor not found")
    
    mentor.verification_status = status
    mentor.is_verified = (status == "approved")
    if notes:
        mentor.verification_notes = notes
    
    db.commit()
    
    return JSONResponse({"success": True, "message": f"Mentor {status} successfully"})

# Profile Edit
@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile_page(request: Request, db: Session = Depends(get_db)):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("profile_edit.html", {
        "request": request,
        "current_user": current_user
    })

@app.post("/profile/update")
async def update_profile(
    request: Request,
    full_name: str = Form(...),
    bio: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
    profile_image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get user from database
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update user info
    user.full_name = full_name
    user.bio = bio
    user.phone = phone
    user.location = location
    
    # Handle profile image upload
    if profile_image and profile_image.filename:
        filename = save_upload_file(profile_image, user.id)
        user.profile_image = filename
    
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=303)

# Mentor registration (additional details)
@app.get("/mentor/register", response_class=HTMLResponse)
async def mentor_register_page(request: Request, db: Session = Depends(get_db)):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.MENTOR:
        return RedirectResponse(url="/login")
    
    # Get mentor profile if exists
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == current_user.id).first()
    
    return templates.TemplateResponse("mentor_register.html", {
        "request": request,
        "current_user": current_user,
        "mentor_profile": mentor_profile
    })

@app.post("/mentor/register")
async def mentor_register(
    request: Request,
    job_title: str = Form(...),
    company: str = Form(...),
    experience_years: int = Form(...),
    industry: str = Form(...),
    skills: str = Form(...),
    hourly_rate: float = Form(...),
    linkedin_url: Optional[str] = Form(None),
    twitter_url: Optional[str] = Form(None),
    github_url: Optional[str] = Form(None),
    portfolio_url: Optional[str] = Form(None),
    youtube_url: Optional[str] = Form(None),
    facebook_url: Optional[str] = Form(None),
    instagram_url: Optional[str] = Form(None),
    website_url: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.MENTOR:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get or create mentor profile
    mentor = db.query(MentorProfile).filter(MentorProfile.user_id == current_user.id).first()
    if not mentor:
        mentor = MentorProfile(user_id=current_user.id)
        db.add(mentor)
    
    # Update mentor profile
    mentor.job_title = job_title
    mentor.company = company
    mentor.experience_years = experience_years
    mentor.industry = industry
    mentor.skills = skills
    mentor.hourly_rate = hourly_rate
    
    # Social URLs
    mentor.linkedin_url = linkedin_url
    mentor.twitter_url = twitter_url
    mentor.github_url = github_url
    mentor.portfolio_url = portfolio_url
    mentor.youtube_url = youtube_url
    mentor.facebook_url = facebook_url
    mentor.instagram_url = instagram_url
    mentor.website_url = website_url
    
    mentor.verification_status = "pending"
    
    # Update user bio
    if bio:
        current_user.bio = bio
        db.add(current_user)
    
    db.commit()
    
    return RedirectResponse(url="/dashboard/mentor", status_code=303)
# Mentorship Program Page
@app.get("/mentorship-program", response_class=HTMLResponse)
async def mentorship_program(request: Request):
    return templates.TemplateResponse("mentorship_program.html", {
        "request": request,
        "current_user": getattr(request.state, 'current_user', None)
    })

# API endpoints for AJAX calls
@app.post("/api/time-slots/{mentor_id}")
async def get_time_slots(
    request: Request,
    mentor_id: int,
    date: str,
    service_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    # Parse date
    try:
        target_date = datetime.strptime(date, "%Y-%m-%d")
        next_day = target_date + timedelta(days=1)
    except:
        return JSONResponse({"success": False, "message": "Invalid date format"})
    
    # Query time slots
    query = db.query(TimeSlot).filter(
        TimeSlot.mentor_id == mentor_id,
        TimeSlot.start_time >= target_date,
        TimeSlot.start_time < next_day,
        TimeSlot.is_booked == False,
        TimeSlot.is_available == True
    )
    
    if service_id:
        query = query.filter(TimeSlot.service_id == service_id)
    
    time_slots = query.order_by(TimeSlot.start_time).all()
    
    # Format slots
    slots = []
    for slot in time_slots:
        slots.append({
            "id": slot.id,
            "start": slot.start_time.strftime("%H:%M"),
            "end": slot.end_time.strftime("%H:%M"),
            "service_id": slot.service_id
        })
    
    return JSONResponse({"success": True, "slots": slots})

@app.post("/api/mentor/time-slots")
async def create_time_slots(
    request: Request,
    start_date: str = Form(...),
    end_date: str = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    days: List[str] = Form(...),
    service_id: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    current_user = getattr(request.state, 'current_user', None)
    if not current_user or current_user.role != UserRole.MENTOR:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    mentor_profile = db.query(MentorProfile).filter(MentorProfile.user_id == current_user.id).first()
    if not mentor_profile:
        raise HTTPException(status_code=404, detail="Mentor profile not found")
    
    # Parse dates and times
    try:
        start_date_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_date_dt = datetime.strptime(end_date, "%Y-%m-%d")
        start_time_dt = datetime.strptime(start_time, "%H:%M")
        end_time_dt = datetime.strptime(end_time, "%H:%M")
    except:
        return JSONResponse({"success": False, "message": "Invalid date/time format"})
    
    # Create slots for each day in range
    created_slots = 0
    current_date = start_date_dt
    
    while current_date <= end_date_dt:
        day_name = current_date.strftime("%A")
        
        if day_name in days:
            # Create time slot
            slot_start = datetime.combine(current_date, start_time_dt.time())
            slot_end = datetime.combine(current_date, end_time_dt.time())
            
            time_slot = TimeSlot(
                mentor_id=mentor_profile.id,
                service_id=service_id,
                start_time=slot_start,
                end_time=slot_end
            )
            
            db.add(time_slot)
            created_slots += 1
        
        current_date += timedelta(days=1)
    
    db.commit()
    
    return JSONResponse({
        "success": True,
        "message": f"Created {created_slots} time slots"
    })

# Health check endpoint for Render
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)



