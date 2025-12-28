from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum

class UserRole(enum.Enum):
    LEARNER = "learner"
    MENTOR = "mentor"
    ADMIN = "admin"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    profile_image = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.LEARNER)
    phone = Column(String(20))
    bio = Column(Text)
    location = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Relationships
    mentor_profile = relationship("MentorProfile", back_populates="user", uselist=False)
    learner_profile = relationship("LearnerProfile", back_populates="user", uselist=False)
    bookings_as_learner = relationship("Booking", foreign_keys="Booking.learner_id", back_populates="learner")
    bookings_as_mentor = relationship("Booking", foreign_keys="Booking.mentor_id", back_populates="mentor")
    reviews_given = relationship("Review", foreign_keys="Review.learner_id", back_populates="learner")
    reviews_received = relationship("Review", foreign_keys="Review.mentor_id", back_populates="mentor")

class MentorProfile(Base):
    __tablename__ = "mentor_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    job_title = Column(String(100))
    company = Column(String(100))
    experience_years = Column(Integer)
    industry = Column(String(100))
    skills = Column(Text)  # Comma separated skills
    hourly_rate = Column(Float, default=0)
    linkedin_url = Column(String(255))
    github_url = Column(String(255))
    portfolio_url = Column(String(255))
    is_verified = Column(Boolean, default=False)
    verification_status = Column(String(50), default="pending")  # pending, approved, rejected
    verification_notes = Column(Text)
    rating = Column(Float, default=0.0)
    total_reviews = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)
    availability = Column(JSON)  # Store availability schedule
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="mentor_profile")
    services = relationship("Service", back_populates="mentor")
    time_slots = relationship("TimeSlot", back_populates="mentor")

class LearnerProfile(Base):
    __tablename__ = "learner_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    current_role = Column(String(100))
    experience_level = Column(String(50))  # beginner, intermediate, advanced
    learning_goals = Column(Text)
    interests = Column(Text)  # Comma separated interests
    education = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="learner_profile")

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentor_profiles.id"))
    name = Column(String(100), nullable=False)
    description = Column(Text)
    category = Column(String(50))  # mock_interview, resume_review, career_guidance, etc.
    price = Column(Float, nullable=False)
    duration_minutes = Column(Integer, default=60)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    mentor = relationship("MentorProfile", back_populates="services")
    bookings = relationship("Booking", back_populates="service")

class TimeSlot(Base):
    __tablename__ = "time_slots"
    
    id = Column(Integer, primary_key=True, index=True)
    mentor_id = Column(Integer, ForeignKey("mentor_profiles.id"))
    service_id = Column(Integer, ForeignKey("services.id"))
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    is_booked = Column(Boolean, default=False)
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    mentor = relationship("MentorProfile", back_populates="time_slots")
    service = relationship("Service")
    booking = relationship("Booking", back_populates="time_slot", uselist=False)

class Booking(Base):
    __tablename__ = "bookings"
    
    id = Column(Integer, primary_key=True, index=True)
    booking_id = Column(String(50), unique=True, index=True)
    learner_id = Column(Integer, ForeignKey("users.id"))
    mentor_id = Column(Integer, ForeignKey("users.id"))
    service_id = Column(Integer, ForeignKey("services.id"))
    time_slot_id = Column(Integer, ForeignKey("time_slots.id"), unique=True)
    status = Column(String(50), default="pending")  # pending, confirmed, completed, cancelled
    amount = Column(Float, nullable=False)
    razorpay_order_id = Column(String(255))
    razorpay_payment_id = Column(String(255))
    razorpay_signature = Column(String(255))
    meeting_link = Column(String(500))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scheduled_for = Column(DateTime(timezone=True))
    
    # Relationships
    learner = relationship("User", foreign_keys=[learner_id], back_populates="bookings_as_learner")
    mentor = relationship("User", foreign_keys=[mentor_id], back_populates="bookings_as_mentor")
    service = relationship("Service", back_populates="bookings")
    time_slot = relationship("TimeSlot", back_populates="booking")
    review = relationship("Review", back_populates="booking", uselist=False)

class Review(Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    booking_id = Column(Integer, ForeignKey("bookings.id"), unique=True)
    learner_id = Column(Integer, ForeignKey("users.id"))
    mentor_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer, nullable=False)  # 1-5
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    booking = relationship("Booking", back_populates="review")
    learner = relationship("User", foreign_keys=[learner_id], back_populates="reviews_given")
    mentor = relationship("User", foreign_keys=[mentor_id], back_populates="reviews_received")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(200))
    message = Column(Text)
    type = Column(String(50))  # booking, payment, system, etc.
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User")
