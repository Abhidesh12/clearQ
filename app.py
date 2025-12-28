from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user

from app import db
from models import User, Service, Booking

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    # Get featured mentors
    featured_mentors = User.query.filter_by(
        role='mentor',
        is_verified=True,
        is_active=True
    ).order_by(User.rating.desc()).limit(6).all()
    
    # Get featured services
    featured_services = Service.query.filter_by(
        is_active=True,
        is_featured=True
    ).order_by(Service.created_at.desc()).limit(6).all()
    
    # Get stats
    stats = {
        'mentors': User.query.filter_by(role='mentor', is_verified=True).count() or 0,
        'sessions': Booking.query.filter_by(status='completed').count() or 0,
        'learners': User.query.filter_by(role='learner').count() or 0,
        'success_rate': 95
    }
    
    return render_template(
        'index.html',
        featured_mentors=featured_mentors,
        featured_services=featured_services,
        stats=stats
    )

@main_bp.route('/explore')
def explore():
    query = request.args.get('q', '')
    domain = request.args.get('domain', '')
    sort = request.args.get('sort', 'rating')
    
    # Build query
    mentors_query = User.query.filter_by(
        role='mentor',
        is_verified=True,
        is_active=True
    )
    
    if query:
        mentors_query = mentors_query.filter(
            db.or_(
                User.full_name.ilike(f'%{query}%'),
                User.domain.ilike(f'%{query}%'),
                User.company.ilike(f'%{query}%')
            )
        )
    
    if domain:
        mentors_query = mentors_query.filter(User.domain.ilike(f'%{domain}%'))
    
    # Apply sorting
    if sort == 'rating':
        mentors_query = mentors_query.order_by(User.rating.desc())
    elif sort == 'price_low':
        mentors_query = mentors_query.order_by(User.price.asc())
    elif sort == 'price_high':
        mentors_query = mentors_query.order_by(User.price.desc())
    else:
        mentors_query = mentors_query.order_by(User.created_at.desc())
    
    # Get paginated results
    page = request.args.get('page', 1, type=int)
    mentors = mentors_query.paginate(page=page, per_page=12, error_out=False)
    
    # Get unique domains
    domains = db.session.query(User.domain).filter(
        User.domain.isnot(None),
        User.role == 'mentor',
        User.is_verified == True
    ).distinct().all()
    domains = [d[0] for d in domains if d[0]]
    
    return render_template(
        'explore.html',
        mentors=mentors,
        query=query,
        domain=domain,
        domains=domains,
        sort=sort
    )

@main_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return admin_dashboard()
    elif current_user.role == 'mentor':
        return mentor_dashboard()
    else:
        return learner_dashboard()

def admin_dashboard():
    stats = {
        'total_users': User.query.count() or 0,
        'total_mentors': User.query.filter_by(role='mentor').count() or 0,
        'verified_mentors': User.query.filter_by(role='mentor', is_verified=True).count() or 0,
        'total_learners': User.query.filter_by(role='learner').count() or 0,
        'total_bookings': Booking.query.count() or 0
    }
    
    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_bookings=recent_bookings,
        recent_users=recent_users
    )

def mentor_dashboard():
    stats = {
        'total_bookings': Booking.query.filter_by(mentor_id=current_user.id).count() or 0,
        'pending_bookings': Booking.query.filter_by(mentor_id=current_user.id, status='pending').count() or 0,
        'confirmed_bookings': Booking.query.filter_by(mentor_id=current_user.id, status='confirmed').count() or 0,
        'total_services': Service.query.filter_by(mentor_id=current_user.id, is_active=True).count() or 0
    }
    
    upcoming_bookings = Booking.query.filter(
        Booking.mentor_id == current_user.id,
        Booking.status == 'confirmed',
        Booking.booking_date >= datetime.utcnow()
    ).order_by(Booking.booking_date.asc()).limit(10).all()
    
    return render_template(
        'mentor/dashboard.html',
        stats=stats,
        upcoming_bookings=upcoming_bookings
    )

def learner_dashboard():
    stats = {
        'total_bookings': Booking.query.filter_by(learner_id=current_user.id).count() or 0,
        'upcoming_bookings': Booking.query.filter(
            Booking.learner_id == current_user.id,
            Booking.status == 'confirmed',
            Booking.booking_date >= datetime.utcnow()
        ).count() or 0,
        'completed_sessions': Booking.query.filter_by(
            learner_id=current_user.id,
            status='completed'
        ).count() or 0
    }
    
    upcoming_bookings = Booking.query.filter(
        Booking.learner_id == current_user.id,
        Booking.status == 'confirmed',
        Booking.booking_date >= datetime.utcnow()
    ).order_by(Booking.booking_date.asc()).limit(5).all()
    
    return render_template(
        'learner/dashboard.html',
        stats=stats,
        upcoming_bookings=upcoming_bookings
    )

@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            # Handle profile image
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and file.filename:
                    image_path = save_profile_image(file, current_user.id)
                    if image_path:
                        current_user.profile_image = image_path
            
            # Update profile fields
            current_user.full_name = request.form.get('full_name', '').strip()
            current_user.phone = request.form.get('phone', '').strip()
            current_user.domain = request.form.get('domain', '').strip()
            
            if current_user.role == 'mentor':
                current_user.company = request.form.get('company', '').strip()
                current_user.experience = request.form.get('experience', '').strip()
                current_user.bio = request.form.get('bio', '').strip()
                current_user.price = int(request.form.get('price', 0))
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'danger')
        
        return redirect(url_for('main.profile'))
    
    return render_template('profile.html')

@main_bp.route('/mentor/<username>')
def mentor_public_profile(username):
    mentor = User.query.filter_by(username=username, role='mentor').first_or_404()
    
    # Increment profile views
    mentor.profile_views = mentor.profile_views + 1 if mentor.profile_views else 1
    db.session.commit()
    
    # Get services
    services = Service.query.filter_by(
        mentor_id=mentor.id,
        is_active=True
    ).order_by(Service.created_at.desc()).all()
    
    return render_template(
        'mentor/public_profile.html',
        mentor=mentor,
        services=services
    )
