import os
import re
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
from flask import current_app
from werkzeug.utils import secure_filename
from PIL import Image
import bleach

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in current_app.config['ALLOWED_EXTENSIONS']

def validate_file(file) -> Tuple[bool, str]:
    """Validate uploaded file"""
    if not file or file.filename == '':
        return False, 'No file selected'
    
    if not allowed_file(file.filename):
        allowed = ', '.join(current_app.config['ALLOWED_EXTENSIONS'])
        return False, f'File type not allowed. Allowed types: {allowed}'
    
    # Check file size
    try:
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)  # Reset position
        
        if size > current_app.config['MAX_CONTENT_LENGTH']:
            max_mb = current_app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
            return False, f'File too large. Maximum size is {max_mb}MB'
    except Exception:
        return False, 'Error reading file'
    
    # Check filename
    filename = secure_filename(file.filename)
    if not filename:
        return False, 'Invalid filename'
    
    return True, 'File valid'

def save_profile_image(file, user_id: int) -> Optional[str]:
    """Save and resize profile image"""
    valid, message = validate_file(file)
    if not valid:
        return None
    
    # Create filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{user_id}_{timestamp}.{ext}"
    
    # Ensure directory exists
    upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'profile_images')
    os.makedirs(upload_dir, exist_ok=True)
    
    filepath = os.path.join(upload_dir, filename)
    
    try:
        # Save original
        file.save(filepath)
        
        # Create thumbnail
        try:
            with Image.open(filepath) as img:
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                # Resize
                img.thumbnail((300, 300))
                
                # Save thumbnail
                thumb_path = os.path.join(upload_dir, f"thumb_{filename}")
                img.save(thumb_path, 'JPEG', quality=85)
        except Exception as e:
            current_app.logger.error(f"Error creating thumbnail: {e}")
        
        return f'uploads/profile_images/{filename}'
        
    except Exception as e:
        current_app.logger.error(f"Error saving profile image: {e}")
        return None

def generate_slug(text: str) -> str:
    """Generate URL-friendly slug"""
    if not text:
        return str(uuid.uuid4())[:8]
    
    # Convert to lowercase
    slug = text.lower()
    # Remove special characters
    slug = re.sub(r'[^\w\s-]', '', slug)
    # Replace spaces with hyphens
    slug = re.sub(r'[-\s]+', '-', slug)
    # Trim
    slug = slug.strip('-')
    
    return slug[:100] if slug else str(uuid.uuid4())[:8]

def sanitize_html(content: str) -> str:
    """Sanitize HTML to prevent XSS"""
    if not content:
        return ''
    
    # Allowed tags and attributes
    allowed_tags = [
        'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'li', 
        'ol', 'p', 'pre', 'span', 'strong', 'ul'
    ]
    
    allowed_attrs = {
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'div': ['class'],
        'span': ['class'],
        'code': ['class']
    }
    
    # Clean HTML
    cleaned = bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
    
    # Add security to external links
    cleaned = re.sub(
        r'<a\s+(?![^>]*\brel=)[^>]*\bhref=[\'"]?http[^>]*>',
        lambda m: m.group(0).replace('<a ', '<a rel="noopener noreferrer" '),
        cleaned
    )
    
    return cleaned
