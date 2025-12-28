import os
from datetime import timedelta

class Config:
    """Base configuration"""
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'csrf-secret-key-change')
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)
    
    if not SQLALCHEMY_DATABASE_URI:
        # Default to SQLite for development
        basedir = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(basedir, 'instance', 'clearq.db')}"
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20,
    }
    
    # File Uploads
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', 'mp4', 'mov', 'avi', 'mp3', 'wav', 'm4a'}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    
    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@clearq.in')
    
    # Razorpay
    RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
    RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
    
    # Flask-Limiter
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"
    
    # Flask-Login
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_PROTECTION = 'strong'
    
    # Application
    APP_NAME = "ClearQ"
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@clearq.in')
    SUPPORT_EMAIL = os.environ.get('SUPPORT_EMAIL', 'support@clearq.in')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
