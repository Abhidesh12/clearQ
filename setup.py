#!/usr/bin/env python3
"""
ClearQ Mentorship Platform Setup Script
"""

import os
import sys
import secrets
import subprocess
from pathlib import Path

def run_command(cmd, check=True):
    """Run shell command and handle output"""
    print(f"Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if check:
            sys.exit(1)
        return None

def create_env_file():
    """Create .env file with secure settings"""
    env_content = f"""# Database
DATABASE_URL=postgresql://clearq_user:password@localhost/clearq_db

# Security
SECRET_KEY={secrets.token_urlsafe(32)}

# Razorpay (get from https://razorpay.com)
RAZORPAY_KEY_ID=your_razorpay_key_id_here
RAZORPAY_KEY_SECRET=your_razorpay_key_secret_here

# Environment
ENVIRONMENT=development

# Optional: Email configuration
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your-email@gmail.com
# SMTP_PASS=your-app-password

# Optional: AWS S3 for file uploads
# AWS_ACCESS_KEY_ID=your_access_key
# AWS_SECRET_ACCESS_KEY=your_secret_key
# AWS_REGION=ap-south-1
# AWS_BUCKET_NAME=clearq-uploads
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("Created .env file. Please update with your actual values.")
    print("Don't forget to update Razorpay credentials!")

def create_upload_directories():
    """Create necessary upload directories"""
    directories = [
        'static/uploads/profile_pics',
        'static/uploads/digital_products',
        'static/uploads/temp'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    print("Installing dependencies...")
    run_command("pip install -r requirements.txt")

def setup_database():
    """Setup PostgreSQL database"""
    print("Setting up database...")
    
    # Check if PostgreSQL is installed
    try:
        run_command("psql --version", check=False)
    except:
        print("PostgreSQL is not installed. Please install it first.")
        print("On Ubuntu: sudo apt-get install postgresql postgresql-contrib")
        print("On macOS: brew install postgresql")
        sys.exit(1)
    
    # Create database (adjust for your system)
    print("Creating database...")
    run_command("""
        sudo -u postgres psql -c "CREATE DATABASE clearq_db;" || true
        sudo -u postgres psql -c "CREATE USER clearq_user WITH PASSWORD 'password';" || true
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE clearq_db TO clearq_user;" || true
        sudo -u postgres psql -c "ALTER USER clearq_user CREATEDB;" || true
    """, check=False)

def setup_git():
    """Initialize git repository"""
    if not Path('.git').exists():
        print("Initializing git repository...")
        run_command("git init")
        run_command("git add .")
        run_command('git commit -m "Initial commit: ClearQ Mentorship Platform"')

def main():
    """Main setup function"""
    print("=" * 60)
    print("ClearQ Mentorship Platform Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Create necessary files and directories
    print("\n1. Creating project structure...")
    create_upload_directories()
    create_env_file()
    
    print("\n2. Installing dependencies...")
    install_dependencies()
    
    print("\n3. Setting up database...")
    setup_database()
    
    print("\n4. Initializing git...")
    setup_git()
    
    print("\n" + "=" * 60)
    print("Setup complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Update .env file with your actual credentials")
    print("2. Create Razorpay account at https://razorpay.com")
    print("3. Get API keys from Razorpay dashboard")
    print("4. Run the application: uvicorn app:app --reload")
    print("5. Visit http://localhost:8000 in your browser")
    print("\nOptional: Set up production deployment:")
    print("- Deploy to Render: git push render main")
    print("- Set up SSL certificates")
    print("- Configure domain name")
    print("\nFor help, visit: https://github.com/yourusername/clearq")

if __name__ == "__main__":
    main()
