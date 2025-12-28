from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Add new columns to mentor_profiles table
def add_social_url_columns():
    # For SQLite
    if "sqlite" in DATABASE_URL:
        with engine.begin() as conn:
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN twitter_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN youtube_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN facebook_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN instagram_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN website_url VARCHAR(255)
            """)
    # For PostgreSQL
    else:
        with engine.begin() as conn:
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN IF NOT EXISTS twitter_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN IF NOT EXISTS youtube_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN IF NOT EXISTS facebook_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN IF NOT EXISTS instagram_url VARCHAR(255)
            """)
            conn.execute("""
                ALTER TABLE mentor_profiles 
                ADD COLUMN IF NOT EXISTS website_url VARCHAR(255)
            """)
    
    print("✅ Social URL columns added successfully!")

if __name__ == "__main__":
    add_social_url_columns()
