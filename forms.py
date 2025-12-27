# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DecimalField, BooleanField, DateField, TimeField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from datetime import datetime

class RegistrationForm(FlaskForm):
    # Common fields
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    
    # Role selector
    role = StringField('Role', validators=[DataRequired()])
    
    # Learner-specific fields
    # (Add any learner-specific fields here)
    
    # Mentor-specific fields
    full_name = StringField('Full Name')
    phone = StringField('Phone Number')
    job_title = StringField('Job Title')
    company = StringField('Company')
    domain = SelectField('Primary Domain', choices=[
        ('', 'Select Domain'),
        ('technology', 'Technology'),
        ('business', 'Business'),
        ('design', 'Design'),
        ('marketing', 'Marketing'),
        ('finance', 'Finance'),
        ('healthcare', 'Healthcare'),
        ('education', 'Education'),
        ('other', 'Other')
    ])
    experience = SelectField('Years of Experience', choices=[
        ('', 'Select Experience'),
        ('1-3', '1-3 years'),
        ('4-6', '4-6 years'),
        ('7-10', '7-10 years'),
        ('10+', '10+ years')
    ])
    skills = StringField('Skills')  # This will be populated by JavaScript
    bio = TextAreaField('Professional Bio', validators=[Length(min=100)])
    
    # Service prices
    resume_review_price = DecimalField('Resume Review Price', places=2)
    mock_interview_price = DecimalField('Mock Interview Price', places=2)
    career_guidance_price = DecimalField('Career Guidance Price', places=2)
    skill_training_price = DecimalField('Skill Training Price', places=2)
    
    # Availability
    available_days = StringField('Available Days')  # Simplified for example
    start_time = TimeField('Start Time')
    end_time = TimeField('End Time')
    available_from = DateField('Available From', default=datetime.utcnow)
    
    # Terms
    terms = BooleanField('I agree to terms', validators=[DataRequired()])
    
    def validate_username(self, username):
        # Check if username exists in database
        # Add your database check here
        pass
