from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, IntegerField, DateField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_wtf.file import FileField, FileAllowed

class BaseUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])

class LearnerRegistrationForm(BaseUserForm):
    pass  # Uses only the base fields

class MentorRegistrationForm(BaseUserForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    phone = StringField('Phone Number')
    job_title = StringField('Job Title', validators=[DataRequired()])
    company = StringField('Company', validators=[DataRequired()])
    domain = SelectField('Primary Domain', choices=[
        ('', 'Select Domain'),
        ('tech', 'Technology'),
        ('business', 'Business'),
        ('design', 'Design'),
        ('marketing', 'Marketing'),
        ('data_science', 'Data Science'),
        ('product_management', 'Product Management'),
        ('finance', 'Finance'),
        ('healthcare', 'Healthcare'),
        ('education', 'Education'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    experience = SelectField('Years of Experience', choices=[
        ('', 'Select Experience'),
        ('0-2', '0-2 years'),
        ('3-5', '3-5 years'),
        ('6-10', '6-10 years'),
        ('10+', '10+ years')
    ], validators=[DataRequired()])
    skills = StringField('Skills')  # Will store comma-separated skills
    resume_review_price = IntegerField('Resume Review Price', default=500)
    mock_interview_price = IntegerField('Mock Interview Price', default=800)
    career_guidance_price = IntegerField('Career Guidance Price', default=600)
    skill_training_price = IntegerField('Skill Training Price', default=1000)
    bio = TextAreaField('Bio', validators=[DataRequired(), Length(min=100)])
    available_from = DateField('Available From', validators=[DataRequired()])
    start_time = TimeField('Start Time')
    end_time = TimeField('End Time')
    terms = BooleanField('Agree to Terms', validators=[DataRequired()])
    
    # Checkbox fields for days (you'll need to handle these differently in WTForms)
    # For simplicity, I'll create StringField and you can handle as CSV
    available_days = StringField('Available Days')
