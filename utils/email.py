import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app, render_template_string
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def send_email(to: str, subject: str, template: str, context: Optional[Dict[str, Any]] = None) -> bool:
    """Send email using configured mail server"""
    if not current_app.config['MAIL_USERNAME'] or not current_app.config['MAIL_PASSWORD']:
        logger.warning(f"Email not sent (no credentials): To={to}, Subject={subject}")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = current_app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to
        
        # Render template
        if context is None:
            context = {}
        
        html_body = render_template_string(template, **context)
        
        # Attach plain text version (strip HTML tags)
        import re
        text_body = re.sub(r'<[^>]+>', '', html_body)
        
        msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Connect to SMTP server
        if current_app.config['MAIL_USE_SSL']:
            server = smtplib.SMTP_SSL(
                current_app.config['MAIL_SERVER'],
                current_app.config['MAIL_PORT']
            )
        else:
            server = smtplib.SMTP(
                current_app.config['MAIL_SERVER'],
                current_app.config['MAIL_PORT']
            )
        
        if current_app.config['MAIL_USE_TLS'] and not current_app.config['MAIL_USE_SSL']:
            server.starttls()
        
        server.login(
            current_app.config['MAIL_USERNAME'],
            current_app.config['MAIL_PASSWORD']
        )
        
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False

# Email templates
VERIFICATION_EMAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
<body>
    <h2>Verify Your Email</h2>
    <p>Hi {{ username }},</p>
    <p>Click the link below to verify your email:</p>
    <a href="{{ verification_url }}">Verify Email</a>
    <p>This link expires in 24 hours.</p>
</body>
</html>
"""

PASSWORD_RESET_TEMPLATE = """
<!DOCTYPE html>
<html>
<body>
    <h2>Reset Your Password</h2>
    <p>Click the link below to reset your password:</p>
    <a href="{{ reset_url }}">Reset Password</a>
    <p>This link expires in 1 hour.</p>
</body>
</html>
"""
