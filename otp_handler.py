import random
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import os

load_dotenv()

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email, otp):
    try:
        msg = EmailMessage()
        msg.set_content(f'Your OTP is: {otp}')
        msg['Subject'] = 'OTP Verification'
        msg['From'] = os.getenv('EMAIL_ADDRESS')
        msg['To'] = email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(os.getenv('EMAIL_ADDRESS'), os.getenv('EMAIL_PASSWORD'))
            smtp.send_message(msg)
        print(f"✅ OTP sent successfully to {email}")
    except Exception as e:
        print(f"❌ Failed to send OTP: {e}")
        raise e

def send_reset_password(email, new_password):
    try:
        msg = EmailMessage()
        msg.set_content(f'Your new password is: {new_password}\nPlease change it after logging in.')
        msg['Subject'] = 'Password Reset'
        msg['From'] = os.getenv('EMAIL_ADDRESS')
        msg['To'] = email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(os.getenv('EMAIL_ADDRESS'), os.getenv('EMAIL_PASSWORD'))
            smtp.send_message(msg)
        print(f"✅ Reset password email sent successfully to {email}")
    except Exception as e:
        print(f"❌ Failed to send reset password email: {e}")
        raise e
