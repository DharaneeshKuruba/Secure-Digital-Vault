import os
import random
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import pyotp
import sqlite3

load_dotenv()

EMAIL_ADDRESS  = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def generate_otp(length: int = 6) -> str:
    """
    Generate a simple numeric OTP (for sign-up / reset flows).
    """
    return str(random.randint(0, 10**length - 1)).zfill(length)

def send_otp(email: str, otp: str) -> None:
    """
    Send a one-time OTP via email (signup / forgot-password flows).
    """
    msg = EmailMessage()
    msg.set_content(f'Your verification OTP is: {otp}')
    msg['Subject'] = 'Secure Vault OTP Verification'
    msg['From']    = EMAIL_ADDRESS
    msg['To']      = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

def send_reset_password(email: str, new_password: str) -> None:
    """
    Email the user their new password after a reset.
    """
    msg = EmailMessage()
    msg.set_content(
        f'Your password has been reset to: {new_password}\n'
        'Please log in and change it immediately.'
    )
    msg['Subject'] = 'Secure Vault Password Reset'
    msg['From']    = EMAIL_ADDRESS
    msg['To']      = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ── TOTP MFA SUPPORT ──────────────────────────────────────────────────────────

def _get_totp_secret(username: str) -> str | None:
    """
    Retrieve per-user TOTP secret from the database.
    """
    conn = sqlite3.connect('vault.db')
    cur  = conn.cursor()
    cur.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def generate_mfa_secret(username: str) -> str:
    """
    Create and store a new Base32 TOTP secret for this user.
    Returns the secret for QR-code provisioning.
    """
    secret = pyotp.random_base32()
    conn = sqlite3.connect('vault.db')
    cur  = conn.cursor()
    cur.execute(
        "UPDATE users SET mfa_secret = ? WHERE username = ?",
        (secret, username)
    )
    conn.commit()
    conn.close()
    return secret

def verify_mfa_code(username: str, code: str) -> bool:
    """
    Verify a user’s TOTP code.
    """
    secret = _get_totp_secret(username)
    if not secret:
        return False
    # Ensure proper padding
    padding = (8 - len(secret) % 8) % 8
    totp = pyotp.TOTP(secret + "=" * padding)
    return totp.verify(code)
