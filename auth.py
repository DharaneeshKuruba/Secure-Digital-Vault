import sqlite3
import bcrypt
import re

def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                       (username, email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username or Email already exists"
    conn.close()
    return True, "User created successfully"

def get_user_mfa_secret(username: str) -> str:
    # For testing purposes, we return a fixed, valid Base32-encoded MFA secret.
    # A valid Base32 secret should have a length that's a multiple of 8.
    # Example: "JBSWY3DPEHPK3PXP" (16 characters)
    return "JBSWY3DPEHPK3PXP"

def verify_user(username: str, password: str) -> tuple[bool, str]:
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        stored_hash = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return True, "Login successful"
    return False, "Invalid credentials"

def user_exists(email: str) -> bool:
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def update_password(email: str, new_password: str) -> None:
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
    conn.commit()
    conn.close()

def get_password_hash(email: str) -> bytes:
    """Return the stored password hash for the given email."""
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against required rules."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."
