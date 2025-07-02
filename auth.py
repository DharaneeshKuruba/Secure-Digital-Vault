import sqlite3
import bcrypt
import re
import pyotp

# ── SCHEMA MIGRATIONS ─────────────────────────────────────────────────────────

def _ensure_users_schema():
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()

    # Ensure phone column exists
    cur.execute("PRAGMA table_info(users)")
    cols = [c[1] for c in cur.fetchall()]
    if 'phone' not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")

    # Ensure mfa_secret column exists
    cur.execute("PRAGMA table_info(users)")
    cols = [c[1] for c in cur.fetchall()]
    if 'mfa_secret' not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")

    conn.commit()
    conn.close()

# Run migrations once on import
_ensure_users_schema()

# ── USER CREATION & LOOKUP ────────────────────────────────────────────────────

def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """
    Create a new user with username, email, phone, bcrypt-hashed password.
    Returns (success, message).
    """
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, email,password) VALUES (?,?,?)",
            (username, email, hashed)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username or Email already exists"
    conn.close()
    return True, "User created successfully"

def user_exists(email: str) -> bool:
    """
    Returns True if a user with that email already exists.
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists

def verify_user(username: str, password: str) -> tuple[bool, str]:
    """
    Validate username/password against stored bcrypt hash.
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password.encode('utf-8'), row[0]):
        return True, "Login successful"
    return False, "Invalid credentials"

def get_user_phone(username: str) -> str | None:
    """
    Retrieve the stored phone number for a given username.
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("SELECT phone FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

# ── PASSWORD RESET ───────────────────────────────────────────────────────────

def update_password(email: str, new_password: str) -> None:
    """
    Overwrite an existing user's password (bcrypt-hashed).
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    cur.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
    conn.commit()
    conn.close()

def get_password_hash(email: str) -> bytes | None:
    """
    Fetch the stored bcrypt hash for the given email.
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

# ── PASSWORD VALIDATION ─────────────────────────────────────────────────────

def validate_password(password: str) -> tuple[bool, str]:
    """
    Enforce complexity: min 8 chars, mixed case, digits, special.
    """
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

# ── TOTP MFA SUPPORT ─────────────────────────────────────────────────────────

def generate_mfa_secret(username: str) -> str:
    """
    Create and store a new Base32 TOTP secret for the user.
    Returns the raw secret for provisioning.
    """
    secret = pyotp.random_base32()
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (secret, username))
    conn.commit()
    conn.close()
    return secret

def get_user_mfa_secret(username: str) -> str | None:
    """
    Fetch the stored Base32 TOTP secret for this user.
    """
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row and row[0] else None
