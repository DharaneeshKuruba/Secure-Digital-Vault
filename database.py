import sqlite3

def setup_db():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()

    # Users table with username, email, bcrypt-hashed password, and phone for MFA
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    ''')

    # Files table creation (without duplicate creation if exists)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            path TEXT NOT NULL,
            salt TEXT
        )
    ''')

    # Check if 'username' column exists in 'files' table
    cursor.execute("PRAGMA table_info(files)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'username' not in columns:
        cursor.execute("ALTER TABLE files ADD COLUMN username TEXT")

    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
