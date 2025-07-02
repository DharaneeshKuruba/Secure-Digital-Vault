from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import time

from encryptor import encrypt_file, decrypt_file
from otp_handler import generate_otp, send_otp
from auth import create_user, verify_user
from database import setup_db

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CORS(app)

# Initialize the database
setup_db()

### 1️⃣ Send OTP Route ###
@app.route('/send-otp', methods=['POST'])
def send_otp_route():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
    
    otp = generate_otp()
    try:
        send_otp(email, otp)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send OTP: {str(e)}'}), 500

    # Store OTP in session (with 5-minute expiry)
    session['otp'] = otp
    session['otp_expiry'] = time.time() + 300

    return jsonify({'status': 'success', 'message': 'OTP sent to email'}), 200

### 2️⃣ Verify OTP and Signup ###
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    user_otp = data.get('otp')

    if not username or not email or not password or not user_otp:
        return jsonify({'status': 'error', 'message': 'Missing fields'}), 400
    
    # Verify OTP and expiry
    if user_otp != session.get('otp') or time.time() > session.get('otp_expiry', 0):
        return jsonify({'status': 'error', 'message': 'Invalid or expired OTP'}), 400
    
    success, msg = create_user(username, email, password)
    if not success:
        return jsonify({'status': 'error', 'message': msg}), 400

    # Clear OTP after successful signup
    session.pop('otp', None)
    session.pop('otp_expiry', None)

    return jsonify({'status': 'success', 'message': 'User registered successfully'}), 201

### 3️⃣ Login Route ###
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Missing username or password'}), 400

    success, msg = verify_user(username, password)
    if success:
        return jsonify({'status': 'success', 'message': msg}), 200
    else:
        return jsonify({'status': 'error', 'message': msg}), 401

### 4️⃣ Upload File Route ###
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400
    file = request.files['file']
    if file:
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # Encrypt the file
        encrypted_path = encrypt_file(filepath)
        os.remove(filepath)  # Remove original file after encryption

        conn = sqlite3.connect('vault.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO files (filename, path) VALUES (?, ?)', 
                       (filename, encrypted_path))
        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'File uploaded successfully'}), 201
    else:
        return jsonify({'status': 'error', 'message': 'File processing failed'}), 400

### 5️⃣ Get Files Route ###
@app.route('/files', methods=['GET'])
def get_files():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename FROM files')
    files = cursor.fetchall()
    conn.close()
    
    return jsonify({'status': 'success', 'files': files}), 200

### 6️⃣ Download File Route ###
@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('SELECT path, filename FROM files WHERE id = ?', (file_id,))
    record = cursor.fetchone()
    conn.close()

    if record:
        encrypted_path, filename = record
        # Prepare a temporary decrypted file path
        decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypted_{filename}")
        decrypt_file(encrypted_path, decrypted_path)
        return send_file(decrypted_path, as_attachment=True)
    else:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
