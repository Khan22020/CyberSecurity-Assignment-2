"""
Secure FinTech Application
A banking application with comprehensive security features
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
import json
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
DATABASE = 'fintech_app.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Encryption key for sensitive data (in production, use environment variable)
try:
    with open('.encryption_key', 'rb') as f:
        encryption_key = f.read()
except FileNotFoundError:
    encryption_key = Fernet.generate_key()
    with open('.encryption_key', 'wb') as f:
        f.write(encryption_key)

cipher = Fernet(encryption_key)

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  failed_login_attempts INTEGER DEFAULT 0,
                  account_locked_until TIMESTAMP,
                  last_login TIMESTAMP)''')
    
    # Transactions table (encrypted sensitive data)
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  amount REAL NOT NULL,
                  description TEXT,
                  encrypted_data TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Audit logs table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  details TEXT)''')
    
    # User profiles table
    c.execute('''CREATE TABLE IF NOT EXISTS user_profiles
                 (user_id INTEGER PRIMARY KEY,
                  full_name TEXT,
                  phone TEXT,
                  address TEXT,
                  encrypted_account_number TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

# Password validation
def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# Input validation
def sanitize_input(input_str):
    """Sanitize user input to prevent XSS"""
    if not input_str:
        return ""
    # Remove potentially dangerous characters
    input_str = str(input_str)
    input_str = input_str.replace('<', '&lt;')
    input_str = input_str.replace('>', '&gt;')
    input_str = input_str.replace('"', '&quot;')
    input_str = input_str.replace("'", '&#x27;')
    input_str = input_str.replace('/', '&#x2F;')
    return input_str

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Encryption/Decryption functions
def encrypt_data(data):
    """Encrypt sensitive data"""
    if data:
        return cipher.encrypt(data.encode()).decode()
    return None

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if encrypted_data:
        try:
            return cipher.decrypt(encrypted_data.encode()).decode()
        except:
            return None
    return None

# Audit logging
def log_audit(user_id, action, ip_address=None, details=None):
    """Log user actions for audit trail"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''INSERT INTO audit_logs (user_id, action, ip_address, details)
                 VALUES (?, ?, ?, ?)''', 
                 (user_id, action, ip_address, json.dumps(details) if details else None))
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# File upload validation
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Input validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        # Length validation
        if len(username) > 50:
            flash('Username too long (max 50 characters).', 'error')
            return render_template('register.html')
        
        # Sanitize input
        username = sanitize_input(username)
        
        # Email validation
        if not validate_email(email):
            flash('Invalid email format.', 'error')
            return render_template('register.html')
        
        # Password match check
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Password strength validation
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')
        
        # Check for duplicate username
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        try:
            # Check if username exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                flash('Username already exists.', 'error')
                conn.close()
                return render_template('register.html')
            
            # Check if email exists
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                flash('Email already exists.', 'error')
                conn.close()
                return render_template('register.html')
            
            # Hash password
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            
            # Insert user
            c.execute('''INSERT INTO users (username, email, password_hash)
                         VALUES (?, ?, ?)''', (username, email, password_hash))
            user_id = c.lastrowid
            
            # Create default profile
            c.execute('''INSERT INTO user_profiles (user_id) VALUES (?)''', (user_id,))
            
            conn.commit()
            conn.close()
            
            # Log registration
            log_audit(user_id, 'USER_REGISTRATION', request.remote_addr, {'username': username})
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            conn.rollback()
            conn.close()
            # Generic error message to prevent information leakage
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        # Sanitize username input to prevent SQL injection
        c.execute('SELECT id, password_hash, failed_login_attempts, account_locked_until FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        
        if not user:
            # Generic error to prevent username enumeration
            flash('Invalid username or password.', 'error')
            conn.close()
            return render_template('login.html')
        
        user_id, password_hash, failed_attempts, locked_until = user
        
        # Check if account is locked
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.now() < locked_until_dt:
                remaining_time = (locked_until_dt - datetime.now()).seconds // 60
                flash(f'Account locked. Try again in {remaining_time} minutes.', 'error')
                conn.close()
                return render_template('login.html')
        
        # Verify password
        if check_password_hash(password_hash, password):
            # Successful login
            session['user_id'] = user_id
            session['username'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)
            
            # Reset failed attempts and update last login
            c.execute('''UPDATE users SET failed_login_attempts = 0, 
                       account_locked_until = NULL, last_login = ? WHERE id = ?''',
                     (datetime.now().isoformat(), user_id))
            conn.commit()
            
            # Log successful login
            log_audit(user_id, 'LOGIN_SUCCESS', request.remote_addr)
            
            conn.close()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Failed login
            failed_attempts = (failed_attempts or 0) + 1
            lockout_until = None
            
            # Lock account after 5 failed attempts
            if failed_attempts >= 5:
                lockout_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                flash('Account locked due to multiple failed login attempts. Try again in 30 minutes.', 'error')
            
            c.execute('''UPDATE users SET failed_login_attempts = ?, 
                       account_locked_until = ? WHERE id = ?''',
                     (failed_attempts, lockout_until, user_id))
            conn.commit()
            
            # Log failed login attempt
            log_audit(user_id, 'LOGIN_FAILED', request.remote_addr, {'attempts': failed_attempts})
            
            conn.close()
            flash('Invalid username or password.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Get user transactions
    c.execute('''SELECT id, amount, description, created_at FROM transactions 
                 WHERE user_id = ? ORDER BY created_at DESC LIMIT 10''', (user_id,))
    transactions = c.fetchall()
    
    # Get account balance
    c.execute('SELECT SUM(amount) FROM transactions WHERE user_id = ?', (user_id,))
    balance = c.fetchone()[0] or 0.0
    
    conn.close()
    
    # Log dashboard access
    log_audit(user_id, 'DASHBOARD_ACCESS', request.remote_addr)
    
    return render_template('dashboard.html', 
                         transactions=transactions, 
                         balance=balance,
                         username=session.get('username'))

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    
    # Log logout
    log_audit(user_id, 'LOGOUT', request.remote_addr)
    
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/add_transaction', methods=['POST'])
@login_required
def add_transaction():
    try:
        amount = request.form.get('amount', '')
        description = request.form.get('description', '')
        
        # Validate amount (numeric)
        try:
            amount = float(amount)
            if amount == 0:
                flash('Amount cannot be zero.', 'error')
                return redirect(url_for('dashboard'))
        except (ValueError, TypeError):
            flash('Invalid amount. Please enter a valid number.', 'error')
            return redirect(url_for('dashboard'))
        
        # Validate description length
        if description and len(description) > 500:
            flash('Description too long (max 500 characters).', 'error')
            return redirect(url_for('dashboard'))
        
        # Sanitize description
        description = sanitize_input(description)
        
        # Encrypt description if sensitive
        encrypted_desc = encrypt_data(description) if description else None
        
        user_id = session['user_id']
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''INSERT INTO transactions (user_id, amount, description, encrypted_data)
                     VALUES (?, ?, ?, ?)''', (user_id, amount, description, encrypted_desc))
        conn.commit()
        conn.close()
        
        # Log transaction
        log_audit(user_id, 'TRANSACTION_CREATED', request.remote_addr, {'amount': amount})
        
        flash('Transaction added successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        account_number = request.form.get('account_number', '').strip()
        
        # Validate input lengths
        if full_name and len(full_name) > 100:
            flash('Full name too long (max 100 characters).', 'error')
            return redirect(url_for('profile'))
        
        if phone and len(phone) > 20:
            flash('Phone number too long (max 20 characters).', 'error')
            return redirect(url_for('profile'))
        
        if address and len(address) > 200:
            flash('Address too long (max 200 characters).', 'error')
            return redirect(url_for('profile'))
        
        # Sanitize inputs
        full_name = sanitize_input(full_name)
        phone = sanitize_input(phone)
        address = sanitize_input(address)
        
        # Encrypt account number
        encrypted_account = encrypt_data(account_number) if account_number else None
        
        # Update profile
        c.execute('''UPDATE user_profiles 
                     SET full_name = ?, phone = ?, address = ?, encrypted_account_number = ?
                     WHERE user_id = ?''',
                  (full_name, phone, address, encrypted_account, user_id))
        conn.commit()
        
        # Log profile update
        log_audit(user_id, 'PROFILE_UPDATE', request.remote_addr)
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    # Get profile data
    c.execute('''SELECT full_name, phone, address, encrypted_account_number 
                 FROM user_profiles WHERE user_id = ?''', (user_id,))
    profile_data = c.fetchone()
    conn.close()
    
    if profile_data:
        full_name, phone, address, encrypted_account = profile_data
        # Decrypt account number for display
        account_number = decrypt_data(encrypted_account) if encrypted_account else ''
        profile_data = {'full_name': full_name, 'phone': phone, 
                       'address': address, 'account_number': account_number}
    else:
        profile_data = {'full_name': '', 'phone': '', 'address': '', 'account_number': ''}
    
    return render_template('profile.html', profile=profile_data)

@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
@login_required
def encrypt_decrypt():
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text', '')
        
        if not text:
            flash('Please enter text to encrypt/decrypt.', 'error')
            return render_template('encrypt_decrypt.html')
        
        try:
            if action == 'encrypt':
                encrypted = encrypt_data(text)
                result = encrypted
                log_audit(session['user_id'], 'ENCRYPTION', request.remote_addr)
            elif action == 'decrypt':
                decrypted = decrypt_data(text)
                if decrypted:
                    result = decrypted
                    log_audit(session['user_id'], 'DECRYPTION', request.remote_addr)
                else:
                    flash('Invalid encrypted data. Decryption failed.', 'error')
                    return render_template('encrypt_decrypt.html')
            else:
                flash('Invalid action.', 'error')
                return render_template('encrypt_decrypt.html')
            
            return render_template('encrypt_decrypt.html', result=result, action=action)
        except Exception as e:
            flash('An error occurred during encryption/decryption.', 'error')
            return render_template('encrypt_decrypt.html')
    
    return render_template('encrypt_decrypt.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload_file'))
        
        # Validate file type
        if not allowed_file(file.filename):
            flash('File type not allowed. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS), 'error')
            return redirect(url_for('upload_file'))
        
        # Validate file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            flash('File too large. Maximum size is 5MB.', 'error')
            return redirect(url_for('upload_file'))
        
        # Secure filename
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session['user_id']}_{filename}")
        
        try:
            file.save(filepath)
            log_audit(session['user_id'], 'FILE_UPLOAD', request.remote_addr, {'filename': filename})
            flash('File uploaded successfully!', 'success')
        except Exception as e:
            flash('Error uploading file.', 'error')
        
        return redirect(url_for('upload_file'))
    
    return render_template('upload.html')

@app.route('/audit_logs')
@login_required
def audit_logs():
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Get audit logs for the user
    c.execute('''SELECT action, ip_address, timestamp, details 
                 FROM audit_logs WHERE user_id = ? 
                 ORDER BY timestamp DESC LIMIT 50''', (user_id,))
    logs = c.fetchall()
    conn.close()
    
    return render_template('audit_logs.html', logs=logs)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, 
                         error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    # Log error but don't expose details
    return render_template('error.html', error_code=500, 
                         error_message='An internal error occurred'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='127.0.0.1', port=5000)

