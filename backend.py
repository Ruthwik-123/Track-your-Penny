import os
import sqlite3
import bcrypt
import re
import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import jwt
from contextlib import contextmanager

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), 'extra', '.env'))

app = Flask(__name__)
# Only allow our specific frontend to talk to the backend
CORS(app, origins=["http://127.0.0.1:5500", "http://localhost:5500"]) 

# --- FOLDER SETUP (The Kill-Switch for the CPU Loop) ---
DB_FOLDER = 'data'
if not os.path.exists(DB_FOLDER):
    os.makedirs(DB_FOLDER)

IP_DB = os.path.join(DB_FOLDER, 'ip.db')
KEYS_DB = os.path.join(DB_FOLDER, 'keys.db')
USERS_DB = os.path.join(DB_FOLDER, 'users.db')

@contextmanager
def db_context_manager(db_path):
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute('PRAGMA busy_timeout = 30000')
    try:
        yield conn
    finally:
        conn.close()

def _get_keys_table_with_ip():
    with db_context_manager(KEYS_DB) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for (table_name,) in tables:
            rows = conn.execute(f'PRAGMA table_info({table_name})').fetchall()
            if any(row[1] == 'ip' for row in rows):
                return table_name
    return None

def _get_account_stats_for_ip(user_ip):
    table_name = _get_keys_table_with_ip()
    if not table_name:
        return 0, 0

    # Whitelist validation for table name to prevent SQL injection
    # Only allow table names that are legitimate internal tables
    ALLOWED_TABLES = {'keys_', 'users', 'email_attempts'}
    if not any(table_name.startswith(prefix) if prefix.endswith('_') else table_name == prefix
               for prefix in ALLOWED_TABLES):
        print(f"Security: Invalid table name rejected: {table_name}")
        return 0, 0

    with db_context_manager(KEYS_DB) as conn:
        count = conn.execute(
            f'SELECT COUNT(*) FROM {table_name} WHERE ip = ?',
            (user_ip,)
        ).fetchone()[0]
    return (1 if count > 0 else 0), count


def initialize_database():
    with db_context_manager(USERS_DB) as conn:
        # Create updated users table with new columns
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, 
                password BLOB,
                email TEXT,
                is_verified INTEGER DEFAULT 0,
                verification_code TEXT,
                code_expiry DATETIME,
                last_ip TEXT
            )
        ''')
        
        # Schema migration: Add missing columns if they don't exist
        existing_columns = [row[1] for row in conn.execute('PRAGMA table_info(users)').fetchall()]
        
        if 'is_verified' not in existing_columns:
            conn.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0')
        if 'verification_code' not in existing_columns:
            conn.execute('ALTER TABLE users ADD COLUMN verification_code TEXT')
        if 'code_expiry' not in existing_columns:
            conn.execute('ALTER TABLE users ADD COLUMN code_expiry DATETIME')
        if 'last_ip' not in existing_columns:
            conn.execute('ALTER TABLE users ADD COLUMN last_ip TEXT')
        
    with db_context_manager(KEYS_DB) as conn:
        # Create rate limiting table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS email_attempts (
                ip TEXT,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ip, attempt_time)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
    with db_context_manager(IP_DB) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS visitor_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                time DATETIME DEFAULT CURRENT_TIMESTAMP,
                has_account INTEGER DEFAULT 0,
                account_count INTEGER DEFAULT 0
            )
        ''')
    print(f" Databases initialized in /{DB_FOLDER} folder.")

# --- HELPER FUNCTIONS ---

def is_valid_email(email):
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def generate_otp():
    """Generate cryptographically secure 6-digit OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def is_rate_limited(ip):
    """Check if IP has exceeded rate limit (3 attempts per 5 minutes)"""
    with db_context_manager(KEYS_DB) as conn:
        # Clean old attempts (older than 5 minutes)
        conn.execute('DELETE FROM email_attempts WHERE attempt_time < ?', 
                    (datetime.now() - timedelta(minutes=5),))
        
        # Count recent attempts
        count = conn.execute(
            'SELECT COUNT(*) FROM email_attempts WHERE ip = ?',
            (ip,)
        ).fetchone()[0]
        
        return count >= 3

def record_email_attempt(ip):
    """Record an email attempt for rate limiting"""
    with db_context_manager(KEYS_DB) as conn:
        conn.execute('INSERT INTO email_attempts (ip) VALUES (?)', (ip,))
        conn.commit()

def is_login_rate_limited(ip):
    """Limit login attempts to 5 per 15 minutes to prevent Brute-Force & CPU exhaustion"""
    with db_context_manager(KEYS_DB) as conn:
        # Clean old attempts (older than 15 minutes)
        conn.execute('DELETE FROM login_attempts WHERE attempt_time < ?', 
                    (datetime.now() - timedelta(minutes=15),))
        
        # Count recent failed attempts
        count = conn.execute(
            'SELECT COUNT(*) FROM login_attempts WHERE ip = ?',
            (ip,)
        ).fetchone()[0]
        
        return count >= 5

def record_failed_login(ip):
    """Record a failed login attempt"""
    with db_context_manager(KEYS_DB) as conn:
        conn.execute('INSERT INTO login_attempts (ip) VALUES (?)', (ip,))
        conn.commit()

def send_email(to_email, subject, body):
    """Send email using Gmail SMTP with SSL and proper error handling"""
    server = None
    try:
        sender_email = os.getenv('SENDER_EMAIL', 'chruthwik2014@gmail.com')
        app_password = os.getenv('GMAIL_APP_PASSWORD')

        if not app_password:
            print("Error: Gmail app password not found in environment variables")
            return False

        # Create SMTP SSL session with timeout
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10)
        server.login(sender_email, app_password)

        # Create properly formatted MIME message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        # Send email
        server.send_message(msg)

        print(f"Email sent successfully to {to_email}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"SMTP Recipients Refused: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {e}")
        return False
    except Exception as e:
        print(f"Email sending error: {e}")
        return False
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass

def generate_jwt_token(username):
    """Generate JWT token for user using secret from environment"""
    secret_key = os.getenv('JWT_SECRET_KEY')
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY not set in environment variables")

    payload = {
        'username': username,
        'exp': datetime.now() + timedelta(hours=24)
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')

# --- ROUTES ---

@app.route('/api/get-client-info', methods=['GET'])
def log_ip():
    user_ip = request.remote_addr
    has_account, account_count = _get_account_stats_for_ip(user_ip)
    try:
        with db_context_manager(IP_DB) as conn:
            conn.execute('''
                INSERT INTO visitor_logs (ip, time, has_account, account_count)
                VALUES (?, CURRENT_TIMESTAMP, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    time = CURRENT_TIMESTAMP,
                    has_account = excluded.has_account,
                    account_count = excluded.account_count
            ''', (user_ip, has_account, account_count))
    except Exception as e:
        print(f"Log Error: {e}")
    return jsonify({"status": "logged"}), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    user, email, pwd = data.get('username'), data.get('email'), data.get('password')
    user_ip = request.remote_addr
    
    # Input validation
    if not user or not email or not pwd:
        return jsonify({"error": "Missing info"}), 400
    
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(pwd) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    # Rate limiting check
    if is_rate_limited(user_ip):
        return jsonify({"error": "Too many email attempts. Please wait 5 minutes."}), 429
    
    hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=10)
    
    try:
        with db_context_manager(USERS_DB) as conn:
            conn.execute('''
                INSERT INTO users (username, password, email, verification_code, code_expiry)
                VALUES (?, ?, ?, ?, ?)
            ''', (user, hashed, email, otp, expiry))
            conn.commit()
        
        # Send OTP email
        subject = "Complete your Track Your Penny registration"
        body = f"""Hello {user},

Click the button below to complete your registration and activate your account:

<a href="http://127.0.0.1:5000/verify-signup?username={user}&code={otp}" style="background-color: #00d1b2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold; margin: 20px 0;">COMPLETE REGISTRATION</a>

Or copy this link to your browser:
http://127.0.0.1:5000/verify-signup?username={user}&code={otp}

This link will expire in 10 minutes.

Best regards,
Track Your Penny Team"""
        
        if send_email(email, subject, body):
            record_email_attempt(user_ip)
            return jsonify({"message": "Registration initiated. Please check your email for verification code."}), 201
        else:
            return jsonify({"error": "Failed to send verification email. Please try again."}), 503
            
    except sqlite3.IntegrityError:
        # User already exists - check if unverified for recovery
        try:
            with db_context_manager(USERS_DB) as conn:
                row = conn.execute('''
                    SELECT email, is_verified FROM users WHERE username = ?
                ''', (user,)).fetchone()
                
                if row:
                    existing_email, is_verified = row
                    
                    if is_verified == 0:
                        # User exists but not verified - update OTP for recovery
                        if is_rate_limited(user_ip):
                            return jsonify({"error": "Too many email attempts. Please wait 5 minutes."}), 429
                        
                        # Check if email matches
                        if existing_email != email:
                            return jsonify({"error": "Email does not match the existing account"}), 400
                        
                        # Update password and generate new OTP
                        new_hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
                        new_otp = generate_otp()
                        new_expiry = datetime.now() + timedelta(minutes=10)
                        
                        conn.execute('''
                            UPDATE users 
                            SET password = ?, verification_code = ?, code_expiry = ?
                            WHERE username = ?
                        ''', (new_hashed, new_otp, new_expiry, user))
                        conn.commit()
                        
                        # Send OTP email
                        subject = "Verify your Track Your Penny account"
                        body = f"""Hello {user},

Your verification code is: {new_otp}

This code will expire in 10 minutes. Please enter it on the verification page to complete your registration.

If you didn't request this, please ignore this email.

Best regards,
Track Your Penny Team"""
                        
                        if send_email(email, subject, body):
                            record_email_attempt(user_ip)
                            return jsonify({
                                "message": "Verification code resent. Please check your email."
                            }), 200
                        else:
                            return jsonify({"error": "Failed to send verification email. Please try again."}), 503
                    else:
                        # User exists and is verified - return conflict
                        return jsonify({"error": "User already exists"}), 409
                else:
                    return jsonify({"error": "User already exists"}), 409
        except Exception as inner_e:
            print(f"Recovery error: {inner_e}")
            return jsonify({"error": "User already exists"}), 409
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/verify-signup', methods=['GET'])
def verify_signup_link():
    """Handle email verification link clicks"""
    username = request.args.get('username')
    code = request.args.get('code')
    
    if not username or not code:
        return redirect(f"http://127.0.0.1:5500/auth.html?error=missing_params")
    
    try:
        with db_context_manager(USERS_DB) as conn:
            row = conn.execute('''
                SELECT verification_code, code_expiry FROM users 
                WHERE username = ? AND is_verified = 0
            ''', (username,)).fetchone()
            
            if not row:
                return redirect(f"http://127.0.0.1:5500/auth.html?error=invalid_user")
            
            stored_code, expiry = row
            
            # Check if code is correct and not expired
            if stored_code != code:
                return redirect(f"http://127.0.0.1:5500/auth.html?error=invalid_code")
            
            if datetime.now() > datetime.fromisoformat(expiry):
                return redirect(f"http://127.0.0.1:5500/auth.html?error=expired")
            
            # Mark as verified
            conn.execute('''
                UPDATE users SET is_verified = 1, verification_code = NULL, code_expiry = NULL
                WHERE username = ?
            ''', (username,))
            conn.commit()

            # Generate token for auto-login after signup
            token = generate_jwt_token(username)
            
            # Redirect to success page with token
            return redirect(f"http://127.0.0.1:5500/auth.html?verified=true&username={username}&token={token}")
            
    except Exception as e:
        print(f"Verification link error: {e}")
        return redirect(f"http://127.0.0.1:5500/auth.html?error=verification_failed")

@app.route('/api/verify-signup', methods=['POST'])
def verify_signup():
    data = request.json
    username, code = data.get('username'), data.get('code')
    
    if not username or not code:
        return jsonify({"error": "Missing username or verification code"}), 400
    
    try:
        with db_context_manager(USERS_DB) as conn:
            row = conn.execute('''
                SELECT verification_code, code_expiry FROM users 
                WHERE username = ? AND is_verified = 0
            ''', (username,)).fetchone()
            
            if not row:
                return jsonify({"error": "Invalid username or already verified"}), 400
            
            stored_code, expiry = row
            
            # Check if code is correct and not expired
            if stored_code != code:
                return jsonify({"error": "Invalid verification code"}), 400
            
            if datetime.now() > datetime.fromisoformat(expiry):
                return jsonify({"error": "Verification code expired"}), 400
            
            # Mark as verified
            conn.execute('''
                UPDATE users SET is_verified = 1, verification_code = NULL, code_expiry = NULL
                WHERE username = ?
            ''', (username,))
            conn.commit()

            # Generate token for auto-login after signup
            token = generate_jwt_token(username)

            return jsonify({
                "message": "Account verified successfully! Welcome to Track Your Penny.",
                "token": token,
                "username": username
            }), 200
            
    except Exception as e:
        print(f"Verification error: {e}")
        return jsonify({"error": "Verification failed"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user, pwd = data.get('username'), data.get('password')
    user_ip = request.remote_addr
    
    if not user or not pwd:
        return jsonify({"error": "Missing username or password"}), 400
    
    # >>> SECURITY FIX: Block brute-force attacks BEFORE computing bcrypt <<<
    if is_login_rate_limited(user_ip):
        return jsonify({"error": "Too many failed login attempts. Please wait 15 minutes."}), 429

    try:
        with db_context_manager(USERS_DB) as conn:
            row = conn.execute('''
                SELECT password, is_verified, last_ip, email FROM users 
                WHERE username = ?
            ''', (user,)).fetchone()
            
            # >>> SECURITY FIX: Record the failure if they get it wrong <<<
            if not row or not bcrypt.checkpw(pwd.encode('utf-8'), row[0]):
                record_failed_login(user_ip) 
                return jsonify({"error": "Invalid credentials"}), 401
            
            stored_password, is_verified, last_ip, email = row
            
            if not is_verified:
                # User exists but is not verified - generate new OTP for recovery
                if is_rate_limited(user_ip):
                    return jsonify({"error": "Too many verification attempts. Please wait 5 minutes."}), 429
                
                otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)
                
                # Update with new OTP
                conn.execute('''
                    UPDATE users SET verification_code = ?, code_expiry = ?
                    WHERE username = ?
                ''', (otp, expiry, user))
                conn.commit()
                
                # Send verification email
                subject = "Verify your Track Your Penny account"
                body = f"""Hello {user},

Your verification code is: {otp}

This code will expire in 10 minutes. Please enter it on the verification page to complete your registration.

If you didn't request this, please ignore this email.

Best regards,
Track Your Penny Team"""
                
                if send_email(email, subject, body):
                    record_email_attempt(user_ip)
                    return jsonify({
                        "status": "verification_required",
                        "message": "Please verify your email first. Check your email for the new verification code."
                    }), 200
                else:
                    return jsonify({"error": "Failed to send verification email. Please try again."}), 503
            
            # IP Guard logic
            if last_ip and last_ip == user_ip:
                # Same IP - update last_ip timestamp, generate token, and send alert
                token = generate_jwt_token(user)

                # Update last_ip to current time (refresh the timestamp)
                conn.execute('UPDATE users SET last_ip = ? WHERE username = ?', (user_ip, user))
                conn.commit()

                # Send login alert email
                subject = "Login Alert - Track Your Penny"
                body = f"""Hello {user},

Success: New login from IP: {user_ip} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This was a successful login to your Track Your Penny account.

If this was you, no action is needed.
If you don't recognize this login, please secure your account.

Best regards,
Track Your Penny Team"""

                send_email(email, subject, body)

                return jsonify({
                    "message": "Login successful",
                    "token": token,
                    "username": user
                }), 200
            else:
                # New IP - require verification
                if is_rate_limited(user_ip):
                    return jsonify({"error": "Too many verification attempts. Please wait 5 minutes."}), 429
                
                otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=10)
                
                # Update with new OTP
                conn.execute('''
                    UPDATE users SET verification_code = ?, code_expiry = ?
                    WHERE username = ?
                ''', (otp, expiry, user))
                conn.commit()  # Added missing commit
                
                # Send verification email
                subject = "New Login Verification - Track Your Penny"
                body = f"""Hello {user},

We detected a login attempt from a new IP address: {user_ip}

Your verification code is: {otp}

This code will expire in 10 minutes. Please enter it to complete your login.

If you didn't attempt this login, please secure your account.

Best regards,
Track Your Penny Team"""
                
                if send_email(email, subject, body):
                    record_email_attempt(user_ip)
                    return jsonify({
                        "status": "verification_required",
                        "message": "New IP detected. Please check your email for verification code."
                    }), 200
                else:
                    return jsonify({"error": "Failed to send verification email. Please try again."}), 503
    
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/api/verify-login', methods=['POST'])
def verify_login():
    data = request.json
    username, code = data.get('username'), data.get('code')
    user_ip = request.remote_addr
    
    if not username or not code:
        return jsonify({"error": "Missing username or verification code"}), 400
    
    try:
        with db_context_manager(USERS_DB) as conn:
            row = conn.execute('''
                SELECT verification_code, code_expiry, email FROM users 
                WHERE username = ? AND is_verified = 1
            ''', (username,)).fetchone()
            
            if not row:
                return jsonify({"error": "Invalid username"}), 400
            
            stored_code, expiry, email = row
            
            # Check if code is correct and not expired
            if stored_code != code:
                return jsonify({"error": "Invalid verification code"}), 400
            
            if datetime.now() > datetime.fromisoformat(expiry):
                return jsonify({"error": "Verification code expired"}), 400
            
            # Update last IP and clear verification code
            conn.execute('''
                UPDATE users SET last_ip = ?, verification_code = NULL, code_expiry = NULL
                WHERE username = ?
            ''', (user_ip, username))
            conn.commit()
            
            # Generate JWT token
            token = generate_jwt_token(username)
            
            return jsonify({
                "message": "Login verified successfully",
                "token": token,
                "username": username
            }), 200
            
    except Exception as e:
        print(f"Login verification error: {e}")
        return jsonify({"error": "Verification failed"}), 500

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True, port=5000)