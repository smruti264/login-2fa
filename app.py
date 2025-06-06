from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Change this in production!

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            secret_key TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, secret_key=None):
        self.id = id
        self.username = username
        self.password = password
        self.secret_key = secret_key

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(*user_data)
    return None

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and bcrypt.checkpw(password, user_data[2]):
            user = User(*user_data)
            login_user(user)
            
            # Check if 2FA is enabled
            if user.secret_key:
                return redirect(url_for('verify_2fa'))
            else:
                return redirect(url_for('setup_2fa'))
        else:
            flash('Invalid username or password!', 'danger')
    return render_template('index.html')

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    if current_user.secret_key:
        return redirect(url_for('dashboard'))
    
    secret_key = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=current_user.username,
        issuer_name="SecureApp"
    )
    
    # Generate QR code in memory
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Update database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET secret_key = ? WHERE id = ?',
        (secret_key, current_user.id)
    )
    conn.commit()
    conn.close()
    return render_template('setup_2fa.html', 
                         qr_image=img_str,
                         secret_key=secret_key)

@app.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if not current_user.secret_key:
        return redirect(url_for('setup_2fa'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(current_user.secret_key)
        
        if totp.verify(otp):
            session['2fa_verified'] = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP!', 'danger')
    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('2fa_verified'):
        return redirect(url_for('verify_2fa'))
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    session.pop('2fa_verified', None)
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)