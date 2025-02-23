import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_very_secret_key'
app.permanent_session_lifetime = timedelta(days=7)  # Extend session to 7 days

# Configuration for Flask-Mail (email sending)

from collections import defaultdict
from datetime import datetime, timedelta

# Rate limiting storage
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = timedelta(minutes=15)

app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your email server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)


users_db = {}


reset_tokens_db = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']
    if not email or not password:
        flash('Email and password are required.')
        return redirect(url_for('home'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.')
        return redirect(url_for('home'))
    if not any(c.isupper() for c in password):
        flash('Password must contain at least one uppercase letter.')
        return redirect(url_for('home'))
    if not any(c.isdigit() for c in password):
        flash('Password must contain at least one number.')
        return redirect(url_for('home'))
    if email in users_db:
        flash('Email already exists.')
        return redirect(url_for('home'))
    users_db[email] = {
        'password_hash': generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
        'username': request.form['username'],
        'joined_date': datetime.now(),
        'last_login': datetime.now(),
        'stats': {
            'visitors': 0,
            'messages': 0,
            'tasks': 0,
            'events': 0,
            'unread_messages': 0,
            'due_tasks': 0,
            'next_event_days': 0
        }
    }
    flash('Account created successfully!')
    return redirect(url_for('home'))


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    
    if email not in users_db:
        flash('Account does not exist. Please sign up first.')
        return redirect(url_for('home'))
        
    # Check rate limiting
    now = datetime.now()
    login_attempts[email] = [t for t in login_attempts[email] if now - t < ATTEMPT_WINDOW]
    if len(login_attempts[email]) >= MAX_ATTEMPTS:
        flash('Too many login attempts. Please try again later.')
        return redirect(url_for('home'))
    login_attempts[email].append(now)
    
    if check_password_hash(users_db[email]['password_hash'], password):
        session.permanent = True  # Make the session permanent
        session['email'] = email
        flash('Login successful!')
        return redirect(url_for('dashboard'))
    flash('Invalid credentials')
    return redirect(url_for('home'))

# Route for the "Forgot Password" page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        if email in users_db:
            # Generate a secure random token
            token = secrets.token_hex(16)

            # Store the token and its expiration time (e.g., 1 hour)
            expiration_time = datetime.now() + timedelta(hours=1)
            reset_tokens_db[token] = {'email': email, 'expiration_time': expiration_time}

            # Send a password reset email
            send_password_reset_email(email, token)

            flash('Password reset instructions have been sent to your email.')
            return redirect(url_for('home'))
        else:
            flash('Invalid email address.')
    return render_template('forgot_password.html')

# Function to send a password reset email
def send_password_reset_email(email, token):
    msg = Message('Password Reset', sender='your_email@example.com', recipients=[email])
    msg.body = f'Click the following link to reset your password: {url_for("reset_password", token=token, _external=True)}'
    mail.send(msg)

# Route for resetting the password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token in reset_tokens_db:
        token_info = reset_tokens_db[token]
        if datetime.now() <= token_info['expiration_time']:
            if request.method == 'POST':
                new_password = request.form['new_password']
                # Update the password in the database (in a real app, you'd hash the password)
                users_db[token_info['email']]['password_hash'] = generate_password_hash(new_password)
                # Delete the used token
                del reset_tokens_db[token]
                flash('Password reset successful. You can now log in with your new password.')
                return redirect(url_for('home'))
            return render_template('reset_password.html')
    flash('Invalid or expired token.')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Please login to view the dashboard.')
        return redirect(url_for('home'))
    return render_template('dashboard.html', users_db=users_db)

@app.route('/settings')
def settings():
    if 'email' not in session:
        return redirect(url_for('home'))
    return render_template('settings.html', users_db=users_db)

@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'email' not in session:
        return redirect(url_for('home'))
    
    email = session['email']
    if 'username' in request.form:
        users_db[email]['username'] = request.form['username']
    
    if request.form.get('new_password'):
        users_db[email]['password_hash'] = generate_password_hash(
            request.form['new_password'],
            method='pbkdf2:sha256',
            salt_length=16
        )
    
    flash('Settings updated successfully!')
    return redirect(url_for('settings'))

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Get the port from the environment variable or use 5000 as default
    app.run(debug=True, host='0.0.0.0', port=port)  # Run the app with the specified port
