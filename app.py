from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_cors import CORS
from functools import wraps
import os
import qrcode
from io import BytesIO
import socket
import base64  # For encoding QR image

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'logs.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define a secret API key for external log submission
API_KEY = "my_secret_api_key_123"  # Change this to a strong key

# Models
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(50), nullable=False)
    level = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Login-required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to continue.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists")
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user'] = username
            flash("Login successful.")
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials")

    # Generate QR code for login URL
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    login_url = f'http://{local_ip}:5000/login'
    img = qrcode.make(login_url)
    buf = BytesIO()
    img.save(buf, format='PNG')
    qr_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('login.html', qr_image=qr_data)

# Logout
@app.route('/logout')
@login_required
def logout():
    session.pop('user', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

# API log receiver with API key authentication
@app.route('/api/log', methods=['POST'])
def receive_log():
    # Check for API key in headers
    api_key = request.headers.get('x-api-key')
    if api_key != API_KEY:
        return jsonify({'error': 'Unauthorized: Invalid API key'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    source = data.get('source')
    level = data.get('level')
    message = data.get('message')

    if not all([source, level, message]):
        return jsonify({'error': 'Missing required fields'}), 400

    log = Log(source=source, level=level, message=message)
    db.session.add(log)
    db.session.commit()
    return jsonify({'status': 'Log received'}), 201

# Index page
@app.route('/')
@login_required
def index():
    level_filter = request.args.get('level')
    source_filter = request.args.get('source')
    search_term = request.args.get('search')

    query = Log.query
    if level_filter:
        query = query.filter_by(level=level_filter)
    if source_filter:
        query = query.filter_by(source=source_filter)
    if search_term:
        query = query.filter(Log.message.ilike(f'%{search_term}%'))

    logs = query.order_by(Log.timestamp.desc()).all()
    levels = [l[0] for l in db.session.query(Log.level).distinct().all()]
    sources = [s[0] for s in db.session.query(Log.source).distinct().all()]

    return render_template('index.html', logs=logs, levels=levels, sources=sources)

# Export logs as JSON
@app.route('/export/json')
@login_required
def export_json():
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    export_data = [
        {
            'id': log.id,
            'source': log.source,
            'level': log.level,
            'message': log.message,
            'timestamp': log.timestamp.isoformat()
        } for log in logs
    ]
    return jsonify(export_data)

# Add log manually from dashboard
@app.route('/add_log', methods=['POST'])
@login_required
def add_log():
    source = request.form.get('source')
    level = request.form.get('level')
    message = request.form.get('message')

    if not all([source, level, message]):
        flash("All fields are required.")
        return redirect(url_for('index'))

    log = Log(source=source, level=level, message=message)
    db.session.add(log)
    db.session.commit()
    flash("✅ Log added successfully!")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables exist inside app context
    app.run(debug=False)  # Never True in production
