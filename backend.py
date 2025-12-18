# backend.py
# Basit, tek dosyalık Flask uygulaması.
# Gereksinimler: flask, sqlalchemy, authlib
# pip install flask sqlalchemy authlib

import os
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

# --- Config ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'supanel.db'))
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

app = Flask(__name__)
app.secret_key = SECRET_KEY

# OAuth (Google)
oauth = OAuth(app)
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
        authorize_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v2/',
        client_kwargs={'scope': 'openid email profile'},
    )

# --- DB helpers ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT,
        google_id TEXT,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        sub TEXT UNIQUE,
        target TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT
    );
    """)
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

# --- Auth helpers ---
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()
    return user

# --- Routes ---
@app.route('/')
def index():
    user = current_user()
    subdomains = []
    if user:
        conn = get_db()
        rows = conn.execute('SELECT sub,target,active,created_at FROM subdomains WHERE user_id=? ORDER BY id DESC', (user['id'],)).fetchall()
        subdomains = [dict(r) for r in rows]
        conn.close()
    return render_template('index.html', user=user, subdomains=subdomains)

# Register
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    name = request.form.get('name','').strip()
    email = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    password2 = request.form.get('password2','')
    if not email or not password or password != password2:
        flash('Geçersiz veri veya parolalar eşleşmiyor')
        return redirect(url_for('register'))
    pw_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)',
                     (name,email,pw_hash,datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        flash('Bu e-posta zaten kayıtlı')
        conn.close()
        return redirect(url_for('register'))
    conn.close()
    flash('Kayıt tamam. Giriş yapabilirsiniz.')
    return redirect(url_for('login'))

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    if not user or not user['password_hash'] or not check_password_hash(user['password_hash'], password):
        flash('E-posta veya parola hatalı')
        return redirect(url_for('login'))
    session['user_id'] = user['id']
    flash('Giriş başarılı')
    return redirect(url_for('index'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Çıkış yapıldı')
    return redirect(url_for('login'))

# Google OAuth start
@app.route('/auth/google')
def auth_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return 'Google OAuth konfigüre edilmemiş', 500
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

# Google OAuth callback
@app.route('/auth/google/callback')
def auth_google_callback():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    profile = resp.json()
    # profile contains: id, email, verified_email, name, given_name, family_name, picture
    google_id = profile.get('id')
    email = profile.get('email', '').lower()
    name = profile.get('name')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE google_id=? OR email=?', (google_id,email)).fetchone()
    if user:
        # update google_id if needed
        conn.execute('UPDATE users SET google_id=?, name=? WHERE id=?', (google_id,name,user['id']))
        conn.commit()
        session['user_id'] = user['id']
        conn.close()
        return redirect(url_for('index'))
    # create
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (name,email,google_id,created_at) VALUES (?,?,?,?)', (name,email,google_id,datetime.utcnow().isoformat()))
        conn.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        # email already exists without google_id — attach it
        existing = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if existing:
            conn.execute('UPDATE users SET google_id=? WHERE id=?', (google_id, existing['id']))
            conn.commit()
            session['user_id'] = existing['id']
            conn.close()
            return redirect(url_for('index'))
        conn.close()
        return 'Kayıt hatası', 500
    session['user_id'] = uid
    conn.close()
    return redirect(url_for('index'))

# Create subdomain (JSON API)
@app.route('/create-subdomain', methods=['POST'])
def create_subdomain():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'error': 'giriş gerekli'}), 401

    data = request.get_json() or {}
    sub = (data.get('sub') or '').strip().lower()
    target = (data.get('target') or '').strip()

    import re
    if not re.fullmatch(r'[a-z0-9\-]{2,63}', sub):
        return jsonify({'ok': False, 'error': 'geçersiz subdomain'}), 400

    # 🔥 DOĞRU DOMAIN
    full = f"{sub}.x.supaneli.org"

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO subdomains (user_id, sub, target, active, created_at) VALUES (?,?,?,?,?)',
            (user['id'], sub, target or None, 1, datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'ok': False, 'error': 'subdomain alınmış'}), 409

    conn.close()
    return jsonify({'ok': True, 'full': full})# Simple admin-only route to list users (example)
@app.route('/admin/users')
def admin_users():
    # very naive admin check: SECRET_KEY match
    if session.get('user_id') is None:
        return redirect(url_for('login'))
    # in real life, check user role
    conn = get_db()
    rows = conn.execute('SELECT id,name,email,google_id,created_at FROM users ORDER BY id DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    # For development only. In production use gunicorn or Render's default.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=True)
