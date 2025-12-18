# backend.py
# Flask app + Porkbun DNS automation
# Requirements: flask sqlalchemy authlib requests
# pip install flask sqlalchemy authlib requests

import os
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse, quote_plus

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

# --------------------
# Config (from env)
# --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'supanel.db'))
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

# Porkbun / DNS config (required for DNS automation)
PORKBUN_API_KEY = os.environ.get('pk1_f223cdc7c0203f255236b3a827f29959681f6a33010e0bbafc0921ef4fcc45d4')
PORKBUN_SECRET_KEY = os.environ.get('sk1_869e8a4ae15f90425789e0f7fe03de455f6f4956fc3a84ce59621e95df6bef53')
PORKBUN_DOMAIN = os.environ.get('PORKBUN_DOMAIN')  # e.g. "supaneli.org"
BASE_SUBDOMAIN = os.environ.get('BASE_SUBDOMAIN', 'x')  # the "x" in nabi.x.supaneli.org (can be empty)
RENDER_TARGET = os.environ.get('RENDER_TARGET', 'ozsoy-dns-service.onrender.com')
PORKBUN_API_BASE = 'https://api.porkbun.com/api/json/v3'

DEBUG = os.environ.get('DEBUG', '0') in ('1', 'true', 'True')

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
        authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
        api_base_url='https://www.googleapis.com/oauth2/v2/',
        client_kwargs={'scope': 'openid email profile'},
    )

# --------------------
# DB helpers
# --------------------
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

init_db()

# --------------------
# Porkbun API helpers
# --------------------
def log(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

def porkbun_api_post(endpoint_path, payload):
    """
    POST helper for Porkbun API v3.
    endpoint_path: like '/dns/create/{domain}'
    payload: dict to send as JSON
    returns: parsed JSON (dict)
    raises requests.HTTPError on HTTP errors
    """
    url = f"{PORKBUN_API_BASE}{endpoint_path}"
    headers = {'Content-Type': 'application/json'}
    log('Porkbun POST', url, payload)
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()

def normalize_target_host(maybe_url_or_host):
    """
    Ensure CNAME content is only host (no scheme, no path).
    If IP is provided, return as-is.
    """
    if not maybe_url_or_host:
        return None
    maybe_url_or_host = maybe_url_or_host.strip()
    parsed = urlparse(maybe_url_or_host if '://' in maybe_url_or_host else '//' + maybe_url_or_host)
    host = parsed.hostname or maybe_url_or_host
    return host.strip()

def create_porkbun_record(name, rtype='CNAME', content=None, ttl='600', domain=None):
    """
    Create DNS record on Porkbun.
    name: e.g. 'nabi.x' (host name relative to PORKBUN_DOMAIN)
    domain: e.g. 'supaneli.org'
    """
    if not (PORKBUN_API_KEY and PORKBUN_SECRET_KEY and (domain or PORKBUN_DOMAIN)):
        raise RuntimeError("Porkbun API keys or domain not configured in environment")

    domain = domain or PORKBUN_DOMAIN
    payload = {
        "secretapikey": PORKBUN_SECRET_KEY,
        "apikey": PORKBUN_API_KEY,
        "name": name,
        "type": rtype,
        "content": content or RENDER_TARGET,
        "ttl": str(ttl or "600")
    }
    endpoint = f"/dns/create/{domain}"
    return porkbun_api_post(endpoint, payload)

def edit_porkbun_record_by_name_type(name, rtype='CNAME', content=None, ttl='600', domain=None):
    """
    Edit record by name+type (editByNameType)
    """
    if not (PORKBUN_API_KEY and PORKBUN_SECRET_KEY and (domain or PORKBUN_DOMAIN)):
        raise RuntimeError("Porkbun API keys or domain not configured in environment")

    domain = domain or PORKBUN_DOMAIN
    endpoint = f"/dns/editByNameType/{domain}/{rtype}/{quote_plus(name)}"
    payload = {
        "secretapikey": PORKBUN_SECRET_KEY,
        "apikey": PORKBUN_API_KEY,
        "content": content or RENDER_TARGET,
        "ttl": str(ttl or "600")
    }
    return porkbun_api_post(endpoint, payload)

# --------------------
# Auth helper
# --------------------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()
    return user

# --------------------
# Routes
# --------------------
@app.route('/')
def index():
    user = current_user()
    subdomains = []
    if user:
        conn = get_db()
        rows = conn.execute('SELECT id,sub,target,active,created_at FROM subdomains WHERE user_id=? ORDER BY id DESC', (user['id'],)).fetchall()
        subdomains = [dict(r) for r in rows]
        conn.close()
    return render_template('index.html', user=user, subdomains=subdomains)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    name = request.form.get('name','').strip()
    email = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    password2 = request.form.get('password2','')
    if not email or not password or password != password2:
        flash('Geçersiz veri veya parolalar eşleşmiyor', 'error')
        return redirect(url_for('register'))
    pw_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)',
                     (name,email,pw_hash,datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        flash('Bu e-posta zaten kayıtlı', 'error')
        conn.close()
        return redirect(url_for('register'))
    conn.close()
    flash('Kayıt tamam. Giriş yapabilirsiniz.', 'success')
    return redirect(url_for('login'))

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
        flash('E-posta veya parola hatalı', 'error')
        return redirect(url_for('login'))
    session['user_id'] = user['id']
    flash('Giriş başarılı', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Çıkış yapıldı', 'info')
    return redirect(url_for('login'))

@app.route('/auth/google')
def auth_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return 'Google OAuth konfigüre edilmemiş', 500
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def auth_google_callback():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    profile = resp.json()
    google_id = profile.get('id')
    email = profile.get('email', '').lower()
    name = profile.get('name')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE google_id=? OR email=?', (google_id,email)).fetchone()
    if user:
        conn.execute('UPDATE users SET google_id=?, name=? WHERE id=?', (google_id,name,user['id']))
        conn.commit()
        session['user_id'] = user['id']
        conn.close()
        return redirect(url_for('index'))
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (name,email,google_id,created_at) VALUES (?,?,?,?)', (name,email,google_id,datetime.utcnow().isoformat()))
        conn.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
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

# --------------------
# Create subdomain (JSON API) - creates Porkbun DNS record too
# --------------------
@app.route('/create-subdomain', methods=['POST'])
def create_subdomain():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'error': 'giriş gerekli'}), 401

    data = request.get_json() or {}
    sub = (data.get('sub') or '').strip().lower()
    target = (data.get('target') or '').strip() or None

    import re
    if not re.fullmatch(r'[a-z0-9\-]{2,63}', sub):
        return jsonify({'ok': False, 'error': 'geçersiz subdomain'}), 400

    # Build final user-facing domain and name for Porkbun API
    if BASE_SUBDOMAIN:
        full = f"{sub}.{BASE_SUBDOMAIN}.{PORKBUN_DOMAIN}"
        name_for_api = f"{sub}.{BASE_SUBDOMAIN}"
    else:
        full = f"{sub}.{PORKBUN_DOMAIN}"
        name_for_api = sub

    # Normalize target host for CNAME content
    if target:
        content = normalize_target_host(target)
    else:
        content = RENDER_TARGET

    # Try create DNS record first
    try:
        resp = create_porkbun_record(name=name_for_api, rtype='CNAME', content=content, ttl='600', domain=PORKBUN_DOMAIN)
        log('create_porkbun_record resp:', resp)
    except requests.HTTPError as e:
        # HTTP-level error from requests
        try:
            err_text = e.response.text
        except Exception:
            err_text = str(e)
        return jsonify({'ok': False, 'error': f'Porkbun API HTTP error: {err_text}'}), 502
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Porkbun API error: {str(e)}'}), 502

    # If API returned non-success, try edit as fallback
    if resp.get('status') != 'SUCCESS':
        try:
            edit_resp = edit_porkbun_record_by_name_type(name=name_for_api, rtype='CNAME', content=content, ttl='600', domain=PORKBUN_DOMAIN)
            log('edit_porkbun_record resp:', edit_resp)
            if edit_resp.get('status') != 'SUCCESS':
                return jsonify({'ok': False, 'error': f'Porkbun error: {resp.get("message") or edit_resp.get("message") or "unknown"}'}), 502
        except requests.HTTPError as e:
            try:
                err_text = e.response.text
            except Exception:
                err_text = str(e)
            return jsonify({'ok': False, 'error': f'Porkbun HTTP error on edit: {err_text}'}), 502
        except Exception as e:
            return jsonify({'ok': False, 'error': f'Porkbun edit error: {str(e)}'}), 502

    # Insert into local DB
    conn = get_db()
    try:
        conn.execute('INSERT INTO subdomains (user_id,sub,target,active,created_at) VALUES (?,?,?,?,?)',
                     (user['id'], sub, content or None, 1, datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        # If DB already has it, still return success (idempotent)
        return jsonify({'ok': False, 'error': 'subdomain alınmış'}), 409
    conn.close()

    return jsonify({'ok': True, 'full': full})

# Admin listing users (simple)
@app.route('/admin/users')
def admin_users():
    if session.get('user_id') is None:
        return redirect(url_for('login'))
    conn = get_db()
    rows = conn.execute('SELECT id,name,email,google_id,created_at FROM users ORDER BY id DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# --------------------
# Run
# --------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=DEBUG)
