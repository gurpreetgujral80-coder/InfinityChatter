import eventlet
eventlet.monkey_patch()
import os
import sqlite3
import secrets
import time
import json
import time
import threading
import hashlib
import hmac
import pathlib
import base64
import requests
from datetime import datetime
from flask import (
    Flask, render_template_string, request, jsonify, current_app,
    session as flask_session, redirect, url_for, send_from_directory,
    abort, make_response
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
from pywebpush import webpush, WebPushException
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

VAPID_PUBLIC_KEY  = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_CLAIMS = {"sub": "https://progamer8.pythonanywhere.com"}

if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
    raise RuntimeError("VAPID keys not loaded! Check .env and os.environ.")

app = Flask(__name__, static_folder="static")

ALLOWED_PARENT_ORIGINS = [
    "https://progamer8.pythonanywhere.com",   # allow itself
    "http://127.0.0.1:5010",                  # your local testing host
    "http://192.168.1.100:5010",              # add your phone/PC local IP if used
    "https://your-production-game-site.example" # production host (replace)
]

@app.after_request
def allow_iframe(response):
    # Remove or override headers that block embedding
    response.headers.pop('X-Frame-Options', None)
    csp = response.headers.get('Content-Security-Policy', '')
    # Remove any existing frame-ancestors rule
    if 'frame-ancestors' in csp:
        parts = [p for p in csp.split(';') if not p.strip().startswith('frame-ancestors')]
        csp = ';'.join(parts)
    # Allow embedding from anywhere or specific origin (better)
    response.headers['Content-Security-Policy'] = f"{csp}; frame-ancestors *"
    return response

# -------- CONFIG ----------
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
# session cookie fix for Render & mobile browsers
app.config.update({
    "SESSION_COOKIE_SAMESITE": "None",  # allow cross-site or fetch navigation
    "SESSION_COOKIE_SECURE": True,      # required for HTTPS
    "SESSION_COOKIE_HTTPONLY": True,    # security
    "SESSION_COOKIE_PATH": "/",          # make sure it applies to all routes
})

PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_legends.db")
HEADING_IMG = "/static/heading.png"  # place your heading image here
MAX_MESSAGES = 100
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
ALLOWED_VIDEO_EXT = {"mp4", "webm", "ogg"}
ALLOWED_AUDIO_EXT = {"mp3", "wav", "ogg", "m4a", "webm"}
messages_store = []
polls_store = {}
USER_SID = {}
ONLINE_USERS = {}
MEET_BASE_URL = os.environ.get('MEET_BASE_URL', 'https://meet.google.com/new')

# ensure static subfolders
pathlib.Path(os.path.join(app.static_folder, "uploads")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "stickers")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "gifs")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "avatars")).mkdir(parents=True, exist_ok=True)

# SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# --------- DB init & helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ---- Core tables ----
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            pass_salt BLOB,
            pass_hash BLOB,
            avatar TEXT DEFAULT NULL,
            status TEXT DEFAULT '',
            is_owner INTEGER DEFAULT 0,
            is_partner INTEGER DEFAULT 0
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            text TEXT,
            attachments TEXT DEFAULT '[]',
            reactions TEXT DEFAULT '[]',
            edited INTEGER DEFAULT 0,
            created_at INTEGER
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS calls (
            id TEXT PRIMARY KEY,
            caller TEXT,
            callee TEXT,
            is_video INTEGER,
            started_at INTEGER,
            ended_at INTEGER,
            status TEXT
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            subscription TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_seen INTEGER
        );
    """)

    conn.commit()

    # ---- Safe schema upgrades ----
    # add phone column to users if missing
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        if "phone" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT NULL")
            conn.commit()
    except Exception as e:
        print("[init_db] Warning: could not add phone column:", e)

    # ---- Contacts table ----
    c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,        -- username who owns this contact list
            contact_name TEXT,
            phone TEXT,
            avatar TEXT DEFAULT NULL,
            added_at INTEGER,
            source TEXT DEFAULT 'manual'
        );
    """)

    # ---- Contact invites table ----
    c.execute("""
        CREATE TABLE IF NOT EXISTS contact_invites (
            token TEXT PRIMARY KEY,
            inviter TEXT NOT NULL,
            phone TEXT,
            created_at INTEGER,
            expires_at INTEGER
        );
    """)

    conn.commit()
    conn.close()


def db_conn():
    return sqlite3.connect(DB_PATH)

# initialize database at startup
init_db()

@app.route("/api/vapid_public")
def vapid_public():
    return jsonify({"publicKey": VAPID_PUBLIC_KEY})

@app.route("/api/save_push_sub", methods=["POST"])
def save_push_sub():
    body = request.get_json() or {}
    sub = body.get("subscription")
    if not sub:
        return jsonify({"error": "missing subscription"}), 400

    username = flask_session.get("username")  # may be None
    endpoint = sub.get("endpoint") if isinstance(sub, dict) else None
    now = int(time.time())

    conn = db_conn()
    c = conn.cursor()
    try:
        if endpoint:
            # upsert by endpoint
            c.execute("SELECT id FROM push_subscriptions WHERE subscription LIKE ?", ('%'+endpoint+'%',))
            r = c.fetchone()
            if r:
                c.execute("UPDATE push_subscriptions SET username=?, last_seen=?, subscription=? WHERE id=?",
                          (username, now, json.dumps(sub), r[0]))
            else:
                c.execute("INSERT INTO push_subscriptions (username, subscription, created_at, last_seen) VALUES (?, ?, ?, ?)",
                          (username, json.dumps(sub), now, now))
        else:
            # fallback: insert raw subscription JSON
            c.execute("INSERT INTO push_subscriptions (username, subscription, created_at, last_seen) VALUES (?, ?, ?, ?)",
                      (username, json.dumps(sub), now, now))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})

@app.route('/static/sw.js')
def serve_sw():
    try:
        response = make_response(
            send_from_directory(current_app.static_folder, 'sw.js', mimetype='application/javascript')
        )
        response.headers['Service-Worker-Allowed'] = '/'  # allow root scope
        response.headers['Cache-Control'] = 'no-cache'    # avoid caching issues
        return response
    except Exception as e:
        current_app.logger.exception("Failed to serve sw.js")
        return "Internal Server Error", 500

@socketio.on('send_message')
def handle_send_message(data):
    # Save message
    sender = data.get('sender')
    avatar = None
    try:
        user = load_user_by_name(sender)
        if user:
            avatar = user.get('avatar')
            if avatar and not avatar.startswith('/') and re.match(r'^m\d+\.(webp|png|jpg|jpeg)$', avatar, re.I):
                avatar = f'/static/{avatar}'
    except Exception:
        avatar = None

    new_msg = {
        "id": len(messages_store) + 1,
        "sender": sender,
        "text": data.get('text'),
        "attachments": data.get('attachments', []),
        "reactions": [],
        "avatar": avatar
    }

    messages_store.append(new_msg)
    # Broadcast to all connected clients
    socketio.emit('new_message', new_msg)

# user helpers
def save_user(name, salt_bytes, hash_bytes, avatar=None, status="", make_owner=False, make_partner=False):
    conn = db_conn(); c = conn.cursor()
    if make_owner:
        c.execute("UPDATE users SET is_owner = 0")
    c.execute("""
        INSERT INTO users (name, pass_salt, pass_hash, avatar, status, is_owner, is_partner)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          pass_salt=excluded.pass_salt, pass_hash=excluded.pass_hash,
          avatar=COALESCE(excluded.avatar, users.avatar),
          status=COALESCE(excluded.status, users.status),
          is_owner=COALESCE((SELECT is_owner FROM users WHERE name = excluded.name), excluded.is_owner),
          is_partner=COALESCE((SELECT is_partner FROM users WHERE name = excluded.name), excluded.is_partner)
    """, (name, sqlite3.Binary(salt_bytes), sqlite3.Binary(hash_bytes), avatar, status, 1 if make_owner else 0, 1 if make_partner else 0))
    conn.commit(); conn.close()

def load_user_by_name(name):
    conn = db_conn(); c = conn.cursor()
    # FIX: Use COLLATE NOCASE for case-insensitive lookup
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE name = ? COLLATE NOCASE LIMIT 1", (name,))
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1], "pass_salt": r[2], "pass_hash": r[3], "avatar": r[4], "status": r[5], "is_owner": bool(r[6]), "is_partner": bool(r[7])}
    return None

def clone_user(name, pass_salt, pass_hash, avatar=None, status=""):
    """
    Create a new user row that reuses the provided salt+hash so the same
    password will work for the new username. New users are NOT owners/partners.
    Returns the newly created user dict (or None on error).
    """
    # normalize memoryview -> bytes if necessary
    if isinstance(pass_salt, memoryview): pass_salt = bytes(pass_salt)
    if isinstance(pass_hash, memoryview): pass_hash = bytes(pass_hash)

    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO users (name, pass_salt, pass_hash, avatar, status, is_owner, is_partner)
               VALUES (?, ?, ?, ?, ?, 0, 0)""",
            (name, sqlite3.Binary(pass_salt), sqlite3.Binary(pass_hash), avatar, status)
        )
        conn.commit()
    except Exception:
        # If INSERT fails (e.g. name collision), ignore/close and continue
        conn.rollback()
    finally:
        conn.close()

    return load_user_by_name(name)

def load_first_user():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"name": r[0], "pass_salt": r[1], "pass_hash": r[2], "avatar": r[3], "status": r[4], "is_owner": bool(r[5]), "is_partner": bool(r[6])}
    return None

def set_partner_by_name(name):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE users SET is_partner = 1 WHERE name = ?", (name,))
    conn.commit(); conn.close()

def get_owner():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE is_owner = 1 LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1], "pass_salt": r[2], "pass_hash": r[3], "avatar": r[4], "status": r[5], "is_owner": bool(r[6]), "is_partner": bool(r[7])}
    return None

def get_partner():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, name FROM users WHERE is_partner = 1 LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1]}
    return None

def _ensure_peer_token_column():
    """Add peer_token column to contacts if missing."""
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(contacts);")
    cols = [r[1] for r in cur.fetchall()]
    if 'peer_token' not in cols:
        try:
            cur.execute("ALTER TABLE contacts ADD COLUMN peer_token TEXT;")
            conn.commit()
        except Exception:
            # If ALTER fails for any schema reason, ignore — app still works, but tokens won't be stored
            pass
    conn.close()

def generate_peer_token():
    """Return a 30-character alphanumeric token."""
    # Use a URL-safe base and then strip non-alnum and truncate to 30
    token = secrets.token_urlsafe(22)  # length ~ 29-30 chars base64-url
    token = re.sub(r'[^A-Za-z0-9]', '', token)
    # if token too short, extend deterministically
    if len(token) < 30:
        token += re.sub(r'[^A-Za-z0-9]', '', hashlib.sha256(token.encode()).hexdigest())
    return token[:30]

# ---------- Contacts helpers ----------
def add_contact(owner, contact_name, phone, avatar=None, source='manual', peer_token=None):
    """
    Insert a contact; normalize owner/contact_name/phone (trim).
    If the contacts table has a peer_token column and peer_token is provided,
    it will be saved. Uses INSERT OR IGNORE so duplicate owner/contact pairs are safe.
    """
    import time
    now = int(time.time())
    owner = (owner or '').strip()
    contact_name = (contact_name or '').strip()
    phone = (phone or '').strip() or None

    conn = db_conn()
    c = conn.cursor()

    # detect whether peer_token column exists and add it if missing (best-effort)
    try:
        c.execute("PRAGMA table_info(contacts);")
        cols = [r[1] for r in c.fetchall()]
        if 'peer_token' not in cols:
            try:
                c.execute("ALTER TABLE contacts ADD COLUMN peer_token TEXT;")
                conn.commit()
                cols.append('peer_token')
            except Exception:
                # ignore alter errors (some sqlite schemas may not allow)
                pass
    except Exception:
        cols = []

    # Build query depending on whether peer_token column exists
    if 'peer_token' in cols:
        c.execute(
            "INSERT OR IGNORE INTO contacts (owner, contact_name, phone, avatar, added_at, source, peer_token) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (owner, contact_name, phone, avatar, now, source, peer_token)
        )
    else:
        c.execute(
            "INSERT OR IGNORE INTO contacts (owner, contact_name, phone, avatar, added_at, source) VALUES (?, ?, ?, ?, ?, ?)",
            (owner, contact_name, phone, avatar, now, source)
        )

    conn.commit()
    conn.close()
    return True

def list_contacts_for(owner):
    """Return contacts for an owner (case-insensitive match)."""
    owner = (owner or '').strip()
    conn = db_conn(); c = conn.cursor()
    # match owner using lower() to be case-insensitive
    c.execute(
      "SELECT id, contact_name, phone, avatar, added_at, source FROM contacts WHERE lower(owner) = lower(?) ORDER BY added_at DESC",
      (owner,)
    )
    rows = c.fetchall(); conn.close()
    return [{"id": r[0], "name": r[1], "phone": r[2], "avatar": r[3], "added_at": r[4], "source": r[5]} for r in rows]

def find_users_by_phones(phones):
    # normalize phones and find registered users (phone column on users table)
    if not phones: return {}
    conn = db_conn(); c = conn.cursor()
    q = "SELECT name, phone FROM users WHERE phone IN ({})".format(",".join("?"*len(phones)))
    c.execute(q, phones)
    rows = c.fetchall(); conn.close()
    return {r[1]: r[0] for r in rows}  # map phone -> username

# ---------- Invite helpers ----------
def create_contact_invite(inviter, phone=None, expires_secs=7*24*3600):
    token = secrets.token_urlsafe(20)
    now = int(time.time())
    exp = now + expires_secs if expires_secs else None
    conn = db_conn(); c = conn.cursor()
    c.execute("INSERT INTO contact_invites (token, inviter, phone, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
              (token, inviter, phone, now, exp))
    conn.commit(); conn.close()
    return token

def load_contact_invite(token):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT token, inviter, phone, created_at, expires_at FROM contact_invites WHERE token = ?", (token,))
    r = c.fetchone(); conn.close()
    if not r: return None
    return {"token": r[0], "inviter": r[1], "phone": r[2], "created_at": r[3], "expires_at": r[4]}

def save_message(sender, text, attachments=None):
    """
    Save a message to the SQLite messages table and return the inserted message dict.
    attachments should be a list (will be stored as JSON string).
    """
    conn = db_conn()
    c = conn.cursor()
    ts = int(time.time())
    att = json.dumps(attachments or [])
    c.execute(
        "INSERT INTO messages (sender, text, attachments, created_at) VALUES (?, ?, ?, ?)",
        (sender, text, att, ts)
    )
    mid = c.lastrowid
    conn.commit()
    conn.close()

    # trim to configured maximum messages
    try:
        trim_messages_limit(MAX_MESSAGES)
    except Exception:
        pass

    # assign avatar for sender
    avatar = None
    try:
        user = load_user_by_name(sender)
        if user:
            avatar = user.get('avatar')
            if avatar and not avatar.startswith('/') and re.match(r'^m\d+\.(webp|png|jpg|jpeg)$', avatar, re.I):
                avatar = f'/static/{avatar}'
    except Exception:
        avatar = None

    # return full message dict with avatar
    return {
        "id": mid,
        "sender": sender,
        "text": text,
        "attachments": attachments or [],
        "reactions": [],
        "edited": False,
        "created_at": ts,
        "avatar": avatar
    }

def send_web_push(subscription_info, payload_dict):
    """
    Send a web push to a subscription object (dict). Returns True on success,
    returns numeric HTTP status (404/410) or False on other failures.
    """
    try:
        webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload_dict),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=VAPID_CLAIMS,
            timeout=10
        )
        return True
    except WebPushException as ex:
        # log details and return status code for caller to act on
        try:
            code = ex.response.status_code
            app.logger.warning("WebPushException status=%s body=%s", code, ex.response.text)
            return code
        except Exception:
            app.logger.exception("WebPushException (no response): %s", ex)
            return False
    except Exception as e:
        app.logger.exception("Unexpected error sending web push: %s", e)
        return False

# --- API: get contacts for logged in user ---
@app.route('/api/contacts', methods=['GET'])
def api_contacts():
    username = flask_session.get('username')
    if not username:
        return jsonify({"error": "not_logged_in"}), 401
    contacts = list_contacts_for(username)
    return jsonify({"contacts": contacts})

# --- API: add one or multiple contacts from client ---
@app.route('/api/contacts_add', methods=['POST'])
def api_contacts_add():
    username = flask_session.get('username')
    if not username:
        return jsonify({"error": "not_logged_in"}), 401
    body = request.get_json() or {}
    entries = body.get('contacts') or []  # list of {name, phone}
    if not entries:
        return jsonify({"error": "no contacts provided"}), 400

    phones = []
    for e in entries:
        phone = (e.get('phone') or '').strip()
        if not phone: continue
        add_contact(username, e.get('name') or '', phone, avatar=e.get('avatar'), source=e.get('source','manual'))
        phones.append(phone)

    # check which of these phones already correspond to registered users
    found = find_users_by_phones(list(set(phones)))
    # notify user (real-time)
    socketio.emit('contacts_updated', {'owner': username}, room=USER_SID.get(username)) if USER_SID.get(username) else None

    # prepare response mapping phone -> username if exists
    present = []
    missing = []
    for p in phones:
        if p in found:
            present.append({"phone": p, "username": found[p]})
        else:
            missing.append({"phone": p})

    return jsonify({"ok": True, "present": present, "missing": missing})

# ---------- Invite + Contacts helpers & endpoints (replace your existing block) ----------
# Note: this block expects sqlite3, time, secrets, current_app and flask_session to be available
# in your module (you previously imported them). It will prefer an existing db_conn()/_db_conn()
# if present, otherwise fall back to using DB_PATH.

def _db_conn():
    """Return a sqlite connection. Prefer existing helpers if available."""
    # prefer existing helpers if present
    if '_db_conn' in globals() and callable(globals()['_db_conn']) and globals()['_db_conn'] is not _db_conn:
        return globals()['_db_conn']()
    if 'db_conn' in globals() and callable(globals()['db_conn']):
        return globals()['db_conn']()
    # fallback to DB_PATH direct open
    if 'DB_PATH' in globals():
        return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    raise RuntimeError("No db connection function found and DB_PATH not defined")

def _ensure_invite_and_contacts_schema():
    """Create minimal tables/columns we need. Safe to call repeatedly."""
    conn = _db_conn()
    cur = conn.cursor()

    # contact_invites table - single-use tokens
    cur.execute("""
      CREATE TABLE IF NOT EXISTS contact_invites (
         token TEXT PRIMARY KEY,
         inviter TEXT,
         phone TEXT,
         created_at INTEGER,
         expires_at INTEGER
      );
    """)

    # canonical contacts table we will use in code
    cur.execute("""
      CREATE TABLE IF NOT EXISTS contacts (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         owner TEXT NOT NULL,
         contact_name TEXT NOT NULL,
         phone TEXT,
         avatar TEXT,
         added_at INTEGER,
         source TEXT,
         UNIQUE(owner, contact_name)
      );
    """)

    # best-effort: ensure users table has phone column (many schemas won't; sqlite allows simple ADD)
    try:
        cur.execute("PRAGMA table_info(users);")
        cols = [r[1] for r in cur.fetchall()]
        if 'phone' not in cols:
            try:
                cur.execute("ALTER TABLE users ADD COLUMN phone TEXT;")
            except Exception:
                # ignore if alter fails (complex schema/older sqlite)
                pass
    except Exception:
        # users table might not exist yet; ignore
        pass

    conn.commit()
    conn.close()

def normalize_phone(s):
    if not s: return ''
    return ''.join(ch for ch in (s or '') if ch.isdigit() or ch == '+')

def load_contact_invite(token):
    """Return invite dict or None."""
    if not token: return None
    _ensure_invite_and_contacts_schema()
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("SELECT token, inviter, phone, created_at, expires_at FROM contact_invites WHERE token=?", (token,))
    row = cur.fetchone()
    conn.close()
    if not row: return None
    return {"token": row[0], "inviter": row[1], "phone": row[2], "created_at": row[3], "expires_at": row[4]}

def create_contact_invite(inviter_username, phone=None, expires_secs=7*24*3600):
    """Create a new invite token and store it."""
    _ensure_invite_and_contacts_schema()
    token = secrets.token_urlsafe(18)
    now = int(time.time())
    exp = now + expires_secs if expires_secs else None
    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO contact_invites (token, inviter, phone, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token, inviter_username, phone or None, now, exp))
    conn.commit()
    conn.close()
    return token

# --- API: create a share invite link for a phone (or general invite) ---
@app.route('/api/create_contact_invite', methods=['POST'])
def api_create_contact_invite():
    # ✅ Ensure schema and DB consistency before doing anything
    try:
        _ensure_invite_and_contacts_schema()
    except Exception:
        current_app.logger.exception("Schema ensure failed in create_contact_invite")

    body = request.get_json(silent=True) or {}

    # accept username from flask_session or from body
    username = None
    try:
        username = flask_session.get('username') if 'flask_session' in globals() else None
    except Exception:
        username = None

    if not username:
        username = body.get('username')
    if not username:
        return jsonify({"error": "not_logged_in"}), 401

    phone = body.get('phone')  # optional
    try:
        token = create_contact_invite(username, phone=phone)
    except Exception as e:
        current_app.logger.exception("create_contact_invite failed: %s", e)
        return jsonify({"error": "server_error", "detail": str(e)}), 500

    base = request.url_root.rstrip('/')
    invite_url = f"{base}/invite/{token}"
    return jsonify({"ok": True, "url": invite_url, "token": token})

# --- API: return invite info for a token (used by invite page to show inviter name) ---
@app.route('/api/invite_info')
def api_invite_info():
    t = request.args.get('t') or request.args.get('token')
    if not t:
        return jsonify({"error": "missing_token"}), 400
    inv = load_contact_invite(t)
    if not inv:
        return jsonify({"error": "invalid"}), 404

    inviter_name = inv.get('inviter')
    # try to lookup nicer display name from users table (match by name OR phone if inviter was a phone)
    try:
        conn = _db_conn(); cur = conn.cursor()
        # try match by name first
        cur.execute("SELECT name, phone FROM users WHERE name = ? LIMIT 1", (inv.get('inviter'),))
        row = cur.fetchone()
        if not row and inv.get('inviter'):
            # fallback: maybe inviter value is actually a phone
            cur.execute("SELECT name, phone FROM users WHERE phone = ? LIMIT 1", (inv.get('inviter'),))
            row = cur.fetchone()
        conn.close()
        if row and row[0]:
            inviter_name = row[0]
    except Exception:
        current_app.logger.exception("invite_info lookup failed")

    return jsonify({"inviter_name": inviter_name, "phone": inv.get('phone')})

# --- API: accept invite (JSON) — create user if needed and add mutual contacts ---
# --- API: accept invite (JSON) — create user if needed and add mutual contacts ---
@app.route('/api/accept_invite', methods=['POST'])
def api_accept_invite():
    from flask import request, jsonify, current_app
    import time, secrets, re

    data = request.get_json(silent=True) or {}
    token = (data.get('token') or '').strip()
    name = (data.get('name') or '').strip()
    phone = (data.get('phone') or '').strip()

    if not token or not name or not phone:
        return jsonify({"error": "missing_fields"}), 400

    inv = load_contact_invite(token)
    if not inv:
        return jsonify({"error": "invalid_invite"}), 404

    inviter = (inv.get('inviter') or '').strip()
    norm_phone = ''.join(ch for ch in phone if ch.isdigit() or ch == '+')

    # Ensure basic invite/contacts schema (best-effort)
    try:
        _ensure_invite_and_contacts_schema()
    except Exception:
        current_app.logger.exception("schema ensure failed")

    conn = None
    new_user_name = name
    try:
        conn = _db_conn()
        cur = conn.cursor()

        # Ensure users table schema and try to find existing user by phone
        try:
            cur.execute("PRAGMA table_info(users);")
            user_cols = [r[1] for r in cur.fetchall()]
        except Exception:
            user_cols = []

        found = None
        if 'phone' in user_cols:
            cur.execute("SELECT rowid, name FROM users WHERE phone = ? COLLATE NOCASE LIMIT 1", (norm_phone,))
            found = cur.fetchone()

        if found:
            new_user_name = found[1] or name
        else:
            # Insert minimal user respecting available columns
            insert_cols = []
            insert_vals = []
            if 'name' in user_cols:
                insert_cols.append('name'); insert_vals.append(name)
            if 'phone' in user_cols:
                insert_cols.append('phone'); insert_vals.append(norm_phone)

            try:
                if insert_cols:
                    q = "INSERT INTO users ({}) VALUES ({})".format(",".join(insert_cols), ",".join("?"*len(insert_vals)))
                    cur.execute(q, insert_vals)
                else:
                    # fallback: forgiving insert (may fail if schema is strict)
                    cur.execute("INSERT INTO users (name, phone) VALUES (?, ?)", (name, norm_phone))
            except Exception:
                # last-resort: create tiny users table and insert (only if necessary)
                try:
                    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)")
                    cur.execute("INSERT INTO users (name, phone) VALUES (?, ?)", (name, norm_phone))
                except Exception:
                    current_app.logger.exception("Unable to create/insert into users table")
            conn.commit()
            new_user_name = name

        # Ensure inviter exists in users table (safety)
        try:
            cur.execute("SELECT 1 FROM users WHERE name = ? LIMIT 1", (inviter,))
            if not cur.fetchone():
                try:
                    cur.execute("INSERT OR IGNORE INTO users (name) VALUES (?)", (inviter,))
                    conn.commit()
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure contacts table has peer_token column (add if missing)
        try:
            cur.execute("PRAGMA table_info(contacts);")
            contact_cols = [r[1] for r in cur.fetchall()]
            if 'peer_token' not in contact_cols:
                try:
                    cur.execute("ALTER TABLE contacts ADD COLUMN peer_token TEXT;")
                    conn.commit()
                    contact_cols.append('peer_token')
                except Exception:
                    # ignore if ALTER fails
                    pass
        except Exception:
            contact_cols = []

        # generate a shared peer_token (30 alnum chars)
        raw = secrets.token_urlsafe(22)
        peer_token = re.sub(r'[^A-Za-z0-9]', '', raw)
        if len(peer_token) < 30:
            # extend deterministically
            import hashlib
            peer_token += re.sub(r'[^A-Za-z0-9]', '', hashlib.sha256(peer_token.encode()).hexdigest())
        peer_token = peer_token[:30]

        ts = int(time.time())

        # Insert mutual contacts: inviter -> new_user ; new_user -> inviter
        try:
            # inviter side
            if 'peer_token' in contact_cols:
                cur.execute("""
                    INSERT OR IGNORE INTO contacts
                    (owner, contact_name, phone, avatar, added_at, source, peer_token)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (inviter, new_user_name, norm_phone, None, ts, 'invite_sent', peer_token))
            else:
                cur.execute("""
                    INSERT OR IGNORE INTO contacts
                    (owner, contact_name, phone, avatar, added_at, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (inviter, new_user_name, norm_phone, None, ts, 'invite_sent'))

            # lookup inviter phone if available
            inviter_phone = None
            try:
                cur.execute("SELECT phone FROM users WHERE name = ? LIMIT 1", (inviter,))
                r = cur.fetchone()
                inviter_phone = r[0] if r else None
            except Exception:
                inviter_phone = None

            # new user side
            if 'peer_token' in contact_cols:
                cur.execute("""
                    INSERT OR IGNORE INTO contacts
                    (owner, contact_name, phone, avatar, added_at, source, peer_token)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (new_user_name, inviter, inviter_phone, None, ts, 'invite_received', peer_token))
            else:
                cur.execute("""
                    INSERT OR IGNORE INTO contacts
                    (owner, contact_name, phone, avatar, added_at, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (new_user_name, inviter, inviter_phone, None, ts, 'invite_received'))

            # delete invite token (single-use)
            cur.execute("DELETE FROM contact_invites WHERE token = ?", (token,))
            conn.commit()
        except Exception as e:
            conn.rollback()
            current_app.logger.exception("contacts insert failed: %s", e)
            return jsonify({"error": "server_error", "detail": str(e)}), 500

    except Exception as e:
        if conn:
            conn.rollback()
        current_app.logger.exception("accept_invite failed: %s", e)
        return jsonify({"error": "server_error", "detail": str(e)}), 500
    finally:
        if conn:
            conn.close()

    # Notify inviter and new user (if online) about new contact
    try:
        payload = {'inviter': inviter, 'new_name': new_user_name, 'new_phone': norm_phone, 'peer_token': peer_token}
        if 'USER_SID' in globals() and 'socketio' in globals():
            try:
                inviter_sid = USER_SID.get(inviter)
                if inviter_sid:
                    socketio.emit('contact_added_by_invite', payload, room=inviter_sid)
            except Exception:
                current_app.logger.exception("emit to inviter failed")

            try:
                new_sid = USER_SID.get(new_user_name)
                if new_sid:
                    socketio.emit('contact_added_by_invite', payload, room=new_sid)
            except Exception:
                current_app.logger.exception("emit to new user failed")
    except Exception:
        current_app.logger.exception("notify inviter/new user failed")

    return jsonify({"success": True, "added": True, "new_user": new_user_name, "peer_token": peer_token})

# --- Invite landing page (GET returns styled HTML; form posts JSON to /api/accept_invite) ---
@app.route('/invite/<token>', methods=['GET'])
def invite_landing(token):
    inv = load_contact_invite(token)
    if not inv:
        return "Invalid or expired invite", 404
    prephone = inv.get('phone') or ''
    # Render minimal, styled landing page (posts JSON to /api/accept_invite)
    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Join InfinityChatter</title>
  <link rel="icon" href="/static/favicon.png" type="image/png">
  <link rel="apple-touch-icon" href="/static/favicon.png">
  <link rel="shortcut icon" href="/static/favicon.png">
  <link rel="manifest" href="/static/manifest.json">
  <meta name="theme-color" content="#0f172a">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="InfinityChatter">
  <meta name="mobile-web-app-capable" content="yes">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Pacifico&family=Poppins:wght@400;600&display=swap" rel="stylesheet">
</head>
<body class="min-h-screen bg-gradient-to-b from-slate-50 to-indigo-50 flex flex-col items-center justify-center p-6">
  <div class="bg-white/80 backdrop-blur rounded-2xl shadow p-8 w-full max-w-md text-center">
    <h1 class="text-3xl" style="font-family: 'Pacifico', cursive;">InfinityChatter</h1>
    <p class="text-slate-600 mb-6">You've been invited by <strong id="inviterName">{{ inviter }}</strong></p>

    <form id="joinForm" class="flex flex-col gap-4" onsubmit="return false;">
      <input id="name" type="text" placeholder="Your full name" required class="border rounded-xl px-4 py-2" />
      <input id="phone" type="tel" placeholder="Your phone number" value="{{ phone }}" required class="border rounded-xl px-4 py-2" />
      <button id="joinBtn" class="bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl py-2">Join InfinityChatter</button>
    </form>

    <p id="statusMsg" class="text-sm text-slate-500 mt-4"></p>
  </div>

<script>
(function(){
  const token = "{{ token }}";

  // show friendly inviter name if API can provide it
  fetch('/api/invite_info?t=' + encodeURIComponent(token)).then(r => r.json()).then(j => {
    if (j && j.inviter_name) document.getElementById('inviterName').textContent = j.inviter_name;
  }).catch(()=>{});

  document.getElementById('joinBtn').addEventListener('click', async function(){
    const status = document.getElementById('statusMsg');
    const name = document.getElementById('name').value.trim();
    const phone = document.getElementById('phone').value.trim();
    if (!name || !phone) { status.textContent = 'Please fill both fields'; return; }

    status.textContent = 'Joining…';
    try {
      const resp = await fetch('/api/accept_invite', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ token, name, phone })
      });
      const j = await resp.json();
      if (resp.ok && j && j.success) {
        localStorage.setItem('infinity_profile', JSON.stringify({ name: name, phone: phone }));
        status.textContent = '✅ Joined — redirecting…';
        setTimeout(()=> location.href = '/inbox', 900);
      } else {
        status.textContent = 'Error: ' + (j && j.error ? j.error : 'Unable to join');
      }
    } catch (err) {
      status.textContent = 'Network error';
    }
  });
})();
</script>
</body>
</html>
    """, inviter=inv.get('inviter'), phone=prephone, token=token)

@app.route("/api/send_test_push", methods=["POST"])
def api_send_test_push():
    """
    POST JSON optional: { "username": "someone" } to send to that user's subscriptions,
    otherwise sends to the most recent saved subscription for debug.
    """
    body = request.get_json(silent=True) or {}
    target_username = body.get("username")

    conn = db_conn(); c = conn.cursor()
    try:
        if target_username:
            c.execute("SELECT id, username, subscription FROM push_subscriptions WHERE username = ? ORDER BY created_at DESC", (target_username,))
        else:
            c.execute("SELECT id, username, subscription FROM push_subscriptions ORDER BY created_at DESC LIMIT 1")
        rows = c.fetchall()
    finally:
        conn.close()

    if not rows:
        return jsonify({"error": "no subscription found"}), 404

    payload = {
        "title": "Test Sender",
        "body": "Notification",
        "icon": "/static/default-avatar.png",
        "url": "/"
    }

    results = []
    for row in rows:
        sub_id, uname, sub_json = row
        try:
            subscription = json.loads(sub_json)
        except Exception as e:
            results.append({"id": sub_id, "status": "bad_json", "error": str(e)})
            continue

        resp = send_web_push(subscription, payload)
        results.append({"id": sub_id, "username": uname, "send_result": resp})
        # if resp is 404 or 410, remove it
        if resp == 404 or resp == 410:
            conn = db_conn(); c = conn.cursor()
            c.execute("DELETE FROM push_subscriptions WHERE id=?", (sub_id,))
            conn.commit(); conn.close()

    return jsonify({"results": results})

def fetch_messages(since=0):
    """
    Fetch all messages from SQLite whose id > since.
    Returns a list of dicts in the shape expected by your JS frontend.
    """
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "SELECT id, sender, text, attachments, reactions, edited, created_at "
        "FROM messages WHERE id > ? ORDER BY id ASC",
        (since,)
    )
    rows = c.fetchall()
    conn.close()

    messages = []
    for r in rows:
        mid, sender, text, attachments_json, reactions_json, edited, created_at = r
        attachments = json.loads(attachments_json or "[]")
        reactions = json.loads(reactions_json or "[]")

        # assign avatar for sender
        avatar = None
        try:
            user = load_user_by_name(sender)
            if user:
                avatar = user.get('avatar')
                if avatar and not avatar.startswith('/') and re.match(r'^m\d+\.(webp|png|jpg|jpeg)$', avatar, re.I):
                    avatar = f'/static/{avatar}'
        except Exception:
            avatar = None

        messages.append({
            "id": mid,
            "sender": sender,
            "text": text,
            "attachments": attachments,
            "reactions": reactions,
            "edited": bool(edited),
            "created_at": created_at,
            "avatar": avatar
        })
    return messages

def trim_messages_limit(max_messages=80):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM messages"); total = c.fetchone()[0]
    if total <= max_messages: conn.close(); return
    to_delete = total - max_messages
    c.execute("DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY id ASC LIMIT ?)", (to_delete,))
    conn.commit(); conn.close()

def edit_message_db(msg_id, new_text, editor):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    sender = r[0]
    user = load_user_by_name(editor)
    if editor != sender and not (user and user.get("is_owner")):
        conn.close(); return False, "not allowed"
    c.execute("UPDATE messages SET text = ?, edited = 1 WHERE id = ?", (new_text, msg_id))
    conn.commit(); conn.close(); return True, None

def delete_message_db(msg_id, requester):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    sender = r[0]
    user = load_user_by_name(requester)
    if requester != sender and not (user and user.get("is_owner")):
        conn.close(); return False, "not allowed"
    c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit(); conn.close(); return True, None

def react_message_db(msg_id, reactor, emoji):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT reactions FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    reactions = json.loads(r[0] or "[]")
    # Toggle reactor's emoji (if same emoji exists by same user remove; otherwise add)
    removed = False
    for rec in list(reactions):
        if rec.get("emoji") == emoji and rec.get("user") == reactor:
            reactions.remove(rec); removed = True; break
    if not removed:
        reactions.append({"emoji": emoji, "user": reactor})
    c.execute("UPDATE messages SET reactions = ? WHERE id = ?", (json.dumps(reactions), msg_id))
    conn.commit(); conn.close(); return True, None

# --- Socket user registration and presence tracking ---

def emit_to_user(username, event, data):
    """Emit a socket event directly to a specific user if connected."""
    try:
        sid = USER_SID.get(username)
        if sid:
            socketio.emit(event, data, to=sid)
    except Exception as e:
        current_app.logger.exception(f"emit_to_user({username}, {event}) failed: {e}")


@socketio.on('register_socket')  # client should call this after connecting
def handle_register_socket(data):
    """Register the current socket connection with the provided username."""
    try:
        username = (data.get('username') if isinstance(data, dict) else str(data)).strip()
        sid = request.sid

        if not username:
            socketio.emit('register_ack', {'ok': False, 'error': 'missing_username'}, to=sid)
            return

        # Save mapping
        USER_SID[username] = sid

        # Join user-specific room (optional)
        try:
            join_room(username)
        except Exception:
            pass

        # Touch presence if function exists
        try:
            if 'touch_user_presence' in globals() and callable(globals()['touch_user_presence']):
                touch_user_presence(username, online=True)
        except Exception:
            current_app.logger.exception("touch_user_presence failed on register")

        # Acknowledge registration
        socketio.emit('register_ack', {'ok': True, 'username': username}, to=sid)
        current_app.logger.info(f"✅ Socket registered for user: {username}")

    except Exception as e:
        current_app.logger.exception(f"handle_register_socket failed: {e}")
        try:
            socketio.emit('register_ack', {'ok': False, 'error': 'server_error'}, to=request.sid)
        except Exception:
            pass


@socketio.on('disconnect')
def handle_disconnect():
    """Cleanup socket mappings and presence on disconnect."""
    try:
        sid = request.sid
        disconnected_user = None

        # Remove user if SID matches
        for username, stored_sid in list(USER_SID.items()):
            if stored_sid == sid:
                USER_SID.pop(username, None)
                disconnected_user = username
                break

        # Leave room and mark offline
        if disconnected_user:
            try:
                leave_room(disconnected_user)
            except Exception:
                pass

            try:
                if 'touch_user_presence' in globals() and callable(globals()['touch_user_presence']):
                    touch_user_presence(disconnected_user, online=False)
            except Exception:
                current_app.logger.exception("touch_user_presence failed on disconnect")

            current_app.logger.info(f"❌ User disconnected: {disconnected_user}")
        else:
            current_app.logger.debug(f"Socket disconnected (unmapped sid: {sid})")

    except Exception as e:
        current_app.logger.exception(f"handle_disconnect failed: {e}")

@socketio.on('request_contacts_sync')
def on_request_contacts_sync(data):
    username = data.get('username') or flask_session.get('username')
    if not username: return
    contacts = list_contacts_for(username)
    emit('contacts_list', {'contacts': contacts})

# Caller invites callee
@socketio.on('call:invite')
def on_call_invite(data):
    # data: { to: 'otherUser', from: 'caller', is_video: true, call_id: 'uuid' }
    to = data.get('to'); caller = data.get('from'); call_id = data.get('call_id')
    if not (to and caller and call_id):
        return
    CALL_INVITES[call_id] = {'caller': caller, 'callee': to, 'is_video': bool(data.get('is_video')), 'status': 'ringing', 'created': int(time.time())}
    # notify callee
    emit_to_user(to, 'call:incoming', {'call_id': call_id, 'from': caller, 'is_video': bool(data.get('is_video'))})
    # optionally ack to caller
    emit('call:invite_ack', {'ok': True, 'call_id': call_id}, to=request.sid)
    # persist call log
    save_call(call_id, caller, to, bool(data.get('is_video')), status='ringing')

@socketio.on('call:accept')
def on_call_accept_colon(data):
    call_id = data.get('call_id')
    info = CALL_INVITES.get(call_id)
    if not info:
        emit('call:error', {'error': 'no_call'}, to=request.sid)
        return

    info['status'] = 'accepted'
    update_call_started(call_id)

    sid_caller = USER_SID.get(info.get('caller'))
    sid_callee = USER_SID.get(info.get('callee'))

    meet_url = f"{MEET_BASE_URL.rstrip('/')}/join?call_id={call_id}"

    if sid_caller:
        emit('open_meet', {'url': meet_url}, room=sid_caller)
        emit('call:accepted', {'call_id': call_id, 'from': info.get('callee')}, room=sid_caller)

    if sid_callee:
        emit('open_meet', {'url': meet_url}, room=sid_callee)

# Callee/Caller reject/hangup
@socketio.on('call:hangup')
def on_call_hangup(data):
    call_id = data.get('call_id'); who = data.get('from')
    c = CALL_INVITES.pop(call_id, None)
    if c:
        emit_to_user(c['caller'], 'call:ended', {'call_id': call_id, 'by': who})
        emit_to_user(c['callee'], 'call:ended', {'call_id': call_id, 'by': who})
        update_call_ended(call_id)

# Signaling: forward SDP offer/answer & ICE candidates
@socketio.on('call:offer')
def on_call_offer(data):
    # data: { call_id, from, to, sdp }
    to = data.get('to'); sdp = data.get('sdp'); caller = data.get('from')
    emit_to_user(to, 'call:offer', {'from': caller, 'sdp': sdp, 'call_id': data.get('call_id')})

@socketio.on('call:answer')
def on_call_answer(data):
    to = data.get('to'); sdp = data.get('sdp'); sender = data.get('from')
    emit_to_user(to, 'call:answer', {'from': sender, 'sdp': sdp, 'call_id': data.get('call_id')})

@socketio.on('call:candidate')
def on_call_candidate(data):
    to = data.get('to'); candidate = data.get('candidate'); sender = data.get('from')
    emit_to_user(to, 'call:candidate', {'from': sender, 'candidate': candidate, 'call_id': data.get('call_id')})

# Optional in-call signals: mute/unmute, hold, switch-camera
@socketio.on('call:signal')
def on_call_signal(data):
    to = data.get('to'); payload = data.get('payload'); emit_to_user(to, 'call:signal', payload)

# --- Add: return list of currently online users to the requesting socket
@socketio.on('get_online_users')
def on_get_online_users(data=None):
    """
    Client asks for the current online users.
    Emits 'online_users' back only to the requesting client with the
    list of usernames (strings).
    """
    try:
        users = list(USER_SID.keys())
        # send only to caller
        emit('online_users', {'users': users}, to=request.sid)
    except Exception as e:
        app.logger.exception('get_online_users error')
        emit('online_users', {'users': []}, to=request.sid)

# call logs
def save_call(call_id, caller, callee, is_video, status="ringing"):
    conn = db_conn(); c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO calls (id, caller, callee, is_video, started_at, ended_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (call_id, caller, callee, 1 if is_video else 0, int(time.time()), None, status))
    conn.commit(); conn.close()

def update_call_started(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET started_at = ?, status = ? WHERE id = ?", (int(time.time()), "active", call_id))
    conn.commit(); conn.close()

def update_call_ended(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET ended_at = ?, status = ? WHERE id = ?", (int(time.time()), "ended", call_id))
    conn.commit(); conn.close()

def fetch_call_log_by_id(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, caller, callee, is_video, started_at, ended_at, status FROM calls WHERE id = ? LIMIT 1", (call_id,))
    r = c.fetchone(); conn.close()
    if r:
        return {"id": r[0], "caller": r[1], "callee": r[2], "is_video": bool(r[3]), "started_at": r[4], "ended_at": r[5], "status": r[6]}
    return None

def next_message_id():
    return len(messages_store) + 1

# --------- crypto for shared passkey ----------
PBKDF2_ITER = 200_000
SALT_BYTES = 16
HASH_LEN = 32

def hash_pass(passphrase: str, salt: bytes = None):
    if salt is None: salt = secrets.token_bytes(SALT_BYTES)
    if isinstance(passphrase, str): passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=HASH_LEN)
    return salt, dk

def verify_pass(passphrase: str, salt: bytes, expected_hash: bytes) -> bool:
    if isinstance(salt, memoryview): salt = bytes(salt)
    if isinstance(expected_hash, memoryview): expected_hash = bytes(expected_hash)
    if salt is None or expected_hash is None: return False
    if isinstance(passphrase, str): passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=len(expected_hash))
    return hmac.compare_digest(dk, expected_hash)

# ---------- presence & runtime state ----------
LAST_SEEN = {}
USER_SID = {}      # username -> sid
CALL_INVITES = {}  # call_id -> info
TYPING_USERS = set()

def touch_user_presence(username):
    if not username: return
    LAST_SEEN[username] = int(time.time())

# ---------- Avatar generation (WhatsApp-like initials SVG) ----------
def initials_and_color(name):
    nm = (name or "").strip()
    initials = ""
    parts = nm.split()
    if len(parts) == 0:
        initials = "?"
    elif len(parts) == 1:
        initials = parts[0][:2].upper()
    else:
        initials = (parts[0][0] + parts[-1][0]).upper()
    h = hashlib.sha256(nm.encode("utf-8")).digest()
    r,g,b = h[0], h[1], h[2]
    return initials, f"rgb({r},{g},{b})"

@app.route("/avatar/<name>")
def avatar_svg(name):
    try:
        name = name.replace("/", " ").strip()
        initials, color = initials_and_color(name)
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240">
  <rect width="100%" height="100%" fill="{color}" rx="120" />
  <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,Segoe UI,Roboto" font-size="96" fill="#fff">{initials}</text>
</svg>'''
        return app.response_class(svg, mimetype='image/svg+xml')
    except Exception:
        abort(404)

# ---------- Helpers for listing stickers/gifs ----------
def list_static_folder(sub):
    folder = os.path.join(app.static_folder, sub)
    if not os.path.isdir(folder): return []
    out=[]
    for fn in sorted(os.listdir(folder)):
        p = os.path.join(folder, fn)
        if os.path.isfile(p):
            ext = fn.rsplit(".",1)[-1].lower()
            if ext:
                out.append(url_for('static', filename=f"{sub}/{fn}"))
    return out

# ---------- Generated stickers/gifs endpoints ----------
@app.route("/generated_stickers")
def generated_stickers():
    # Return a list of inline SVG data-URLs representing avatar-style stickers and a few emoji stickers.
    names = ["You","Me","AA","Pro","Gamer","Tommy","Alex","Sam"]
    outs = []
    for n in names:
        init, color = initials_and_color(n)
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240"><rect width="100%" height="100%" fill="{color}" rx="40"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,Segoe UI,Roboto" font-size="72" fill="#fff">{init}</text></svg>'
        data = "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        outs.append(data)
    # A couple of emoji-based sticker placeholders
    emoji_stickers = ["😀","🔥","🏁","🚗","🎮","💥"]
    for e in emoji_stickers:
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240"><rect width="100%" height="100%" fill="#fff" rx="40"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="Segoe UI Emoji, Noto Color Emoji, Apple Color Emoji" font-size="96" >{e}</text></svg>'
        data = "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        outs.append(data)
    return jsonify(outs)

@app.route("/generated_gifs")
def generated_gifs():
    # Just return static/gifs plus generated placeholders if exist
    gifs = list_static_folder("gifs")
    return jsonify(gifs)

# new endpoints for lists used by the modern UI
@app.route("/stickers_list")
def stickers_list():
    return jsonify(list_static_folder("stickers"))

@app.route("/gifs_list")
def gifs_list():
    return jsonify(list_static_folder("gifs"))

# ---------- Avatar creation & caching (DiceBear) ----------
def dicebear_avatar_url(style, seed, params):
    # style e.g. 'adventurer' ; params is dict of query params
    qs = "&".join([f"{k}={requests.utils.quote(str(v))}" for k,v in params.items() if v is not None and v != ""])
    return f"https://avatars.dicebear.com/api/{style}/{requests.utils.quote(seed)}.svg?{qs}"

@app.route("/avatar_create")
def avatar_create_page():
    # small page with controls to create and preview DiceBear avatars; will POST to /avatar_save
    username = flask_session.get('username')
    if not username:
        return redirect(url_for('index'))
    return render_template_string(AVATAR_CREATE_HTML, username=username)

@app.route("/avatar_save", methods=["POST"])
def avatar_save():
    # Save a DiceBear avatar (server fetch and cache) and update user's avatar path
    username = flask_session.get('username')
    if not username:
        return "not signed in", 401
    body = request.get_json() or {}
    seed = body.get("seed") or username
    style = body.get("style") or "adventurer"
    params = body.get("params") or {}
    try:
        url = dicebear_avatar_url(style, seed, params)
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return "could not fetch avatar", 500
        svg = r.content
        fn = f"avatars/{secure_filename(username)}_{secrets.token_hex(6)}.svg"
        path = os.path.join(app.static_folder, fn)
        with open(path, "wb") as f:
            f.write(svg)
        avatar_url = url_for('static', filename=fn)
        # update user avatar in DB
        conn = db_conn(); c = conn.cursor()
        c.execute("UPDATE users SET avatar = ? WHERE name = ?", (avatar_url, username))
        conn.commit(); conn.close()
        return jsonify({"status":"ok","avatar":avatar_url})
    except Exception as e:
        return f"error: {e}", 500

AUDIO_CALL_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Audio Call — InfinityChatter</title>
  <link rel="icon" href="/static/favicon.png" type="image/png">
  <link rel="apple-touch-icon" href="/static/favicon.png">
  <link rel="shortcut icon" href="/static/favicon.png">
  <link rel="manifest" href="/static/manifest.json">
  <meta name="theme-color" content="#0f172a">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="InfinityChatter">
  <meta name="mobile-web-app-capable" content="yes">
  <style>
    :root{--bg:#0b1320;--panel:#0f1b2b;--accent:#25D366;--muted:#b6c2cf}
    html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial}
    body{background:linear-gradient(180deg,#08121b 0%, #071018 100%);color:#e6eef6;display:flex;align-items:center;justify-content:center}
    .call-card{width:100%;max-width:420px;background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0.01));border-radius:14px;padding:20px;box-shadow:0 8px 24px rgba(2,6,23,0.6)}
    .avatar{width:120px;height:120px;border-radius:50%;background:#203444;display:flex;align-items:center;justify-content:center;font-size:42px;margin:0 auto 16px}
    .name{font-size:20px;text-align:center;margin-bottom:6px}
    .status{font-size:13px;text-align:center;color:var(--muted);margin-bottom:18px}
    .controls{display:flex;gap:12px;justify-content:center}
    .btn{background:rgba(255,255,255,0.04);border:0;padding:12px;border-radius:50%;width:56px;height:56px;display:inline-flex;align-items:center;justify-content:center;cursor:pointer}
    .btn.end{background:#e53935;color:#fff;width:68px;height:68px}
    .small{font-size:12px;color:var(--muted);text-align:center;margin-top:12px}
    .hidden{display:none}
    .top-actions{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
    .muted-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-left:6px}
  </style>
</head>
<body>
  <div class="call-card" role="main">
    <div class="top-actions">
      <div style="display:flex;gap:10px;align-items:center">
        <div style="width:10px;height:10px;border-radius:50%;background:#33cc33" aria-hidden></div>
        <div style="font-weight:600">Audio Call</div>
      </div>
      <div style="font-size:12px;color:var(--muted)">Asphalt Legends</div>
    </div>

    <div id="avatar" class="avatar" aria-hidden>📞</div>
    <div id="peerName" class="name">Connecting…</div>
    <div id="callState" class="status">Preparing call</div>

    <div class="controls">
      <button id="muteBtn" class="btn" title="Mute/unmute microphone">🔇</button>
      <button id="endBtn" class="btn end" title="End call">⛔</button>
      <button id="speakerBtn" class="btn" title="Toggle speaker output">🔊</button>
    </div>

    <div class="small" id="timeCounter">00:00</div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.7.2/dist/socket.io.min.js"></script>
  <script>
    // Template-provided username (available via Flask flask_session) - Jinja will replace it.
    const MYNAME = String({{ (flask_session.get('username')|tojson) or '""' }}).replace(/^"|"$/g, '');

    // Read parameters from URL: call_id, role (caller|callee), peer (the other username)
    const params = new URLSearchParams(location.search);
    const CALL_ID = params.get('call_id');
    const PEER = params.get('peer') || params.get('to') || params.get('from') || '';
    const IS_VIDEO = (params.get('is_video') === '1' || params.get('is_video') === 'true');

    const socket = io();
    socket.on('open_audio_page', data => {
      if (data.url) window.location.href = data.url;
    });

    // When the callee accepts and is told to open the video call page
    socket.on("open_meet", (data) => {
      if (!data || !data.url) return;
      const appUrl = data.url.replace("https://meet.google.com/new", "googlemeet://meet.google.com/new");
      // Try to open the app first
      window.location.href = appUrl;
      // Fallback to web after 1–1.5 s
      setTimeout(() => {
        window.open(data.url, "_blank", "noopener,noreferrer");
      }, 1500);
    });

    if (MYNAME) socket.emit('register_socket', {username: MYNAME});

    let pc = null;
    let localStream = null;
    let startTime = null;
    let timerInterval = null;

    const peerNameEl = document.getElementById('peerName');
    const callStateEl = document.getElementById('callState');
    const avatarEl = document.getElementById('avatar');
    const timeEl = document.getElementById('timeCounter');

    peerNameEl.textContent = PEER || 'Unknown';

    function formatTime(s){const m=Math.floor(s/60);const ss=s%60;return String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0')}
    function startTimer(){startTime = Date.now(); timerInterval = setInterval(()=>{timeEl.textContent = formatTime(Math.floor((Date.now()-startTime)/1000))},1000)}
    function stopTimer(){if(timerInterval){clearInterval(timerInterval);timerInterval=null}}

    function setState(text){callStateEl.textContent = text}

    // Call this when caller clicks "Video Call" on a user
    function startMeetCall(selectedUser) {
      socket.emit("call_outgoing", { to: selectedUser, from: MYNAME, isVideo: true });
    }

    async function ensureLocalStream(){
      if (localStream) return localStream;
      try{
        localStream = await navigator.mediaDevices.getUserMedia({audio:true});
        return localStream;
      }catch(e){console.error('getUserMedia failed', e); setState('Microphone access denied'); throw e}
    }

    function createPeerConnection(){
      pc = new RTCPeerConnection();
      pc.onicecandidate = (ev)=>{ if(ev.candidate){ socket.emit('call:candidate', {to: PEER, from: MYNAME, candidate: ev.candidate, call_id: CALL_ID}) } };
      pc.ontrack = (ev)=>{ // single remote audio track
        const [remoteStream] = ev.streams;
        // play remote audio element
        let audio = document.getElementById('remoteAudio');
        if(!audio){ audio = document.createElement('audio'); audio.id='remoteAudio'; audio.autoplay=true; audio.style.display='none'; document.body.appendChild(audio) }
        audio.srcObject = remoteStream;
      };
      return pc;
    }

    socket.on("open_meet_creator", ({ call_id }) => {
      // 1) Open Meet (web/app) in a new tab so caller can immediately create a meeting
      window.open("https://meet.google.com/new", "_blank", "noopener,noreferrer");

      // 2) Show a small share input UI for the caller to paste the meeting link and share
      if (document.getElementById('meet-share-box')) return; // avoid duplicates

      const box = document.createElement("div");
      box.id = "meet-share-box";
      box.style.cssText = "position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#0f1720;color:#fff;padding:12px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,0.6);z-index:9999;display:flex;gap:8px;align-items:center;";
      box.innerHTML = `
        <input id="meetLinkInput" placeholder="Paste Meet link here (Ctrl+V)" style="padding:8px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);width:320px;" />
        <button id="shareMeetBtn" style="background:#25D366;color:#fff;border:0;padding:8px 10px;border-radius:6px;cursor:pointer;">Share</button>
        <button id="cancelShareBtn" style="background:#fff;color:#000;border:0;padding:8px 10px;border-radius:6px;cursor:pointer;">Cancel</button>
      `;
      document.body.appendChild(box);

      document.getElementById("shareMeetBtn").onclick = () => {
        const link = document.getElementById("meetLinkInput").value.trim();
        if (!link) { alert("Please paste a Meet link first."); return; }
        socket.emit("share_meet_invite", { call_id, url: link });
        box.remove();
      };

      document.getElementById("cancelShareBtn").onclick = () => { box.remove(); };
    });

    socket.on("incoming_meet_invite", (data) => {
      // data: { from, call_id, url? }
      const { from, call_id, url } = data;
      // create a pretty banner
      const banner = document.createElement("div");
      banner.className = "meet-invite-banner";
      banner.style.cssText = "position:fixed;top:18px;left:50%;transform:translateX(-50%);background:linear-gradient(180deg,#0b1320,#071021);color:#fff;padding:14px 18px;border-radius:12px;box-shadow:0 10px 30px rgba(2,6,23,0.6);z-index:9999;display:flex;gap:12px;align-items:center;";
      banner.innerHTML = `
        <div style="font-weight:700;margin-right:8px;">${from}</div>
        <div style="opacity:0.9;margin-right:12px;">is inviting you to a Google Meet</div>
        <div style="display:flex;gap:8px;">
          <button id="acceptMeetBtn" style="background:#25D366;border:0;padding:8px 10px;border-radius:8px;cursor:pointer;">Accept</button>
          <button id="declineMeetBtn" style="background:#ff3b30;border:0;padding:8px 10px;border-radius:8px;cursor:pointer;">Decline</button>
        </div>
      `;
      document.body.appendChild(banner);

      document.getElementById("acceptMeetBtn").onclick = () => {
        banner.remove();
        // If server forwarded url, use it; otherwise open /new and then server/caller need to coordinate.
        const meetUrl = url || "https://meet.google.com/new";
        // Send accept to server with the meet URL so both open same link
        socket.emit("meet_accept", { call_id, url: meetUrl });

        // Try open app deep-link first on mobile; fallback to web after a short timeout
        try {
          window.location.href = meetUrl.replace("https://meet.google.com", "googlemeet://meet.google.com");
          setTimeout(() => { window.open(meetUrl, "_blank", "noopener,noreferrer"); }, 1200);
        } catch (e) {
          window.open(meetUrl, "_blank", "noopener,noreferrer");
        }
      };

      document.getElementById("declineMeetBtn").onclick = () => {
        banner.remove();
        socket.emit("meet_decline", { call_id });
      };
    });

    socket.on("open_meet", (data) => {
      if (!data || !data.url) return;
      // Try app deep link first for mobile; fallback to web version
      const webUrl = data.url;
      const appUrl = webUrl.replace("https://meet.google.com", "googlemeet://meet.google.com");
      try {
        // Try opening app (on Android this will open the native app if installed)
        window.location.href = appUrl;
        setTimeout(() => { window.open(webUrl, "_blank", "noopener,noreferrer"); }, 1200);
      } catch (e) {
        window.open(webUrl, "_blank", "noopener,noreferrer");
      }
    });

    socket.on("meet_declined", ({ call_id }) => {
      // show a small toast for caller
      const t = document.createElement("div");
      t.textContent = "Invite declined";
      t.style.cssText = "position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#111;padding:8px 12px;color:#fff;border-radius:8px;z-index:9999;";
      document.body.appendChild(t);
      setTimeout(()=>t.remove(), 3000);
    });

  </script>
</body>
</html>
"""

@app.route('/audio_call')
def audio_call_page():
    return render_template_string(AUDIO_CALL_HTML)

@app.route('/video_call')
def video_call_page():
    return render_template_string(VIDEO_CALL_HTML)

# ---------- Templates ----------
# AVATAR CREATE page HTML (separate smaller page)
AVATAR_CREATE_HTML = r'''<!-- AVATAR_CREATE_HTML (updated) -->
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Create Avatar - InfinityChatter</title>
<link rel="icon" href="/static/favicon.png" type="image/png">
<link rel="apple-touch-icon" href="/static/favicon.png">
<link rel="shortcut icon" href="/static/favicon.png">
<link rel="manifest" href="/static/manifest.json">
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="InfinityChatter">
<meta name="mobile-web-app-capable" content="yes">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; background: #f8fafc; padding:18px;}
  .preview{ width:180px; height:180px; border-radius:50%; overflow:hidden; display:inline-block; background:#fff; box-shadow:0 6px 20px rgba(2,6,23,0.06); border:6px solid rgba(255,255,255,0.8); }
  .preview img{ width:100%; height:100%; object-fit:cover; display:block; }
  .tile{ cursor:pointer; border-radius:8px; padding:6px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); display:flex; align-items:center; justify-content:center; }
  .tile.selected{ outline:3px solid #6366f1; }
  .controls{ display:flex; gap:8px; flex-wrap:wrap; }
  label.switch { display:inline-flex; align-items:center; gap:8px; cursor:pointer; user-select:none; }
</style>
</head>
<body>
  <div class="max-w-3xl mx-auto">
    <h1 class="text-2xl font-bold mb-3">Create avatar — DiceBear (WhatsApp-style approx)</h1>
    <div class="flex gap-6">
      <div>
        <div class="preview mb-3" id="avatarPreview"><img id="avatarImg" src="/avatar/{{ username }}" alt="avatar preview" /></div>
        <div style="display:flex;gap:8px;">
          <button id="saveBtn" class="px-3 py-2 rounded bg-indigo-600 text-white">Save avatar</button>
          <a href="/chat" class="px-3 py-2 rounded bg-gray-200">Back to chat</a>
        </div>
      </div>
      <div style="flex:1;">
        <div class="mb-2">
          <label class="text-sm font-semibold">Style</label>
          <select id="styleSelect" class="p-2 border rounded w-full">
            <option value="adventurer">adventurer</option>
            <option value="avataaars">avataaars</option>
            <option value="bottts">bottts</option>
            <option value="pixel-art">pixel-art</option>
          </select>
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Seed (name or random)</label>
          <input id="seedInput" class="p-2 border rounded w-full" placeholder="seed (e.g. your name)" />
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Quick presets (click)</label>
          <div class="grid grid-cols-3 gap-2 mt-2" id="presetGrid"></div>
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Controls</label>
          <div class="controls mt-2">
            <div><label class="text-xs">Skin tone</label>
              <select id="skinTone" class="p-2 border rounded">
                <option value="">auto</option>
                <option value="T1">light</option>
                <option value="T2">fair</option>
                <option value="T3">tan</option>
                <option value="T4">brown</option>
                <option value="T5">dark</option>
              </select>
            </div>
            <div><label class="text-xs">Hair</label>
              <select id="hair" class="p-2 border rounded">
                <option value="">auto</option><option value="short">short</option><option value="long">long</option><option value="curly">curly</option><option value="bald">bald</option>
              </select>
            </div>
            <div><label class="text-xs">Eyes</label>
              <select id="eyes" class="p-2 border rounded"><option value="">auto</option><option value="smile">smile</option><option value="round">round</option><option value="squint">squint</option></select>
            </div>
            <div><label class="text-xs">Mouth</label>
              <select id="mouth" class="p-2 border rounded"><option value="">auto</option><option value="smile">smile</option><option value="serious">serious</option><option value="laugh">laugh</option></select>
            </div>
            <div><label class="text-xs">Accessory</label>
              <select id="accessory" class="p-2 border rounded"><option value="">none</option><option value="glasses">glasses</option><option value="earrings">earrings</option><option value="cap">cap</option></select>
            </div>
            <div style="display:flex;align-items:center;">
              <label class="switch"><input id="whatsappLike" type="checkbox" /> WhatsApp-style (approx)</label>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

<script>
function el(id){ return document.getElementById(id); }
const username = "{{ username }}";

// build params; we map UI controls into query params sent to proxy.
// DiceBear will accept unknown params (they are ignored if not supported by the chosen sprite), but we use common param names.
function buildParams(){
  const p = {};
  if(el('skinTone').value) p['skin[]'] = el('skinTone').value;
  if(el('hair').value) p['hair'] = el('hair').value;
  if(el('eyes').value) p['eyes'] = el('eyes').value;
  if(el('mouth').value) p['mouth'] = el('mouth').value;
  if(el('accessory').value) p['accessories[]'] = el('accessory').value;
  // whatsapp-like toggle forwards as a flag; proxy will apply a recommended set of params for that style.
  if(el('whatsappLike').checked) p['whatsapp_like'] = '1';
  return p;
}

function updatePreview(){
  const style = el('styleSelect').value;
  const seed = (el('seedInput').value || username || 'user').trim();
  const params = buildParams();
  const qs = new URLSearchParams(params).toString();
  // proxy_dicebear will fetch and return the final SVG (CORS-safe).
  const url = `/proxy_dicebear?style=${encodeURIComponent(style)}&seed=${encodeURIComponent(seed)}${qs ? '&' + qs : ''}`;
  el('avatarImg').src = url + '&_=' + Date.now(); // cache-bust
}

// wire events
el('styleSelect').addEventListener('change', updatePreview);
el('seedInput').addEventListener('input', updatePreview);
['hair','eyes','mouth','accessory','skinTone','whatsappLike'].forEach(id => {
  el(id).addEventListener('change', updatePreview);
});

// presets (random seeds)
const presetGrid = el('presetGrid');
for(let i=0;i<9;i++){
  const seed = 'user' + Math.random().toString(36).slice(2,8);
  const d = document.createElement('div'); d.className='tile'; d.textContent = seed;
  d.onclick = ()=>{
    el('seedInput').value = seed;
    updatePreview();
    document.querySelectorAll('.tile').forEach(t=> t.classList.remove('selected'));
    d.classList.add('selected');
  };
  presetGrid.appendChild(d);
}

el('saveBtn').addEventListener('click', async ()=>{
  const style = el('styleSelect').value;
  const seed = (el('seedInput').value || username || 'user').trim();
  const params = buildParams();
  const res = await fetch('/avatar_save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ style, seed, params })});
  if(!res.ok){ alert('Save failed: '+await res.text()); return; }
  const j=await res.json(); if(j.avatar){ alert('Saved avatar'); location.href = '/chat'; }
});

// initial preview
updatePreview();
</script>
</body>
</html>
'''

from urllib.parse import quote_plus, urlencode
import requests
from flask import request, current_app, Response

def dicebear_avatar_url(style, seed, params):
    """
    Build DiceBear API URL (SVG). When params contains 'whatsapp_like' we apply
    a recommended set of parameters to approximate WhatsApp's cartoony avatar.
    Note: this is an approximation — official WhatsApp avatars are Meta's product.
    """
    # Remove control-only params
    params = dict(params)  # copy
    whatsapp_flag = params.pop('whatsapp_like', None)

    # Basic normalization: prefer avataaars/adventurer for cartoony faces
    if whatsapp_flag:
        # prefer 'adventurer' which gives good face/body shapes; 'avataaars' is also good
        style = style if style in ('adventurer','avataaars') else 'adventurer'
        # suggested WhatsApp-like defaults (approximate)
        defaults = {
            # common, general options — DiceBear will ignore unknown names for some styles,
            # but these help push toward a round, cartoony portrait.
            'backgroundType': 'circle',    # request circular background when supported
            'backgroundColor[]': 'transparent',
            'radius': '50',                # roundedness if supported
            # character options (names vary by sprite; proxy forwards them)
            'hair': params.get('hair','short'),
            'eyes': params.get('eyes','smile'),
            'mouth': params.get('mouth','smile'),
            'accessories[]': params.get('accessories[]', params.get('accessories','')),
            # skin tone shorthands if provided
            'skin[]': params.get('skin[]', params.get('skin','')),
        }
        # merge defaults but keep explicit params the user supplied
        for k,v in defaults.items():
            if k not in params or not params[k]:
                params[k] = v

    # Build base URL: DiceBear 9.x API returns SVG for /{style}/svg
    base = f"https://api.dicebear.com/9.x/{quote_plus(style)}/svg"
    # ensure seed is included
    qs = {'seed': seed}
    # add other params (flatten lists for arrays)
    for k, v in params.items():
        if v is None or v == '':
            continue
        # DiceBear expects repeated params for array-like fields; here we accept comma or array strings too.
        qs[k] = v

    url = base + '?' + urlencode(qs, doseq=True)
    return url

@app.route("/proxy_dicebear")
def proxy_dicebear():
    style = request.args.get('style','adventurer')
    seed = request.args.get('seed','user')
    # capture all query params except style/seed (so we can forward arbitrary controls)
    params = {k: request.args.get(k) for k in request.args.keys() if k not in ('style','seed')}
    try:
        url = dicebear_avatar_url(style, seed, params)
        # fetch svg from DiceBear
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            current_app.logger.error("DiceBear returned status %s for url %s", r.status_code, url)
            return "error fetching avatar", 502
        # return SVG (CORS safe because it comes from our server)
        return Response(r.content, mimetype='image/svg+xml')
    except Exception as e:
        current_app.logger.exception("proxy_dicebear error")
        return f"error: {e}", 500

@app.route('/inbox')
def inbox_page():
    return send_from_directory('static', 'Main_page.html')

@app.route('/calls')
def calls_page():
    return send_from_directory('static', 'Call_Page.html')

@app.route('/Updates')
def Updates_page():
    return send_from_directory('static', 'Profile_Page.html')

@app.route('/settings')
def settings_page():
    return send_from_directory('static', 'Settings_Page.html')

# ---------- END contacts/inbox addition ----------
LOGIN_HTML = r'''<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>InfinityChatter — Login</title>
  <link rel="icon" href="/static/favicon.png" type="image/png">
  <link rel="apple-touch-icon" href="/static/favicon.png">
  <link rel="shortcut icon" href="/static/favicon.png">
  <link rel="manifest" href="/static/manifest.json">
  <meta name="theme-color" content="#0f172a">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="InfinityChatter">
  <meta name="mobile-web-app-capable" content="yes">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background:linear-gradient(135deg,#eff6ff,#f5f3ff); display:flex; align-items:center; justify-content:center; height:100vh; font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial; }
    .card { width:100%; max-width:420px; background:#fff; border-radius:18px; padding:28px; box-shadow:0 10px 30px rgba(2,6,23,0.08); text-align:center; }
    .avatar-container{ margin-bottom:18px; display:flex; justify-content:center; }
    .avatar-circle{ width:96px; height:96px; border-radius:50%; background:#f1f5f9; display:flex; align-items:center; justify-content:center; border:3px solid #e2e8f0; cursor:pointer; overflow:hidden; }
    .avatar-circle img{ width:100%; height:100%; object-fit:cover; }
    input[type=text], input[type=tel] { width:100%; padding:10px 12px; border-radius:10px; border:1px solid #e6eef6; margin-top:10px; font-size:1rem; }
    button { margin-top:14px; width:100%; padding:10px; border-radius:10px; border:none; background:#2563eb; color:#fff; font-weight:700; }
  </style>
</head>
<body>
  <div class="card">
    <h2 style="font-weight:800;font-size:20px;margin-bottom:12px;">InfinityChatter</h2>
    <div class="avatar-container">
      <label for="avatarInput" class="avatar-circle" id="avatarCircle"><span style="font-size:28px;">📷</span></label>
      <input id="avatarInput" type="file" accept="image/*" style="display:none" />
    </div>
    <input id="nameInput" type="text" placeholder="Your name" />
    <input id="mobileInput" type="tel" placeholder="Mobile number" />
    <button id="saveBtn">Continue</button>
  </div>

<script>
  // If profile exists already, go to inbox
  const existingProfile = localStorage.getItem('infinity_profile');
  if(existingProfile){
    // small delay to show smooth redirect for UX
    setTimeout(()=> window.location.href = '/inbox', 200);
  }

  const avatarInput = document.getElementById('avatarInput');
  const avatarCircle = document.getElementById('avatarCircle');
  let avatarData = null;

  avatarCircle.addEventListener('click', ()=> avatarInput.click());
  avatarInput.addEventListener('change', (e)=>{
    const file = e.target.files && e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = ()=> {
      avatarData = reader.result;
      avatarCircle.innerHTML = '<img src="'+avatarData+'" alt="avatar">';
    };
    reader.readAsDataURL(file);
  });

  document.getElementById('saveBtn').addEventListener('click', ()=>{
    const name = document.getElementById('nameInput').value.trim();
    const mobile = document.getElementById('mobileInput').value.trim();
    if(!name){ alert('Please enter your name'); return; }
    if(!mobile){ alert('Please enter your mobile number'); return; }
    const profile = { name, mobile, avatar: avatarData };
    localStorage.setItem('infinity_profile', JSON.stringify(profile));
    window.location.href = '/inbox';
  });
</script>
</body>
</html>
'''

# --- AVATAR page (full-featured generator using DiceBear HTTP API) ---
AVATAR_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Create Avatar — InfinityChatter</title>
<link rel="icon" href="/static/favicon.png" type="image/png">
<link rel="apple-touch-icon" href="/static/favicon.png">
<link rel="shortcut icon" href="/static/favicon.png">
<link rel="manifest" href="/static/manifest.json">
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="InfinityChatter">
<meta name="mobile-web-app-capable" content="yes">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{ font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial; padding:12px; background:#f8fafc; }
  .tile { display:inline-flex; gap:8px; padding:8px; border-radius:8px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); cursor:pointer; text-align:center; flex-direction:column; width:92px; align-items:center; margin:6px; }
  #avatarPreview { width:240px; height:240px; border-radius:24px; background:#fff; display:flex; align-items:center; justify-content:center; box-shadow:0 10px 30px rgba(0,0,0,0.06); overflow:hidden; }
  #cameraPreview video{ width:320px; border-radius:12px; }
</style>
</head><body>
  <h2 class="text-xl font-bold mb-3">Create Avatar</h2>
  <p class="text-sm text-gray-600">You can either capture a photo (recommended suggestions) or manually tune the avatar controls (hair, eyes, accessories). This uses DiceBear's HTTP API for generation.</p>

  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-4">
    <div>
      <div id="avatarPreview" class="mb-3">Preview</div>
      <div class="flex gap-2">
        <button id="downloadAvatar" class="px-3 py-2 bg-indigo-600 text-white rounded">Download</button>
        <button id="saveAvatar" class="px-3 py-2 bg-green-600 text-white rounded">Save to profile</button>
      </div>
      <div class="mt-3">
        <label class="text-sm font-semibold">Seed (randomize to get thousands of combinations)</label>
        <div class="flex gap-2 mt-2"><input id="seedInput" class="p-2 border rounded flex-1" placeholder="seed or leave empty for random"/><button id="randomSeed" class="px-3 py-2 bg-gray-200 rounded">Random</button></div>
      </div>
    </div>

    <div>
      <div class="mb-2"><strong>Capture / Upload Photo (optional)</strong></div>
      <div id="cameraPreview" class="mb-2"></div>
      <div class="flex gap-2">
        <button id="startCamera" class="px-3 py-2 bg-gray-100 rounded">Start Camera</button>
        <button id="takePhoto" class="px-3 py-2 bg-indigo-600 text-white rounded">Capture</button>
        <button id="uploadPhoto" class="px-3 py-2 bg-gray-100 rounded">Upload Photo</button>
      </div>
      <p class="text-xs text-gray-500 mt-2">If you capture/upload a photo we'll hash it and use the hash as the DiceBear seed to create recommended avatars (simple deterministic approach).</p>
    </div>

    <div>
      <div class="mb-2"><strong>Controls</strong></div>
      <div id="controls" class="grid grid-cols-1 gap-2">
        <label class="text-xs">Style</label>
        <select id="styleSelect" class="p-2 border rounded">
          <option value="adventurer">Adventurer</option>
          <option value="avataaars">Avataaars</option>
          <option value="big-smile">Big Smile</option>
          <option value="pixel-art">Pixel Art</option>
        </select>

        <label class="text-xs mt-2">Hair</label>
        <div id="hairTiles" class="flex flex-wrap"></div>

        <label class="text-xs mt-2">Eyes</label>
        <div id="eyesTiles" class="flex flex-wrap"></div>

        <label class="text-xs mt-2">Accessories</label>
        <div id="accTiles" class="flex flex-wrap"></div>
      </div>
    </div>
  </div>

<script>
/*
  Avatar page JS:
  - Provides tile-based selectors for several parameters (hair, eyes, accessories)
  - Builds a DiceBear HTTP API URL and previews the SVG
  - Allows capture/upload of photo -> hash to seed -> preview avatars
  - Save to server via /save_avatar (expects data:image/svg+xml;base64,...)
*/

const previewEl = document.getElementById('avatarPreview');
const seedInput = document.getElementById('seedInput');
const styleSelect = document.getElementById('styleSelect');
let selectedParams = { hair: '', eyes: '', accessories: '' };

// simple tile palettes (small subset; you can expand these arrays)
const hairOptions = ['short', 'long', 'bun', 'mohawk', 'bald'];
const eyesOptions = ['normal', 'smile', 'surprised', 'wink'];
const accOptions = ['glasses', 'beanie', 'earring', 'hat', 'none'];

function buildDicebearUrl(){
  const style = styleSelect.value || 'adventurer';
  const seed = seedInput.value || Math.random().toString(36).slice(2,10);
  const params = new URLSearchParams();
  params.set('seed', seed);
  // many DiceBear styles accept different query params. We set generic ones for demonstration.
  if(selectedParams.hair) params.set('hair', selectedParams.hair);
  if(selectedParams.eyes) params.set('eyes', selectedParams.eyes);
  if(selectedParams.accessories && selectedParams.accessories !== 'none') params.set('accessories', selectedParams.accessories);
  params.set('backgroundColor', 'transparent');
  // use the 9.x DiceBear API path
  return `https://api.dicebear.com/9.x/${encodeURIComponent(style)}/svg?${params.toString()}`;
}

async function renderPreview(){
  const url = buildDicebearUrl();
  // fetch SVG (as text) then show inline; also prepare a data URL for downloading
  const r = await fetch(url);
  if(!r.ok) {
    previewEl.innerHTML = 'Could not fetch avatar';
    return;
  }
  const svgText = await r.text();
  // sanitize (basic) and show
  previewEl.innerHTML = svgText;
  // store for download
  previewEl.dataset.svg = svgText;
}

document.getElementById('randomSeed').addEventListener('click', ()=>{
  seedInput.value = Math.random().toString(36).slice(2,10);
  renderPreview();
});

styleSelect.addEventListener('change', renderPreview);
seedInput.addEventListener('change', renderPreview);

// build tiles UI
function mkTiles(containerId, options, paramKey){
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  options.forEach(opt=>{
    const t = document.createElement('div'); t.className='tile';
    t.innerHTML = `<div style="font-size:28px;">${opt[0].toUpperCase()}</div><div style="font-size:12px;">${opt}</div>`;
    t.onclick = ()=>{
      selectedParams[paramKey] = opt;
      // highlight selection
      Array.from(el.children).forEach(c=> c.style.outline='');
      t.style.outline = '2px solid #4f46e5';
      renderPreview();
    };
    el.appendChild(t);
  });
}
mkTiles('hairTiles', hairOptions, 'hair');
mkTiles('eyesTiles', eyesOptions, 'eyes');
mkTiles('accTiles', accOptions, 'accessories');

// camera & upload
let stream = null;
const cameraContainer = document.getElementById('cameraPreview');
document.getElementById('startCamera').addEventListener('click', async ()=>{
  if(stream){ // stop
    stream.getTracks().forEach(t=>t.stop()); stream=null; cameraContainer.innerHTML=''; return;
  }
  try{
    stream = await navigator.mediaDevices.getUserMedia({ video:true, audio:false });
    const v = document.createElement('video'); v.autoplay = true; v.playsInline = true; v.srcObject = stream;
    cameraContainer.innerHTML=''; cameraContainer.appendChild(v);
  }catch(e){ alert('Camera error: ' + e.message); }
});

document.getElementById('takePhoto').addEventListener('click', async ()=>{
  if(!stream){ alert('Start camera first'); return; }
  const video = cameraContainer.querySelector('video');
  if(!video) return;
  const c = document.createElement('canvas'); c.width = video.videoWidth || 400; c.height = video.videoHeight || 400;
  const ctx = c.getContext('2d'); ctx.drawImage(video, 0, 0, c.width, c.height);
  const dataUrl = c.toDataURL('image/png');
  // hash the image data and use as seed
  const hashHex = await hashDataUrl(dataUrl);
  seedInput.value = 'photo-' + hashHex.slice(0,10);
  renderPreview();
});

document.getElementById('uploadPhoto').addEventListener('click', ()=>{
  const inp = document.createElement('input'); inp.type='file'; inp.accept='image/*';
  inp.onchange = async (ev)=>{
    const f = ev.target.files[0];
    const reader = new FileReader();
    reader.onload = async (e)=>{
      const dataUrl = e.target.result;
      const hh = await hashDataUrl(dataUrl);
      seedInput.value = 'upload-' + hh.slice(0,10);
      renderPreview();
    };
    reader.readAsDataURL(f);
  };
  inp.click();
});

async function hashDataUrl(dataUrl){
  const b = atob(dataUrl.split(',')[1]);
  const arr = new Uint8Array(b.length);
  for(let i=0;i<b.length;i++) arr[i]=b.charCodeAt(i);
  const digest = await crypto.subtle.digest('SHA-1', arr);
  return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

document.getElementById('downloadAvatar').addEventListener('click', ()=>{
  const svg = previewEl.dataset.svg;
  if(!svg) return alert('Generate avatar first');
  const blob = new Blob([svg], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'avatar.svg'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});

document.getElementById('saveAvatar').addEventListener('click', async ()=>{
  const svg = previewEl.dataset.svg;
  if(!svg) return alert('Generate avatar first');
  const b64 = btoa(unescape(encodeURIComponent(svg)));
  const dataUri = 'data:image/svg+xml;base64,' + b64;
  // send to server to save and get cached url
  const username = prompt('Save avatar for which username?', 'user');
  if(!username) return;
  const r = await fetch('/save_avatar', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, image: dataUri })});
  const j = await r.json();
  if(j.ok){
    alert('Avatar saved: ' + j.url);
    // open profile page in parent and set preview if possible
    try{ window.opener && window.opener.postMessage({ avatarSaved: j.url }, '*'); }catch(e){}
  } else {
    alert('Save failed: ' + (j.error || 'unknown'));
  }
});

// initial render
renderPreview();
</script>
</body></html>
'''
# ---- CHAT HTML (heavily modified) ----
# --- CHAT page: updated with emoji-mart v5, sticker/gif/avatar/emoji panel, typing indicator, attach menu, poll modal, avatar flow ---
CHAT_HTML = r'''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>InfinityChatter — Chat</title>
  <link rel="icon" href="/static/favicon.png" type="image/png">
  <link rel="apple-touch-icon" href="/static/favicon.png">
  <link rel="shortcut icon" href="/static/favicon.png">
  <link rel="manifest" href="/static/manifest.json">
  <meta name="theme-color" content="#0f172a">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="InfinityChatter">
  <meta name="mobile-web-app-capable" content="yes">
  <script src="https://cdn.tailwindcss.com"></script>

  <!-- emoji-mart v5 browser build (exposes global EmojiMart for vanilla JS) -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/emoji-mart@5.6.0/dist/browser.css">
  <script src="https://cdn.jsdelivr.net/npm/emoji-mart@5.6.0/dist/browser.js"></script>

  <style>
    :root{
      --glass-bg: rgba(255,255,255,0.8);
      --download-bg: rgba(17,24,39,0.7);
    }

    /* page background image */
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      background-image: url('/static/background.jpeg');
      background-repeat: no-repeat;
      background-position: center center;
      background-attachment: fixed;
      background-size: cover;
      margin: 0;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    header {
      position: fixed;
      left: 0;
      right: 0;
      top: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      background: linear-gradient(90deg, rgba(255,255,255,0.98), rgba(248,250,252,0.95));
      z-index: 40;
      padding: 10px 14px;
      border-bottom: 1px solid rgba(0,0,0,0.04);
      box-sizing: border-box;
      flex-wrap: wrap;
      text-align: center;
    }

    /* wrapper centers everything */
    .heading-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
      width: 100%;
      max-width: 980px;
    }

    .heading-wrapper img {
      height: 56px;
      width: auto;
      border-radius: 10px;
      object-fit: cover;
    }

    .heading-title {
      font-weight: 800;
      font-size: 1.05rem;
      line-height: 1;
    }

    /* tablets */
    @media (min-width: 768px) {
      header { padding: 12px 18px; }
      .heading-wrapper { flex-direction: column; align-items: center; }
      .heading-wrapper img { height: 70px; }
      .heading-title { font-size: 1.25rem; }
    }

    /* laptops/desktops: slightly smaller height + keep centered */
    @media (min-width: 1024px) {
      header { padding: 10px 20px; }
      .heading-wrapper { flex-direction: column; align-items: center; text-align: center; }
      .heading-wrapper img { height: 64px; }
      .heading-title { font-size: 1.4rem; margin-left: 0; }
    }
    .call-btn{
      display:inline-flex;
      align-items:center;
      gap:6px;
      white-space:nowrap;
      padding:6px 10px;
      border-radius:8px;
      border:1px solid rgba(0,0,0,0.08);
      background: #fff;
      box-shadow: 0 1px 2px rgba(0,0,0,0.04);
      cursor:pointer;
      font-size:0.92rem;
      transition: transform .08s ease, box-shadow .08s ease;
    }
    .call-btn:active{ transform: translateY(1px); }
    .call-btn:hover{ box-shadow: 0 4px 12px rgba(0,0,0,0.08); }

    /* make buttons tile/stack on very small widths */
    @media (max-width:520px){
      .header-actions { gap:6px; }
      .call-btn { padding:8px 12px; font-size:0.9rem; flex: 1 1 auto; min-width:120px; text-align:center; }
    }

    .header-actions {
      position: absolute;
      right: 12px;
      top: 12px;
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .profile-name {
      cursor: pointer;
      padding: 6px 10px;
      border-radius: 10px;
      background: white;
      box-shadow: 0 6px 18px rgba(2,6,23,0.04);
    }

    /* give first message a bit of breathing room under header */
    .chat-messages {
      padding-top: calc(var(--header-height, 80px) + 12px);
    }

    main{ padding:120px 12px 200px; max-width:980px; margin:0 auto; min-height:calc(100vh - 260px); box-sizing:border-box; }
    .msg-row{ margin-bottom:12px; display:flex; gap:8px; align-items:flex-start; }
    .msg-body{ display:flex; flex-direction:column; align-items:flex-start; min-width:0; }
    .bubble{ position:relative; padding: 10px 36px 10px 14px; border-radius:12px; display:inline-block; word-break:break-word; white-space:pre-wrap; background-clip:padding-box; box-shadow: 0 6px 18px rgba(2,6,23,0.04); }
    .me{ background: linear-gradient(90deg,#e6ffed,#dcffe6); border-bottom-right-radius:6px; align-self:flex-end; margin-left:auto; }
    .them{ background: rgba(255,255,255,0.95); border-bottom-left-radius:6px; margin-right:auto; }
    .bubble .three-dot { position:absolute; top:8px; right:8px; background:transparent; border:none; font-size:1.05rem; padding:4px; cursor:pointer; color:#111827; border-radius:6px; z-index: 5;}
    .msg-meta-top{ font-size:0.75rem; color:#6b7280; display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px; width:100%; transition: color 0.2s ease; }

    /* attachments & previews */
    #attachmentPreview{ padding:8px; border-bottom:1px solid rgba(0,0,0,0.06); display:none; }
    .preview-item{ position:relative; display:inline-block; margin-right:8px; vertical-align:top; max-width:90px; }
    .preview-item img, .preview-item video{ max-width:100%; border-radius:8px; display:block; }
    .media-container{ position:relative; display:inline-block; width:100%; max-width:420px; }
    .media-container img.thumb{ display:block; width:100%; border-radius:10px; }
    .media-container .play-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
    .media-container .play-overlay .play-circle{ width:56px; height:56px; background: rgba(0,0,0,0.6); border-radius:999px; display:flex; align-items:center; justify-content:center; color:white; font-size:22px; }
    .download-btn{ position:absolute; top:8px; right:8px; width:36px; height:36px; border-radius:999px; display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; background:var(--download-bg); font-size:1.05rem; z-index:10; box-shadow:0 6px 18px rgba(0,0,0,0.2); }
    .doc-link{ display:inline-flex; align-items:center; gap:10px; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 6px 18px rgba(2,6,23,0.04); margin-top:8px; text-decoration:none; color:#111827; }

    .reaction-bar{ display:flex; gap:6px; margin-top:8px; align-items:center; }
    .reaction-pill{ display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.95); box-shadow:0 6px 18px rgba(2,6,23,0.04); font-size:0.85rem; }
    .reaction-emoji{ width:20px; height:20px; display:inline-flex; align-items:center; justify-content:center; font-size:14px; }

    /* ===== Liquid Glass Responsive Composer ===== */
    .composer {
      position: fixed;
      left: 0;
      right: 0;
      bottom: calc(env(safe-area-inset-bottom, 0) + 8px);
      display: flex;
      justify-content: center;
      padding: clamp(8px, 2.4vw, 18px);
      z-index: 90;
      transition: bottom 0.28s ease-in-out, transform 0.28s ease-in-out;
      pointer-events: auto;
    }

    .composer.up {
      transform: translateY(-60vh); /* matches drawer height */
    }

    .composer-main {
      display: flex;
      border-radius: 14px;
      padding: 8px 10px;
      gap: 6px;
      align-items: center;
      width: min(980px, calc(100% - 32px));
      max-width: 980px;
      margin: 0 auto;           /* <-- keeps it centered */
      position: relative;
      overflow: hidden;

      /* frosted translucent look */
      background: linear-gradient(
        135deg,
        rgba(255, 255, 255, 0.35) 0%,
        rgba(245, 247, 250, 0.20) 100%
      );
      backdrop-filter: blur(16px) saturate(1.35) contrast(1.05);
      -webkit-backdrop-filter: blur(16px) saturate(1.35) contrast(1.05);

      /* inner + outer glow */
      box-shadow: 0 8px 28px rgba(8, 15, 30, 0.12),
                  inset 0 1px 1px rgba(255, 255, 255, 0.45);
      border: 1px solid rgba(255, 255, 255, 0.25);
      transition: box-shadow .25s ease, transform .25s ease;
      flex-wrap: nowrap;
      z-index: 1;
    }

    /* sheen highlight */
    .composer-main::after {
      content: "";
      position: absolute;
      top: -40%;
      left: -20%;
      width: 140%;
      height: 80%;
      background: linear-gradient(
        120deg,
        rgba(255, 255, 255, 0.55) 0%,
        rgba(255, 255, 255, 0.12) 40%,
        rgba(255, 255, 255, 0) 80%
      );
      transform: rotate(-12deg);
      filter: blur(20px);
      opacity: 0.6;
      pointer-events: none;
      z-index: 0;
      transition: opacity .25s ease, transform .25s ease;
    }

    /* Elevated (focused/open state) */
    .composer-main.glass-elevated {
      transform: translateY(-6px);
      backdrop-filter: blur(22px) saturate(1.5) contrast(1.07);
      -webkit-backdrop-filter: blur(22px) saturate(1.5) contrast(1.07);
      box-shadow: 0 18px 40px rgba(6, 10, 25, 0.16),
                  inset 0 1px 2px rgba(255, 255, 255, 0.55);
    }
    .composer-main.glass-elevated::after {
      opacity: 0.85;
      transform: rotate(-10deg) translateY(-6px);
    }

    /* Buttons (plus, mic, emoji) */
    .plus-small, .mic-btn, #emojiBtn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: clamp(36px, 7vw, 48px);
      height: clamp(36px, 7vw, 48px);
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.18);
      background: rgba(255,255,255,0.4);
      backdrop-filter: blur(6px) saturate(1.2);
      -webkit-backdrop-filter: blur(6px) saturate(1.2);
      box-shadow: 0 6px 16px rgba(2, 6, 23, 0.08);
      z-index: 5;
      flex: 0 0 auto;
      -webkit-tap-highlight-color: transparent;
      transition: background .2s ease;
    }
    .plus-small:hover, .mic-btn:hover, #emojiBtn:hover {
      background: rgba(255,255,255,0.55);
    }

    /* circular mic on narrow screens */
    @media (max-width:420px){
      .mic-btn {
        border-radius: 999px;
        width: clamp(40px,9vw,52px);
        height: clamp(40px,9vw,52px);
      }
    }

    /* Textarea */
    .textarea {
      flex: 1 1 auto;
      min-height: 40px;
      font-size: 0.9rem;
      padding: 6px 8px;
      max-height: 30vh;
      border-radius: 12px;
      border: 0;
      resize: none;
      background: rgba(255,255,255,0.75);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      color: #0b1220;
      outline: none;
      box-sizing: border-box;
      line-height: 1.4;
      transition: background .2s ease;
    }
    .textarea:focus {
      background: rgba(255,255,255,0.9);
    }

    /* Send button */
    #sendBtn {
      flex: 0 0 auto;
      padding: clamp(8px,1.8vw,12px) clamp(12px,2.2vw,16px);
      margin-left: 6px;
      border-radius: 12px;
      font-size: clamp(.9rem,1.6vw,1rem);
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: white;
      box-shadow: 0 6px 20px rgba(79,70,229,0.35);
      transition: transform .15s ease, box-shadow .15s ease;
    }
    #sendBtn:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(79,70,229,0.45); }

    /* Extra tiny screens: hide plus */
    @media (max-width: 380px){
      .plus-small { display:none; }
      .composer-main { gap: 6px; padding: 8px; }
    }
    /* Tablet sizes (≥ 600px) → medium */
    @media (min-width: 600px) {
      .composer-main {
        border-radius: 18px;
        padding: 12px 14px;
        gap: 10px;
      }
      .textarea {
        min-height: 48px;
        font-size: 1rem;
        padding: 8px 10px;
      }
      .plus-small, .mic-btn, #emojiBtn {
        width: 42px;
        height: 42px;
      }
    }

    /* Laptop / Desktop (≥ 1024px) → larger and more spacious */
    @media (min-width: 1024px) {
      .composer-main {
        border-radius: 22px;
        padding: 14px 18px;
        gap: 14px;
      }
      .textarea {
        min-height: 56px;
        font-size: 1.05rem;
        padding: 10px 14px;
      }
      .plus-small, .mic-btn, #emojiBtn {
        width: 48px;
        height: 48px;
      }
      #sendBtn {
        font-size: 1rem;
        padding: 12px 18px;
        border-radius: 14px;
      }
    }
    .emoji-mart {
      position: absolute !important;
      left: 0 !important;
      right: 0 !important;
      bottom: 0 !important;
      top: auto !important;
      width: 100% !important;
      height: 100% !important;
      max-width: none !important;
      border-radius: 0 !important;
      box-shadow: none !important;
      border-top: 1px solid #e5e7eb !important;
    }

    .emoji-drawer.active {
      display: flex;
    }

    /* Header with drag handle */
    .emoji-drawer-header {
      height: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .drag-bar {
      width: 42px;
      height: 4px;
      border-radius: 4px;
      background: rgba(0,0,0,0.2);
    }

    /* Content scrollable */
    .emoji-drawer-content {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    /* Emoji grid */
    .emoji-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
      gap: 10px;
      font-size: 1.6rem;
      text-align: center;
    }

    /* GIFs */
    .gif-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
      gap: 10px;
    }
    .gif-grid img {
      width: 100%;
      border-radius: 10px;
      cursor: pointer;
      transition: transform .2s;
    }
    .gif-grid img:hover {
      transform: scale(1.05);
    }

    /* Push composer up when drawer open */
    .composer {
      transition: bottom 0.3s ease;
    }

    .composer.up {
      bottom: 280px;  /* match emoji panel height */
    }

    .attach-menu-vertical {
        position: fixed;
        right: 18px;
        bottom: 100px;
        display: none; /* start hidden */
        flex-direction: column;
        gap: 10px;
        border-radius: 12px;
        z-index: 80;
    }
    .attach-card{ background:white; padding:10px 14px; min-width:140px; box-shadow:0 10px 30px rgba(0,0,0,0.12); display:flex; gap:8px; align-items:center; cursor:pointer; }

    /* sticker panel */
    #stickerPanel{ position:fixed; left:0; right:0; bottom:76px; height:40vh; background:linear-gradient(180deg,#fff,#f9fafb); border-top-left-radius:14px; border-top-right-radius:14px; box-shadow:0 -10px 30px rgba(0,0,0,0.06); padding:12px; display:none; z-index:75; overflow:auto; }
    .panel-tabs{ display:flex; gap:8px; margin-bottom:8px; }
    .panel-tabs button{ padding:6px 10px; border-radius:999px; border:0; background:#f3f4f6; cursor:pointer; }
    .avatar-controls .tile { display:inline-flex; gap:8px; padding:8px; border-radius:8px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); cursor:pointer; text-align:center; flex-direction:column; width:92px; align-items:center; }

    /* polling modal */
    .modal { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(0,0,0,0.4); z-index:120; }
    .modal-card { width:100%; max-width:560px; background:white; border-radius:12px; padding:16px; }

    /* small utilities */
    .hidden{ display:none; }
    /* Bottom drawer panel */
    #stickerPanel {
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;               /* Stick to bottom */
      height: 40vh;            /* like phone keyboard */
      background: #fff;
      border-top-left-radius: 14px;
      border-top-right-radius: 14px;
      box-shadow: 0 -4px 16px rgba(0,0,0,0.1);
      transform: translateY(100%);
      transition: transform 0.25s ease-in-out;
      z-index: 200;
      display: flex;
      flex-direction: column;
    }
    #stickerPanel.active {
      transform: translateY(0);
    }
    .composer {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      transition: bottom 0.25s ease-in-out;
    }
    #emojiGrid .emoji-mart {
      width: 100% !important;
      height: 100% !important;
      border: none !important;
      box-shadow: none !important;
      border-radius: 0 !important;
    }
    /* Incoming call banner */
    .incoming-call-banner {
      position: fixed;
      top: calc(var(--header-height, 56px) + 8px);
      left: 0;
      right: 0;
      background: #ffffffee;
      border: 1px solid #ddd;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      z-index: 200;
      padding: 12px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .incoming-call-banner.hidden {
      display: none;
    }

    .incoming-call-banner .caller-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .incoming-call-banner .caller-info #incomingLabel {
      font-size: 0.9rem;
      color: #555;
    }
    .incoming-call-banner .caller-info #incomingCallerName {
      font-size: 1.1rem;
      font-weight: bold;
      color: #111;
    }

    .incoming-call-banner .banner-buttons {
      display: flex;
      gap: 12px;
    }
    .incoming-call-banner .btn-decline,
    .incoming-call-banner .btn-accept {
      padding: 8px 14px;
      border: none;
      border-radius: 8px;
      font-size: 0.9rem;
      cursor: pointer;
    }
    .btn-decline {
      background: #f87171;  /* red */
      color: white;
    }
    .btn-accept {
      background: #34d399;  /* green */
      color: white;
    }

    /* In-call control buttons (header area) */
    .in-call-controls {
      position: fixed;
      top: 12px;
      left: 12px;
      display: flex;
      gap: 8px;
      z-index: 210;
    }
    .in-call-controls.hidden {
      display: none;
    }
    .ic-btn {
      background: rgba(255,255,255,0.9);
      border: none;
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 1.2rem;
      cursor: pointer;
      box-shadow: 0 3px 8px rgba(0,0,0,0.15);
    }
    .ic-btn:hover {
      background: rgba(255,255,255,1);
    }
    .chat-audio {
      width: 250px;
      height: 40px;
    }
    .message-wrapper { padding:8px; margin:6px 0; background:#f7f7f7; border-radius:8px; position:relative; overflow:visible; }
    .message-header { display:flex; align-items:center; gap:8px; justify-content:space-between; }
    .msg-opts-btn { background:transparent; border:0; cursor:pointer; font-size:18px; line-height:1; padding:4px; margin-left:8px; visibility:visible; z-index:20; }
    .msg-menu { position:absolute; right:8px; top:36px; background:#fff; border:1px solid #ddd; border-radius:6px; padding:6px; z-index:100000; box-shadow:0 8px 16px rgba(0,0,0,0.12); display:none; }
    .msg-menu.visible { display:block; }
    /* Outgoing/online modal tweaks */
    #onlineUsersModal .modal-card { padding:12px; }
    .online-user-tile { display:flex; align-items:center; gap:10px; padding:8px; border-radius:8px; cursor:pointer; background:#fff; color:#111; box-shadow:0 6px 18px rgba(2,6,23,0.04); }
    .online-user-tile:hover { transform:translateY(-2px); transition:transform .12s ease; }
    @keyframes slideDown {
      from {transform:translateY(-100%);opacity:0;}
      to {transform:translateY(0);opacity:1;}
    }
    #waIncomingBanner>div, #waOutgoingBanner>div {
      animation: slideDown 0.3s ease-out;
    }
    .incoming-meet-banner{
      position:fixed;bottom:0;left:0;right:0;
      background:#f7f9ff;
      border-top:2px solid #4285F4;
      display:flex;justify-content:center;
      padding:12px;z-index:9999;
      box-shadow:0 -2px 6px rgba(0,0,0,0.1);
    }
    .banner-content{display:flex;align-items:center;gap:12px;}
    .banner-actions button{font-size:14px;padding:4px 10px;border-radius:6px;border:none;cursor:pointer;}
    .accept-btn{background:#34A853;color:white;}
    .decline-btn{background:#EA4335;color:white;}
  </style>
</head>
<body>

      <!-- Header -->
      <header>
        <button id="audioCallBtn" class="call-btn" title="Start audio call" aria-label="Audio call" style="position: fixed; left: 0.50rem; top: 0.50rem;">📞 Audio</button>
        <button id="videoCallBtn" class="call-btn" title="Start video call" aria-label="Video call" style="position: fixed; left: 0.50rem; top: 3.20rem">📽️ Video</button>
        <div class="heading-wrapper" role="banner" aria-label="App header">
          <img src="{{ heading_img }}" alt="Heading image" />
          <div class="heading-title">Asphalt <span style="color:#be185d;">Legends</span></div>
        </div>

        <!-- Incoming Call Banner / Modal -->
        <div id="incomingCallBanner" class="incoming-call-banner hidden">
          <div class="banner-content">
            <div class="caller-info">
              <span id="incomingLabel">Incoming Call</span>
              <span id="incomingCallerName"></span>
            </div>
            <div class="banner-buttons">
              <button id="declineCallBtn" class="btn-decline">Decline</button>
              <button id="acceptCallBtn" class="btn-accept">Accept</button>
            </div>
          </div>
        </div>

        <!-- Online Users Modal (appears when user clicks call button) -->
        <div id="onlineUsersModal" class="modal hidden" style="z-index:220;">
          <div class="modal-card" style="max-width:420px;">
            <h3 style="margin:0 0 8px 0;">Select a person to call</h3>
            <div id="onlineUsersList" style="display:flex;flex-direction:column;gap:8px;max-height:50vh;overflow:auto;padding-right:6px;"></div>
            <div style="text-align:right;margin-top:8px;">
              <button id="closeOnlineUsers" style="padding:8px 12px;border-radius:6px;">Cancel</button>
            </div>
          </div>
        </div>

        <div class="header-actions" role="navigation" aria-label="Profile actions">
          <div id="profileBtn" class="profile-name">{{ username }}</div>
          <div id="profileMenu" class="menu hidden"
            style="display:none; position: absolute; right:12px; top:48px; border-radius:12px; overflow:hidden;">
            <div id="viewProfileBtn" class="attach-card">Profile</div>
            <form method="post" action="{{ url_for('logout') }}" style="margin:0;">
              <button type="submit" class="attach-card">Logout</button>
            </form>
          </div>
        </div>
      </header>
      <div id="meetShareBox" class="hidden" style="position:fixed;bottom:20px;right:20px;background:#fff;border-radius:12px;box-shadow:0 0 12px rgba(0,0,0,0.15);padding:14px;z-index:999;">
          <div style="font-weight:600;margin-bottom:8px;">Share Google Meet Link</div>
          <input id="meetShareInput" type="text" placeholder="Paste your Meet link here" style="width:240px;padding:6px;border:1px solid #ccc;border-radius:6px;">
          <button id="meetShareBtn" style="margin-left:8px;background:#4285F4;color:#fff;border:none;padding:6px 10px;border-radius:6px;">Share</button>
      </div>

      <div id="chat-wrap" style="position:relative; min-height:360px; display:flex; flex-direction:column; top:6.5rem; overflow-y: auto;">
            <div id="messages" class="mb-6" aria-live="polite" style="padding: 12px;"></div>

            <!-- Bottom Drawer: Stickers/GIFs/Avatars/Emoji -->
            <div id="stickerPanel" class="emoji-drawer">
              <div class="drag-bar" style="
                  width:40px;
                  height:5px;
                  background:#ccc;
                  border-radius:3px;
                  margin:8px auto;
              "></div>

              <!-- Tabs -->
              <div class="panel-tabs">
                <button id="tab_stickers">Stickers</button>
                <button id="tab_gifs">GIFs</button>
                <button id="tab_avatars">Avatars</button>
                <button id="tab_emoji">Emoji</button>
              </div>

              <!-- Content area -->
              <div id="panelContent" class="emoji-drawer-content">
                <div id="stickersContainer" class="grid grid-cols-4 gap-2 hidden"></div>
                <div id="gifGrid" class="gif-grid hidden"></div>
                <div id="avatarGrid" class="emoji-grid hidden"></div>
                <div id="emojiGrid" class="emoji-grid"></div>
              </div>
            </div>

          <!-- Composer -->
          <div class="composer" id="composer" aria-label="Composer area">
            <div class="composer-inner">
              <div id="attachmentPreview"></div>

              <div class="composer-main" id="composerMain" role="form" aria-label="Message composer">
                <button id="plusBtn" class="plus-small bg-white shadow" style="font-size:2rem;" aria-label="Attach">＋</button>

                <textarea id="msg" class="textarea" placeholder="Type a message..." maxlength="1200"
                  aria-label="Message input"></textarea>

                <!-- emoji button opens drawer -->
                <button id="emojiBtn" title="Emoji" class="w-11 h-11 rounded-lg bg-white" aria-label="Emoji">😊</button>

                <!-- mic button -->
                <button id="micBtn" class="mic-btn" aria-label="Voice message" aria-pressed="false"
                  title="Hold to record or click to toggle">🎙️</button>

                <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white" aria-label="Send">Send</button>
              </div>
            </div>
          </div>
          <div id="attachMenuVertical" class="attach-menu-vertical" style="display: none;">
              <div class="attach-card" data-action="document">📁<div>  Documents</div></div>
              <div class="attach-card" data-action="camera">📷<div>  Camera</div></div>
              <div class="attach-card" data-action="gallery">🌇<div>  Gallery</div></div>
              <div class="attach-card" data-action="audio">🎧<div>  Audio</div></div>
              <div class="attach-card" data-action="location">🌐<div>  Location</div></div>
              <div class="attach-card" id="pollBtn">🗳️<div>  Poll</div></div>
          </div>
          <!-- Poll modal -->
          <div id="pollModal" class="hidden" style="display:none;">
            <div class="modal">
              <div class="modal-card">
                <h3>Create Poll</h3>
                <form id="pollForm">
                  <div><input id="poll_question" placeholder="Your question" class="w-full p-2 border rounded mb-2"></div>
                  <div id="pollOptions">
                    <input name="option" placeholder="Option 1" class="w-full p-2 border rounded mb-2">
                    <input name="option" placeholder="Option 2" class="w-full p-2 border rounded mb-2">
                  </div>
                  <div class="flex gap-2">
                    <button id="addPollOption" type="button" class="px-3 py-1 bg-gray-100 rounded">Add option</button>
                    <button class="px-3 py-1 bg-indigo-600 text-white rounded">Create Poll</button>
                    <button id="cancelPoll" type="button" class="px-3 py-1 bg-gray-200 rounded">Cancel</button>
                  </div>
                </form>
              </div>
            </div>
          </div>

          <!-- Profile Modal -->
          <div id="profileModal" class="hidden fixed inset-0 items-center justify-center bg-black/40 z-[60]">
            <div class="bg-white rounded-lg p-4 w-96">
              <div class="flex items-center justify-between mb-3">
                <div>
                  <div class="text-lg font-bold">Profile</div>
                </div>
                <button id="closeProfile" class="text-gray-500">✕</button>
              </div>
              <form id="profileForm" enctype="multipart/form-data">
                <div class="mb-2"><label class="text-xs">Display name</label><input id="profile_display_name" name="name"
                    class="w-full p-2 border rounded" value="{{ username }}" /></div>
                <div class="mb-2"><label class="text-xs">Status</label><input id="profile_status" name="status"
                    class="w-full p-2 border rounded" value="{{ user_status }}" /></div>
                <div class="mb-2">
                  <label class="text-xs">Avatar</label>
                  <div style="display:flex;gap:8px;">
                    <button id="createAvatarBtn" type="button" class="px-3 py-2 bg-green-600 text-white rounded">Create
                      Avatar</button>
                    <div id="currentAvatarPreview"
                      style="min-width:64px;min-height:64px;background:#f3f4f6;border-radius:8px;"></div>
                  </div>
                </div>
                <div class="flex gap-2">
                  <button type="submit" class="px-3 py-2 rounded bg-indigo-600 text-white">Save</button>
                  <button id="profileCancel" type="button" class="px-3 py-2 rounded bg-gray-200">Cancel</button>
                </div>
                <div id="profileMsg" class="text-sm mt-2 text-gray-500"></div>
              </form>
            </div>
          </div>

          <!-- Incoming call banner -->
          <div id="incomingCall"
            style="display:none; position:fixed; left:50%; transform:translateX(-50%); top:12px; z-index:100; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12);">
            <div id="incomingText">Incoming call</div>
            <div style="display:flex;gap:8px;margin-top:8px;">
              <button id="acceptCall" class="px-3 py-1 rounded bg-green-600 text-white">Accept</button>
              <button id="declineCall" class="px-3 py-1 rounded bg-red-500 text-white">Decline</button>
            </div>
          </div>
      </div>
<!-- include socket.io and other scripts (socket server expected) -->
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script src="/static/push-client.js"></script>
<script>

window.socket = io({
  transports: ['websocket', 'polling'],  // allow WebSocket upgrade
  path: '/socket.io',
  upgrade: true,                         // enable upgrade to WebSocket
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 2000
});

if (typeof cs !== 'undefined') cs.socket = window.socket;

socket.on('connect', () => {
  console.log('✅ socket connected', socket.id);
  const profile = JSON.parse(localStorage.getItem('infinity_profile') || '{}');
  if (profile.name) socket.emit('register_socket', { username: profile.name });
});
socket.on('disconnect', () => console.log('⚠️ socket disconnected'));
socket.on('connect_error', (err) => console.error('❌ socket connect_error', err));

(async function() {
  // token format: the raw query string if no key used
  const raw = window.location.search.replace(/^\?/, '');
  const token = raw || new URLSearchParams(window.location.search).get('t');

  // if your server expects session, call the server to resolve the token
  try {
    const r = await fetch('/api/resolve_peer?t=' + encodeURIComponent(token), {credentials: 'same-origin'});
    if (!r.ok) {
      // handle error: maybe user not logged-in on server; if you use localStorage-profile,
      // you can fallback to a client-side lookup (not recommended for security).
      console.warn('resolve_peer failed', await r.text());
      // fallback: try to treat token as name (if deterministic generation used)
      // or redirect to /login
    } else {
      const j = await r.json();
      const peer = j.peer;
      // now load messages for peer, e.g. fetch('/messages?peer=' + encodeURIComponent(peer)) etc.
      initChatForPeer(peer);
    }
  } catch (e) {
    console.error(e);
  }
})();

(function () {
  'use strict';

  // Central state container to avoid accidental globals
  const cs = {
    socket: (typeof io === 'function') ? io() : null,
    myName: "{{ username }}" || "anonymous",
    lastId: 0,
    stagedFiles: [],
    typingTimer: null,
    isTyping: false,
    calls: {},     // call_id -> call state
    pcConfig: { iceServers: [{ urls: ["stun:stun.l.google.com:19302"] }] }

  };
  window.messageStates = {};
  const socket = (typeof cs !== 'undefined' && cs.socket)
    ? cs.socket
    : (typeof io === 'function' ? io({ transports: ['polling'] }) : null);
  // Safe DOM refs (assigned on DOMContentLoaded)
  let emojiBtn, composer, textarea, micBtn, plusBtn, attachMenuVertical;
  let sendBtn, emojiDrawer, messagesEl, inputEl, composerEl, composerMain, panel;
  let incomingCallBanner, incomingCallerNameEl, acceptCallBtn, declineCallBtn;
  let inCallControls, btnHangup, btnMute, btnToggleVideo, btnSwitchCam;
  let panelGrid;

  cs.socket.on("connect", () => {
    if (cs.myName || window.username) {
      const name = cs.myName || window.username;
      cs.socket.emit("identify", { name });
      console.log("🔄 re-identify sent on reconnect:", name);

      // init push subscription (if push-client.js is loaded)
      if (window.initPushForCurrentUser) {
        try { window.initPushForCurrentUser(); } catch(e){ console.warn('initPush failed', e); }
      }
    } else {
      console.warn("⚠️ No username set for identify");
    }
  });


  // ✅ Incoming call event (WhatsApp-style banner)
  cs.socket.on("incoming_call", (d) => {
      console.log("📞 Incoming call:", d);
      if (typeof showWhatsAppIncomingBanner === "function") {
        showWhatsAppIncomingBanner(d.from, d.isVideo, d.call_id);
      } else {
        console.warn("⚠️ showWhatsAppIncomingBanner not defined yet.");
      }
  });

  // Helper: safe getElement
  function $id(id){ return document.getElementById(id) || null; }

  // Simple HTML escape
  function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }

  // Expose escapeHtml (some other code may call it)
  window.escapeHtml = escapeHtml;

  window.showWhatsAppIncomingBanner = function(fromUser, isVideo, call_id){
      document.getElementById("waIncomingBanner")?.remove();
      const banner = document.createElement("div");
      banner.id = "waIncomingBanner";
      banner.innerHTML = `
        <div style="
          position:fixed;top:0;left:0;right:0;height:90px;
          background:linear-gradient(135deg,#25D366,#128C7E);
          color:white;display:flex;align-items:center;justify-content:space-between;
          padding:12px 20px;font-family:system-ui,sans-serif;
          box-shadow:0 2px 10px rgba(0,0,0,0.25);z-index:9999;">
          <div style="display:flex;align-items:center;gap:14px;">
            <img src="/avatar/${fromUser}" style="width:56px;height:56px;border-radius:50%;
                  object-fit:cover;border:2px solid #fff;">
            <div>
              <div style="font-weight:600;font-size:18px;">${fromUser}</div>
              <div style="font-size:14px;opacity:.9;">${isVideo ? "Video call" : "Voice call"}</div>
            </div>
          </div>
          <div style="display:flex;gap:12px;">
            <button id="waAccept" style="
              background:#25D366;border:none;border-radius:50%;width:48px;height:48px;
              display:flex;align-items:center;justify-content:center;">📞</button>
            <button id="waDecline" style="
              background:#d9534f;border:none;border-radius:50%;width:48px;height:48px;
              display:flex;align-items:center;justify-content:center;">❌</button>
          </div>
        </div>`;
      document.body.appendChild(banner);

      const accept = document.getElementById("waAccept");
      const decline = document.getElementById("waDecline");

      accept.onclick = () => {
          socket.emit("call_accept", { call_id, from: MYNAME });
          banner.remove();
          const msg = document.createElement("div");
          msg.textContent = "Opening meeting…";
          msg.style.cssText = "position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#0b5;color:#fff;padding:8px 12px;border-radius:8px;z-index:9999;";
          document.body.appendChild(msg);
      };

      decline.onclick = () => {
        cs.socket.emit("call_decline", { call_id, from: cs.myName });
        banner.remove();
      };
  };

  window.showWhatsAppOutgoingBanner = function(toUser, isVideo){
      document.getElementById("waOutgoingBanner")?.remove();
      const banner = document.createElement("div");
      banner.id = "waOutgoingBanner";
      banner.innerHTML = `
        <div style="
          position:fixed;top:0;left:0;right:0;height:90px;
          background:linear-gradient(135deg,#25D366,#128C7E);
          color:white;display:flex;align-items:center;justify-content:space-between;
          padding:12px 20px;font-family:system-ui,sans-serif;
          box-shadow:0 2px 10px rgba(0,0,0,0.25);z-index:9999;">
          <div style="display:flex;align-items:center;gap:14px;">
            <img src="/avatar/${toUser}" style="width:56px;height:56px;border-radius:50%;
                  object-fit:cover;border:2px solid #fff;">
            <div>
              <div style="font-weight:600;font-size:18px;">Calling ${toUser}</div>
              <div id="waRingText" style="font-size:14px;opacity:.9;">Ringing...</div>
            </div>
          </div>
          <button id="waCancel" style="
            background:#d9534f;border:none;border-radius:50%;width:48px;height:48px;
            display:flex;align-items:center;justify-content:center;">❌</button>
        </div>`;
      document.body.appendChild(banner);
      document.getElementById("waCancel").onclick = () => {
        cs.socket.emit("call_decline", { to: toUser, from: cs.myName });
        banner.remove();
      };
  };

  async function sendMessage(textArg, attsArg) {
    const inputEl = document.querySelector('#msg') || document.querySelector('#textarea');
    const text = (typeof textArg === 'string') ? textArg.trim() : (inputEl ? (inputEl.value || '').trim() : '');
    const atts = Array.isArray(attsArg) ? attsArg : (cs.stagedFiles || []).slice();

    if (!text && (!atts || atts.length === 0)) return;

    try {
        let res, json;

        if (atts.length > 0) {
            // send files + text
            const fd = new FormData();
            fd.append('text', text);
            fd.append('sender', cs.myName);
            for (const f of atts) fd.append('file', f, f.name);

            res = await fetch('/send_composite_message', { method: 'POST', body: fd, credentials: 'same-origin' });
            json = await res.json().catch(() => null);

            if (res.ok && json && json.message) {
                appendMessage(json.message);
                cs.stagedFiles = [];
                if (inputEl) inputEl.value = '';
                const preview = document.getElementById('attachmentPreview') || document.getElementById('previewContainer');
                if (preview) { preview.innerHTML = ''; preview.style.display = 'none'; }
                cs.lastId = json.message.id || cs.lastId;
                return json.message;
            } else {
                cs.lastId = 0;
                if (typeof poll === 'function') await poll();
                return null;
            }
        } else {
            // send text only
            res = await fetch('/send_message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text, sender: cs.myName }),
                credentials: 'same-origin'
            });

            json = await res.json().catch(() => null);

            if (res.ok && json && json.message) {
                appendMessage(json.message);
                if (inputEl) inputEl.value = '';
                cs.stagedFiles = [];
                cs.lastId = json.message.id || cs.lastId;
                return json.message;
            } else {
                cs.lastId = 0;
                if (typeof poll === 'function') await poll();
                return null;
            }
        }
    } catch (err) {
        console.error('sendMessage error', err);
        alert('Send error: ' + (err && err.message ? err.message : err));
        return null;
    }
}

// expose globally
window.sendMessage = sendMessage;

    // === Dedup & safe append helpers ===
    window._renderedMessageIds = window._renderedMessageIds || new Set();

    // --- helpers ---
    function createOptsMenu() {
        const menu = document.createElement('div');
        menu.className = 'msg-menu';
        menu.innerHTML = '<button class="msg-action edit">Edit</button><button class="msg-action delete">Delete</button><button class="msg-action react">React</button>';
        document.body.appendChild(menu);
        return menu;
    }

    function escapeHtml(s) {
      if (s == null) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // create or return a shared message menu (single DOM node)
    function getSharedMsgMenu() {
      if (window._sharedMsgMenu) return window._sharedMsgMenu;

      const menu = document.createElement('div');
      menu.className = 'msg-menu';
      menu.style.position = 'fixed';
      menu.style.display = 'none';
      menu.style.zIndex = '100000';
      menu.innerHTML = [
        '<button class="msg-action edit">Edit</button>',
        '<button class="msg-action delete">Delete</button>',
        '<button class="msg-action react">React</button>'
      ].join('');
      document.body.appendChild(menu);

      // click handler for actions (delegated)
      menu.addEventListener('click', function(ev){
        ev.stopPropagation();
        const action = ev.target.closest('.msg-action');
        if (!action) return;
        const mid = menu.dataset.mid; // message id for which the menu was opened
        const wrapper = mid ? document.querySelector(`[data-message-id="${mid}"]`) : null;

        if (action.classList.contains('edit')) {
          const cur = wrapper ? (wrapper.querySelector('.msg-text') ? wrapper.querySelector('.msg-text').textContent : '') : '';
          const newText = prompt('Edit message:', cur);
          if (newText == null) { hideMenu(); return; }
          fetch('/edit_message', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: mid, text: newText })
          }).then(r => {
            if (r.ok && wrapper) {
              const textEl = wrapper.querySelector('.msg-text');
              if (textEl) textEl.textContent = newText;
              // mark edited if you like
              const editedFlag = wrapper.querySelector('.msg-edited');
              if (!editedFlag) {
                const sp = document.createElement('span'); sp.className='msg-edited'; sp.style.fontSize='.7rem'; sp.style.color='#9ca3af'; sp.textContent=' (edited)';
                const meta = wrapper.querySelector('.msg-meta-top');
                meta && meta.appendChild(sp);
              }
            } else {
              alert('Edit failed');
            }
          }).catch(()=>alert('Edit failed'));
        } else if (action.classList.contains('delete')) {
          if (!confirm('Delete this message?')) { hideMenu(); return; }
          fetch('/delete_message', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: mid })
          }).then(r => {
            if (r.ok && wrapper) wrapper.remove();
            else alert('Delete failed');
          }).catch(()=>alert('Delete failed'));
        } else if (action.classList.contains('react')) {
          const emoji = prompt('React with emoji (e.g. ❤️):', '👍');
          if (!emoji) { hideMenu(); return; }
          fetch('/react_message', {
            method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id: mid, emoji })
          }).then(r => {
            if (r.ok && wrapper) {
              const rspan = document.createElement('span'); rspan.className='reaction'; rspan.textContent = emoji;
              wrapper.querySelector('.msg-meta-top')?.appendChild(rspan);
            } else alert('React failed');
          }).catch(()=>alert('React failed'));
        }

        hideMenu();
      });

      function hideMenu() {
        menu.style.display = 'none';
        delete menu.dataset.mid;
      }

      // close on outside click
      document.addEventListener('click', function(){
        if (menu.style.display === 'block') hideMenu();
      });

      window._sharedMsgMenu = menu;
      return menu;
    }

    // Append message function (keeps structure consistent with your renderer)
    window.appendMessage = window.appendMessage || function appendMessage(m){
      try {
        if (!m) return;
        // numeric id expected from server, but tolerate missing
        const mid = (typeof m.id !== 'undefined') ? String(m.id) : String(Date.now());

        // prevent duplicate render
        if (typeof m.id !== 'undefined') {
          const numeric = Number(m.id);
          if (!Number.isNaN(numeric)) {
            if (window._renderedMessageIds.has(numeric)) return;
            window._renderedMessageIds.add(numeric);
          }
        }

        const me = (m.sender === (window.cs && window.cs.myName));

        // create DOM
        const wrapper = document.createElement('div');
        wrapper.className = 'msg-row';
        wrapper.dataset.messageId = mid; // used by menu positioning and later queries

        const body = document.createElement('div');
        body.className = 'msg-body';

        const meta = document.createElement('div');
        meta.className = 'msg-meta-top';
        const leftMeta = document.createElement('div');
        leftMeta.innerHTML = `<strong>${escapeHtml(m.sender||'')}</strong>`;
        const rightMeta = document.createElement('div');
        rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
        meta.appendChild(leftMeta); meta.appendChild(rightMeta);

        body.appendChild(meta);

        const bubble = document.createElement('div');
        bubble.className = 'bubble ' + (me ? 'me' : 'them');

        // message text
        const textNode = document.createElement('div');
        textNode.className = 'msg-text';
        if (m.text) {
          textNode.textContent = m.text; // use textContent to avoid HTML injection
          if (m.edited) {
            const editedSpan = document.createElement('span');
            editedSpan.className = 'msg-edited';
            editedSpan.style.fontSize = '.7rem';
            editedSpan.style.color = '#9ca3af';
            editedSpan.textContent = ' (edited)';
            textNode.appendChild(editedSpan);
          }
        }
        // --- add avatar image ---
        if (m.avatar) {
            const name = m.avatar;
            if (/^m\d+\.(webp|png|jpg|jpeg)$/i.test(name) && name.toLowerCase() !== 'm47.webp') {
                const avatarImg = document.createElement('img');
                avatarImg.src = `/static/${name}`;          // correct URL
                avatarImg.alt = 'avatar';
                avatarImg.className = 'message-avatar';
                avatarImg.style.width = '48px';            // adjust size as needed
                avatarImg.style.height = '48px';
                avatarImg.style.marginRight = '6px';
                avatarImg.style.verticalAlign = 'middle';
                avatarImg.onerror = () => {
                    avatarImg.src = '/static/m1.webp';
                    avatarImg.title = '(fallback)';
                };
                // insert before text node
                bubble.insertBefore(avatarImg, textNode);
            }
        }
        bubble.appendChild(textNode);

        (m.attachments || []).forEach(a => {
            if (!a) return;
            if (a.type === 'image') {
                // --- patch URL for local avatars ---
                let url = a.url || '';
                const name = url.split('/').pop();
                if (/^m\d+\.(webp|png|jpg|jpeg)$/i.test(name) && name.toLowerCase() !== 'm47.webp') {
                    url = `/static/${name}`;
                    a.url = url; // update original object (optional)
                }
                const img = document.createElement('img');
                img.src = url;
                img.className = 'image-attachment';
                img.alt = a.name || '';
                // fallback in case image fails
                img.onerror = () => { img.src = '/static/m1.webp'; img.title = (img.title || '') + ' (fallback)'; };
                bubble.appendChild(img);
            } else {
                const d = document.createElement('div');
                d.className = 'preview-item-doc';
                d.textContent = a.name || a.url || '';
                bubble.appendChild(d);
            }
        });

        // three-dot options button
        const menuBtn = document.createElement('button');
        menuBtn.className = 'three-dot';
        menuBtn.type = 'button';
        menuBtn.setAttribute('aria-label', 'Message options');
        menuBtn.innerText = '⋯';
        menuBtn.style.marginLeft = '8px';
        menuBtn.style.background = 'transparent';
        menuBtn.style.border = 'none';
        menuBtn.style.cursor = 'pointer';
        menuBtn.style.fontSize = '18px';
        menuBtn.style.zIndex = '20';

        // open shared menu and position it
        menuBtn.addEventListener('click', function(ev){
          ev.stopPropagation();
          const menu = getSharedMsgMenu();
          // set which message id the menu is for
          menu.dataset.mid = mid;

          // position menu near button (with viewport bounds check)
          const rect = menuBtn.getBoundingClientRect();
          menu.style.display = 'block';
          // ensure menu width is available (it may be 0 if not measured yet)
          const menuW = menu.offsetWidth || 160;
          const left = Math.min(window.innerWidth - menuW - 8, rect.right - menuW + 8);
          menu.style.left = Math.max(8, left) + 'px';
          menu.style.top = (rect.bottom + 8) + 'px';
        });

        bubble.appendChild(menuBtn);
        wrapper.appendChild(body);

        // append to messages container (choose #messages or .messages)
           const container =
              document.getElementById('messages') || document.querySelector('.messages');

            if (container) {
              container.appendChild(wrapper);
              container.scrollTop = container.scrollHeight;
            } else {
              // fallback
              document.body.appendChild(wrapper);
            }

          } catch (err) {
            console.error('appendMessage error', err);
          }
    };

    // === Socket handler — only append if not already rendered ===
    if (window.socket && typeof window.socket.on === 'function') {
      try {
        if (window.socket.off) window.socket.off('new_message');
      } catch(e){}
        window.socket.on('new_message', (m) => {
          try {
            if (!m) return;

            const mid = (typeof m.id !== 'undefined') ? Number(m.id) : null;
            if (mid === null || Number.isNaN(mid)) return;

            // Avoid duplicate rendering
            if (window._renderedMessageIds.has(mid)) return;

            // Render message instantly
            appendMessage(m);
            window._renderedMessageIds.add(mid);

            // Update lastId safely
            if (window.cs) {
              window.cs.lastId = Math.max(window.cs.lastId || 0, mid);
            }

            // ---------- Delivery & Seen Tick Logic ----------
            if (m.sender !== (window.cs?.myName || "")) {
              if (!m.seenBy || !m.seenBy.includes(window.cs.myName)) {
                fetch('/mark_seen', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ id: m.id, user: window.cs.myName })
                });
              }
            } else {
              if (m.delivered && window.messageStates[m.id] !== 'delivered') {
                updateMessageStatus(m.id, 'delivered');
              }
              if (m.seenBy?.length > 0 && window.messageStates[m.id] !== 'seen') {
                updateMessageStatus(m.id, 'seen');
              }
            }

            // Auto-scroll to bottom
            const container = document.getElementById('messages') || document.querySelector('.messages');
            if (container) container.scrollTop = container.scrollHeight;

          } catch (e) {
            console.error('socket new_message handler error', e);
          }
        });
    }

  // Attachment preview setter (exposed)
  function setAttachmentPreview(files){
    cs.stagedFiles = Array.from(files||[]);
    const preview = $id('attachmentPreview') || $id('previewContainer');
    if(!preview) return;
    preview.innerHTML = '';
    preview.style.display = cs.stagedFiles.length ? 'block' : 'none';
    cs.stagedFiles.forEach((file, idx)=>{
      const item = document.createElement('div'); item.className='preview-item';
      const removeBtn = document.createElement('button'); removeBtn.className='preview-remove-btn'; removeBtn.innerText='×';
      removeBtn.onclick = (e)=>{ e.stopPropagation(); cs.stagedFiles.splice(idx,1); setAttachmentPreview(cs.stagedFiles); };
      item.appendChild(removeBtn);
      if(file.type && file.type.startsWith('image/')){
        const img = document.createElement('img');
        const reader = new FileReader();
        reader.onload = (ev)=> img.src = ev.target.result;
        reader.readAsDataURL(file);
        item.appendChild(img);
      } else if(file.type && file.type.startsWith('video/')){
        const img = document.createElement('img'); img.className='thumb'; item.appendChild(img);
        createVideoThumbnailFromFile(file).then(dataUrl=>{ if(dataUrl) img.src = dataUrl; });
      } else if(file.type && file.type.startsWith('audio/')){
        const au = document.createElement('audio'); const url=URL.createObjectURL(file); au.src = url; au.controls=true; item.appendChild(au);
      } else {
        const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name || 'file'; item.appendChild(d);
      }
      preview.appendChild(item);
    });
  }
  window.setAttachmentPreview = setAttachmentPreview;

  // Video thumbnail helpers
  function createVideoThumbnailFromFile(file, seekTo=0.5){
    return new Promise((resolve)=>{
      const url = URL.createObjectURL(file);
      createVideoThumbnailFromUrl(url, seekTo).then((data)=>{
        URL.revokeObjectURL(url);
        resolve(data);
      }).catch(()=>{ URL.revokeObjectURL(url); resolve(null); });
    });
  }
  function createVideoThumbnailFromUrl(url, seekTo=0.5){
    return new Promise((resolve)=>{
      try{
        const video = document.createElement('video');
        video.crossOrigin = 'anonymous';
        video.src = url;
        video.muted = true; video.playsInline = true;
        video.addEventListener('loadeddata', ()=>{
          const t = Math.min(seekTo, Math.max(0, (video.duration || 1)*0.2 ));
          function seekHandler(){
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth || 320;
            canvas.height = video.videoHeight || 180;
            const ctx = canvas.getContext("2d", { willReadFrequently: true });
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const dataURL = canvas.toDataURL('image/png');
            video.remove();
            resolve(dataURL);
          }
          if(video.readyState >= 2){ video.currentTime = t; }
          else { video.addEventListener('canplay', ()=> video.currentTime = t, { once:true }); }
          video.addEventListener('seeked', seekHandler, { once:true });
          setTimeout(()=>{ try{ const canvas = document.createElement('canvas'); canvas.width=320; canvas.height=180; const ctx=canvas.getContext('2d'); ctx.fillStyle='#000'; ctx.fillRect(0,0,canvas.width,canvas.height); resolve(canvas.toDataURL()); }catch(e){ resolve(null);} }, 2500);
        }, { once:true });
        video.addEventListener('error', ()=> resolve(null));
      }catch(e){ resolve(null); }
    });
  }
  window.createVideoThumbnailFromFile = createVideoThumbnailFromFile;

    // Recording / Voice Message Helpers - fixed version
    let mediaRecorder = null;
    let micStream = null;
    let audioChunks = [];
    let recording = false;

    async function startRecording() {
      if (recording) return;
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('Microphone not supported in this browser.');
        return;
      }

      try {
        micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(micStream);
        audioChunks = [];

        mediaRecorder.addEventListener('dataavailable', e => {
          if (e.data && e.data.size) audioChunks.push(e.data);
        });

        mediaRecorder.addEventListener('stop', async () => {
          try {
            const blob = new Blob(audioChunks, { type: audioChunks[0]?.type || 'audio/webm' });
            const fileName = `voice_${Date.now()}.webm`;
            const file = new File([blob], fileName, { type: blob.type });

            // Show a preview in the attachment area instead of auto-sending
            cs.stagedFiles = [file];
            setAttachmentPreview(cs.stagedFiles);

            // Optionally show Send/Discard buttons inside preview
            showVoicePreviewControls(file);
          } catch (err) {
            console.error('Voice process error:', err);
            alert('Could not prepare voice message: ' + err.message);
          } finally {
            audioChunks = [];
          }
        });

        mediaRecorder.start();
        recording = true;
        updateMicUI(true);
      } catch (err) {
        console.error('Microphone error', err);
        alert('Could not start microphone: ' + (err.message || err));
        if (micStream) {
          micStream.getTracks().forEach(t => t.stop());
          micStream = null;
        }
        recording = false;
        updateMicUI(false);
      }
    }

    function stopRecording() {
      if (!recording) return;
      try {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
      } catch (e) {
        console.warn(e);
      }
      if (micStream) {
        micStream.getTracks().forEach(t => t.stop());
        micStream = null;
      }
      recording = false;
      updateMicUI(false);
    }

    function toggleRecording() {
      if (recording) stopRecording();
      else startRecording();
    }

    function updateMicUI(state) {
      if (!micBtn) return;
      if (state) {
        micBtn.classList.add('recording');
        micBtn.setAttribute('aria-pressed', 'true');
        micBtn.title = 'Recording… click to stop';
        micBtn.innerText = '⏸️';
      } else {
        micBtn.classList.remove('recording');
        micBtn.setAttribute('aria-pressed', 'false');
        micBtn.title = 'Record voice message';
        micBtn.innerText = '🎙️';
      }
    }

    // Show preview with playback + send/discard controls
    function showVoicePreviewControls(file) {
      const previewContainer = document.querySelector('#previewContainer');
      if (!previewContainer) return;

      // Clear old preview controls
      const oldControls = document.querySelector('.voice-controls');
      if (oldControls) oldControls.remove();

      const wrapper = document.createElement('div');
      wrapper.className = 'voice-controls';
      wrapper.style.display = 'flex';
      wrapper.style.alignItems = 'center';
      wrapper.style.gap = '8px';
      wrapper.style.marginTop = '6px';

      // Audio player
      const audio = document.createElement('audio');
      audio.controls = true;
      audio.src = URL.createObjectURL(file);
      audio.style.maxWidth = '200px';

      // Send button
      const sendBtn = document.createElement('button');
      sendBtn.textContent = 'Send';
      sendBtn.className = 'btn btn-primary';
      sendBtn.onclick = async () => {
        try {
          const fd = new FormData();
          fd.append('text', '');
          fd.append('file', file, file.name);

          const r = await fetch('/send_composite_message', { method: 'POST', body: fd });
          if (r.ok) {
            cs.stagedFiles = [];
            setAttachmentPreview([]);
            wrapper.remove();
            if (messagesEl) messagesEl.innerHTML = '';
            cs.lastId = 0;
            if (typeof window.poll === 'function') await window.poll();
          } else {
            const txt = await r.text();
            alert('Voice send failed: ' + txt);
          }
        } catch (err) {
          alert('Voice send error: ' + (err && err.message ? err.message : err));
        }
      };

      // Discard button
      const discardBtn = document.createElement('button');
      discardBtn.textContent = 'Discard';
      discardBtn.className = 'btn btn-secondary';
      discardBtn.onclick = () => {
        cs.stagedFiles = [];
        setAttachmentPreview([]);
        wrapper.remove();
      };

      wrapper.appendChild(audio);
      wrapper.appendChild(sendBtn);
      wrapper.appendChild(discardBtn);
      previewContainer.appendChild(wrapper);
    }

    // Utility: gather attachments from preview container (legacy)
    function gatherAttachments() {
      const items = document.querySelectorAll('#previewContainer .preview-item');
      const atts = [];
      items.forEach(p => {
        if (p.type === 'audio') {
          atts.push({ type: 'audio', blob: p.blob });
        }
      });
      return atts;
    }

  // Show / hide sticker panel — fixed + accessible version
    function openStickerPanel() {
      const panel = document.getElementById('stickerPanel');
      const composer = document.querySelector('.composer');

      if (!panel) return;

      // Show panel
      panel.hidden = false;
      panel.inert = false;
      panel.classList.add('active');
      panel.setAttribute('aria-hidden', 'false');

      // Move composer above the panel
      if (composer) {
        const h = panel.offsetHeight || 280;
        composer.style.bottom = `${h}px`;
      }

      // Focus first focusable item to avoid accessibility warnings
      const firstFocusable = panel.querySelector(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (firstFocusable) firstFocusable.focus();
    }

    function closeStickerPanel() {
      const panel = document.getElementById('stickerPanel');
      const composer = document.querySelector('.composer');
      const input = document.getElementById('chatInput');

      if (!panel) return;

      // Hide panel visually & from accessibility tree
      panel.classList.remove('active');
      panel.hidden = true;
      panel.inert = true;
      panel.setAttribute('aria-hidden', 'true');

      // Reset composer position
      if (composer) composer.style.bottom = '0px';

      // Move focus back to chat input to prevent focus being hidden
      if (input) input.focus();
    }

  /* ---------------------------
     WebRTC / calls
     --------------------------- */

  // small in-call UI helpers
  function showInCallUI(callId, peerName, isCaller){
    let callUi = $id('inCallUI');
    if(!callUi){
      callUi = document.createElement('div');
      callUi.id = 'inCallUI';
      callUi.style.position = 'fixed';
      callUi.style.bottom = '20px';
      callUi.style.right = '20px';
      callUi.style.zIndex = '10000';
      callUi.style.padding = '12px';
      callUi.style.background = 'rgba(0,0,0,0.8)';
      callUi.style.color = 'white';
      callUi.style.borderRadius = '10px';
      callUi.style.fontSize = '0.9rem';
      document.body.appendChild(callUi);
    }
    callUi.innerHTML = `<div>In call with <strong>${escapeHtml(peerName || '')}</strong></div><div>ID: ${escapeHtml(callId)}</div><button id="btnHangupUI">Hang Up</button>`;
    const btn = $id('btnHangupUI');
    if(btn) btn.onclick = ()=>{ hideInCallUI(); endCall(callId); };
    callUi.style.display = 'block';
  }
  function hideInCallUI(){ const ui = $id('inCallUI'); if(ui){ ui.style.display='none'; ui.innerHTML=''; } }
  window.showInCallUI = showInCallUI;
  window.hideInCallUI = hideInCallUI;

  // Peer helpers
  function getPeerForCall(callId){ return cs.calls[callId]?.peer || null; }
  function getCurrentCameraId(stream){ if(!stream) return null; const t = stream.getVideoTracks()[0]; if(!t) return null; return t.getSettings && t.getSettings().deviceId ? t.getSettings().deviceId : null; }

  function setupPeerConnection(callId, localStream, hasVideo){
    const pc = new RTCPeerConnection(cs.pcConfig);
    cs.calls[callId].pc = pc;

    if(localStream){
      localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
    }

    const remoteStream = new MediaStream();
    pc.ontrack = (evt)=>{
      evt.streams.forEach(s=> s.getTracks().forEach(t=> remoteStream.addTrack(t)));
      const remoteV = $id('remoteVideo') || (function(){ const v = document.createElement('video'); v.id='remoteVideo'; v.autoplay=true; v.playsInline=true; document.body.appendChild(v); return v; })();
      remoteV.srcObject = remoteStream;
    };

    pc.onicecandidate = (e)=>{
      if(e.candidate){
        cs.socket && cs.socket.emit && cs.socket.emit('call:candidate', { to: getPeerForCall(callId), from: cs.myName, candidate: e.candidate, call_id: callId });
      }
    };

    pc.onconnectionstatechange = ()=>{
      const st = pc.connectionState;
      console.log('pc state', st);
      if(st === 'connected') updateCallStateUI(callId, 'connected');
      if(st === 'disconnected' || st === 'failed' || st === 'closed') endCallLocal(callId, 'peer');
    };

    return pc;
  }

  async function startCall(toUser, isVideo=true){
    const callId = 'call-' + Date.now() + '-' + Math.random().toString(36).slice(2,8);
    const constraints = { audio: true, video: isVideo ? { facingMode: 'user' } : false };
    let localStream;
    try {
      localStream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch(err){
      alert('Could not access microphone/camera: ' + (err && err.message ? err.message : err));
      return;
    }
    cs.calls[callId] = { localStream, isCaller: true, pc: null, currentCameraId: getCurrentCameraId(localStream), peer: toUser };
    setupPeerConnection(callId, localStream, isVideo);
    // notify callee
    cs.socket && cs.socket.emit && cs.socket.emit('call:invite', { to: toUser, from: cs.myName, is_video: !!isVideo, call_id: callId });
    // local preview
    const lv = $id('localVideo') || (function(){ const v=document.createElement('video'); v.id='localVideo'; v.autoplay=true; v.muted=true; document.body.appendChild(v); return v; })();
    lv.srcObject = localStream; lv.style.display = isVideo ? 'block' : 'none';
    showInCallUI(callId, toUser, true);
  }
  window.startCall = startCall;

  async function toggleMute(callId){
    const call = cs.calls[callId]; if(!call || !call.localStream) return;
    call.localStream.getAudioTracks().forEach(t => { t.enabled = !t.enabled; });
    cs.socket && cs.socket.emit && cs.socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'mute', by: cs.myName, muted: !call.localStream.getAudioTracks()[0].enabled } });
  }
  async function toggleVideo(callId){
    const call = cs.calls[callId]; if(!call || !call.localStream) return;
    call.localStream.getVideoTracks().forEach(t=> t.enabled = !t.enabled);
    cs.socket && cs.socket.emit && cs.socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'video-toggled', by: cs.myName, videoOn: !!call.localStream.getVideoTracks().find(tt=>tt.enabled) } });
  }
  async function switchCamera(callId){
    const call = cs.calls[callId]; if(!call) return;
    const devices = await navigator.mediaDevices.enumerateDevices();
    const videoInputs = devices.filter(d=>d.kind==='videoinput');
    if(videoInputs.length<=1) return alert('No other camera found');
    const currentId = call.currentCameraId;
    let next = videoInputs.find(d=>d.deviceId !== currentId); if(!next) next = videoInputs[0];
    const newStream = await navigator.mediaDevices.getUserMedia({ video:{ deviceId:{ exact: next.deviceId } }, audio:false }).catch(()=>null);
    if(!newStream) return;
    const newTrack = newStream.getVideoTracks()[0];
    const pc = call.pc;
    const senders = pc.getSenders();
    const sender = senders.find(s => s.track && s.track.kind === 'video');
    if(sender) await sender.replaceTrack(newTrack);
    call.localStream.getVideoTracks().forEach(t=>{ t.stop(); call.localStream.removeTrack(t); });
    call.localStream.addTrack(newTrack);
    call.currentCameraId = next.deviceId;
    const lv = $id('localVideo'); if(lv) lv.srcObject = call.localStream;
  }

  async function shareScreen(callId){
    try{
      const screenStream = await navigator.mediaDevices.getDisplayMedia({ video:true });
      const call = cs.calls[callId]; if(!call) return;
      const screenTrack = screenStream.getVideoTracks()[0];
      const pc = call.pc;
      const senders = pc.getSenders();
      const videoSender = senders.find(s => s.track && s.track.kind === 'video');
      if(videoSender){
        await videoSender.replaceTrack(screenTrack);
        screenTrack.onended = async ()=>{
          const camStream = await navigator.mediaDevices.getUserMedia({ video:true }).catch(()=>null);
          if(camStream){
            const camTrack = camStream.getVideoTracks()[0];
            await videoSender.replaceTrack(camTrack);
            call.localStream.getVideoTracks().forEach(t=>t.stop());
            call.localStream.addTrack(camTrack);
            const lv = $id('localVideo'); if(lv) lv.srcObject = call.localStream;
          }
        };
      }
    }catch(e){ console.warn('screen share failed', e); }
  }

  function endCall(callId){
    cs.socket && cs.socket.emit && cs.socket.emit('call:hangup', { call_id: callId, from: cs.myName });
    endCallLocal(callId, cs.myName);
  }
  function endCallLocal(callId, by){
    const call = cs.calls[callId]; if(!call) return;
    try{
      if(call.pc){ call.pc.close(); call.pc = null; }
      if(call.localStream){ call.localStream.getTracks().forEach(t=>t.stop()); }
    }catch(e){}
    const lv = $id('localVideo'); if(lv) lv.srcObject = null;
    const rv = $id('remoteVideo'); if(rv) rv.srcObject = null;
    delete cs.calls[callId];
    hideInCallUI();
    alert('Call ended by ' + (by || 'local'));
  }

    // expose end/toggle functions for external UI
    window.toggleMute = toggleMute;
    window.toggleVideo = toggleVideo;
    window.switchCamera = switchCamera;
    window.endCall = endCall;
    window.shareScreen = shareScreen;

    /* ---------------------------
       Polling, rendering messages & reactions
       --------------------------- */

    async function poll() {
      try {
        const lastId = cs.lastId || 0;
        const base = (typeof window.SERVER_URL === 'string' && window.SERVER_URL)
          ? window.SERVER_URL.replace(/\/$/, '')
          : '';
        const url = base + `/poll_messages?since=${lastId}`;

        const resp = await fetch(url, { credentials: 'same-origin' });
        if (!resp.ok) {
          console.debug(`poll() -> ${resp.status}`);
          return;
        }

        const data = await resp.json();
        if (!data || !data.length) return;

        for (const m of data) {
          const mid = Number(m.id || 0);
          if (!mid) continue;

          const alreadyRendered = window._renderedMessageIds.has(mid);
          if (!alreadyRendered) {
            appendMessage(m);
            window._renderedMessageIds.add(mid);
            cs.lastId = Math.max(cs.lastId || 0, mid);
          }

          // ---------- ✅ Delivery & Seen Tick Logic ----------
          if (m.sender !== cs.myName) {
            // Mark as seen if visible
            if (!m.seenBy || !m.seenBy.includes(cs.myName)) {
              fetch('/mark_seen', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: m.id, user: cs.myName })
              });
            }
          } else {
            // Upgrade tick state for my messages
            if (m.delivered && window.messageStates[m.id] !== 'delivered') {
              updateMessageStatus(m.id, 'delivered');
            }
            if (m.seenBy && m.seenBy.length > 0 && window.messageStates[m.id] !== 'seen') {
              updateMessageStatus(m.id, 'seen');
            }
          }
        }

        // Auto-scroll handled inside appendMessage, or fallback:
        const container = document.getElementById('messages') || document.querySelector('.messages');
        if (container) container.scrollTop = container.scrollHeight;

      } catch (err) {
        console.error('poll error', err);
      }
    }

    window.poll = poll;

    /* ---------------------------
       Helper: smart popover placement
       --------------------------- */
    function positionPopover(popover, anchorRect) {
      // anchorRect: getBoundingClientRect of the message wrapper (anchor)
      const pad = 8;
      const menuW = popover.offsetWidth || 180;
      const menuH = popover.offsetHeight || 220;
      const vw = window.innerWidth;
      const vh = window.innerHeight;

      // try place to the right of anchor
      let left = Math.min(vw - menuW - pad, Math.round(anchorRect.right + pad));
      // if not enough room to right, place to left
      if (left < pad) left = Math.max(pad, Math.round(anchorRect.left - menuW - pad));
      // top: align with anchor top but ensure in viewport
      let top = Math.max(pad, Math.round(anchorRect.top));
      if (top + menuH + pad > vh) top = Math.max(pad, vh - menuH - pad);

      popover.style.left = left + 'px';
      popover.style.top = top + 'px';
    }

    /* ---------------------------
       Emoji picker (react) popover
       --------------------------- */
    function showEmojiPickerForMessage(messageId, anchorEl) {
      // remove existing
      document.querySelectorAll('.emoji-popover').forEach(n => n.remove());

      const pop = document.createElement('div');
      pop.className = 'emoji-popover';
      pop.style.position = 'absolute';
      pop.style.zIndex = 160000;
      pop.style.padding = '8px';
      pop.style.background = '#fff';
      pop.style.border = '1px solid rgba(0,0,0,0.08)';
      pop.style.boxShadow = '0 8px 24px rgba(0,0,0,0.12)';
      pop.style.borderRadius = '12px';
      pop.style.display = 'flex';
      pop.style.gap = '6px';
      pop.style.overflowX = 'auto';
      pop.style.whiteSpace = 'nowrap';
      pop.style.maxWidth = 'min(90vw, 420px)';

      const emojis = ['👍','❤️','❓','🎉','😮','😢','🤣','🔥','👏','🤔','💯'];

      emojis.forEach(emo => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'emoji-btn';
        btn.textContent = emo;
        btn.style.border = 'none';
        btn.style.background = 'transparent';
        btn.style.padding = '6px 8px';
        btn.style.borderRadius = '8px';
        btn.style.cursor = 'pointer';
        btn.style.fontSize = '18px';
        btn.style.display = 'inline-block';

        btn.onclick = async (ev) => {
          ev.stopPropagation();
          // optimistic show
          addReactionToMessageDOM(messageId, emo, (window.cs && window.cs.myName) || 'You');

          try {
            await fetch('/react_message', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: messageId, emoji: emo, user: (window.cs && window.cs.myName) })
            });
          } catch (err) {
            console.warn('react failed', err);
          } finally {
            pop.remove();
          }
        };
        pop.appendChild(btn);
      });

      document.body.appendChild(pop);
      // position
      const anchorRect = (anchorEl && anchorEl.getBoundingClientRect && anchorEl.getBoundingClientRect()) || anchorEl;
      requestAnimationFrame(() => positionPopover(pop, anchorRect));

      // close on outside click
      setTimeout(() => {
        const hide = (e) => { if (!pop.contains(e.target)) { pop.remove(); document.removeEventListener('click', hide); } };
        document.addEventListener('click', hide);
      }, 50);
    }

    /* ---------------------------
      Main: appendMessage (full)
      --------------------------- */
  function appendMessage(m) {
      try {
        if (!m) return;

        const me = m.sender === (window.cs && window.cs.myName);

        // wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'msg-row';
        wrapper.dataset.messageId = m.id;

        // body container
        const bodyContainer = document.createElement('div');
        bodyContainer.className = 'msg-body-container';
        bodyContainer.style.display = 'flex';
        bodyContainer.style.justifyContent = me ? 'flex-end' : 'flex-start';

        // message body
        const body = document.createElement('div');
        body.className = 'msg-body';
        body.style.maxWidth = '78%';

        // bubble
        const bubble = document.createElement('div');
        bubble.className = 'bubble ' + (me ? 'me' : 'them');
        bubble.style.display = 'flex';
        bubble.style.flexDirection = 'column';
        bubble.style.alignItems = 'flex-start';
        bubble.style.gap = '6px';
        bubble.style.position = 'relative';

        // meta (sender + tick area)
        const meta = document.createElement('div');
        meta.className = 'msg-meta-top';
        meta.style.display = 'flex';
        meta.style.justifyContent = 'space-between';
        meta.style.width = '100%';
        meta.style.color = '#000';
        const leftMeta = document.createElement('div');
        leftMeta.innerHTML = `<strong style="color:inherit">${escapeHtml(m.sender || '')}</strong>`;
        const rightMeta = document.createElement('div');
        rightMeta.innerHTML = me
          ? `<span class="tick-wrap" style="display:inline-block; margin-left:6px">
              <span class="tick1" style="color:#6b7280; margin-right:2px">✓</span>
              <span class="tick2" style="color:#6b7280; opacity:0; transform:scale(.8); transition: opacity .28s ease, transform .28s ease">✓</span>
            </span>`
          : '';
        meta.appendChild(leftMeta);
        meta.appendChild(rightMeta);
        bubble.appendChild(meta);

        // message text
        const hasPoll = (m.attachments || []).some(a => a && a.type === 'poll');
        if (m.text && !hasPoll) {
          const textNode = document.createElement('div');
          textNode.className = 'msg-text';
          textNode.textContent = m.text;
          if (m.edited) {
            const editedSpan = document.createElement('span');
            editedSpan.textContent = ' (edited)';
            editedSpan.style.fontSize = '.7rem';
            editedSpan.style.color = '#9ca3af';
            textNode.appendChild(editedSpan);
          }
          bubble.appendChild(textNode);
        }

        // attachments
        (m.attachments || []).forEach(a => {
          if (!a) return;

          // sticker
          if (a.type === 'sticker' || a.url?.match(/\.(webp|png|jpg|jpeg|gif)$/i)) {
            const img = document.createElement('img');
            img.src = a.url;
            img.className = 'sticker';
            img.style.maxWidth = '220px';
            img.style.borderRadius = '8px';
            img.style.marginTop = '8px';
            img.style.alignSelf = 'center';
            bubble.appendChild(img);
            return;
          }

          // poll
          if (a.type === 'poll') {
            const pollContainer = document.createElement('div');
            pollContainer.className = 'poll';
            pollContainer.style.marginTop = '8px';
            pollContainer.style.width = '100%';
            pollContainer.style.maxWidth = 'min(560px, 90vw)';
            pollContainer.style.boxSizing = 'border-box';

            const list = document.createElement('div');
            list.style.display = 'flex';
            list.style.flexDirection = 'column';
            list.style.gap = '8px';

            const counts = a.counts || new Array(a.options.length).fill(0);
            const userVoteIndex =
              a.userVoteIndex !== undefined
                ? a.userVoteIndex
                : a.userVotes && a.userVotes[(window.cs && window.cs.myName)] !== undefined
                ? a.userVotes[window.cs.myName]
                : undefined;

            a.options.forEach((op, idx) => {
              const row = document.createElement('div');
              row.className = 'poll-option-row';
              row.style.display = 'flex';
              row.style.alignItems = 'center';
              row.style.gap = '10px';
              row.style.padding = '8px';
              row.style.borderRadius = '8px';
              row.style.background = '#f3f4f6';
              row.style.cursor = 'pointer';
              row.style.transition = 'background .15s';

              const circle = document.createElement('div');
              circle.style.width = '20px';
              circle.style.height = '20px';
              circle.style.border = '2px solid #9ca3af';
              circle.style.borderRadius = '50%';
              circle.style.display = 'flex';
              circle.style.alignItems = 'center';
              circle.style.justifyContent = 'center';
              circle.style.position = 'relative';
              circle.style.flexShrink = '0';

              const fill = document.createElement('div');
              fill.style.width = '12px';
              fill.style.height = '12px';
              fill.style.borderRadius = '50%';
              fill.style.background = '#10b981';
              fill.style.transform = userVoteIndex === idx ? 'scale(1)' : 'scale(0)';
              fill.style.transition = 'transform .22s cubic-bezier(.2,.9,.2,1)';
              fill.style.transformOrigin = 'center';

              const check = document.createElement('div');
              check.style.position = 'absolute';
              check.style.fontSize = '12px';
              check.style.color = '#fff';
              check.style.opacity = userVoteIndex === idx ? '1' : '0';
              check.style.transition = 'opacity .22s';
              check.innerText = '✓';

              circle.appendChild(fill);
              circle.appendChild(check);

              const label = document.createElement('div');
              label.textContent = op;
              label.style.flex = '1';
              label.style.wordBreak = 'break-word';

              const countSpan = document.createElement('span');
              countSpan.style.display = 'none';
              countSpan.textContent = counts[idx] || 0;

              row.appendChild(circle);
              row.appendChild(label);
              row.appendChild(countSpan);

              row.addEventListener('click', async ev => {
                ev.preventDefault();
                ev.stopPropagation();

                const currentlySelected = userVoteIndex === idx || row.dataset.voted === '1';
                if (currentlySelected) {
                  fill.style.transform = 'scale(0)';
                  check.style.opacity = '0';
                  row.dataset.voted = '0';
                  try {
                    await fetch('/unvote_poll', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        message_id: m.id,
                        option: idx,
                        user: window.cs && window.cs.myName
                      })
                    });
                    cs.lastId = 0;
                    if (typeof poll === 'function') await poll();
                  } catch (err) {
                    console.warn('unvote failed', err);
                  }
                  return;
                }

                fill.style.transform = 'scale(1)';
                check.style.opacity = '1';
                Array.from(list.children).forEach(c => (c.style.pointerEvents = 'none'));
                try {
                  await fetch('/vote_poll', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      message_id: m.id,
                      option: idx,
                      user: window.cs && window.cs.myName
                    })
                  });
                  cs.lastId = 0;
                  if (typeof poll === 'function') await poll();
                } catch (err) {
                  console.warn('vote failed', err);
                  fill.style.transform = 'scale(0)';
                  check.style.opacity = '0';
                } finally {
                  Array.from(list.children).forEach(c => (c.style.pointerEvents = 'auto'));
                }
              });

              if (userVoteIndex === idx) row.dataset.voted = '1';
              else row.dataset.voted = '0';

              list.appendChild(row);
            });

            pollContainer.appendChild(list);

            const viewVotes = document.createElement('div');
            viewVotes.textContent = 'View votes';
            viewVotes.style.color = '#2563eb';
            viewVotes.style.cursor = 'pointer';
            viewVotes.style.marginTop = '8px';
            viewVotes.style.fontWeight = '600';
            viewVotes.style.alignSelf = 'flex-start';
            viewVotes.addEventListener('click', ev => {
              ev.preventDefault();
              ev.stopPropagation();
              openPollVotesDrawer(m, a);
            });
            pollContainer.appendChild(viewVotes);

            bubble.appendChild(pollContainer);
            return;
          }

          const { element } = createAttachmentElement(a) || {};
          if (element) bubble.appendChild(element);
        });

        // reactions
        if (m.reactions?.length) {
          const agg = {};
          for (const r of m.reactions) {
            agg[r.emoji] = agg[r.emoji] || new Set();
            agg[r.emoji].add(r.user);
          }
          const reactionBar = document.createElement('div');
          reactionBar.className = 'reaction-bar';
          reactionBar.style.marginTop = '6px';
          reactionBar.style.display = 'flex';
          reactionBar.style.gap = '6px';
          for (const emoji in agg) {
            const userset = agg[emoji];
            const pill = document.createElement('div');
            pill.className = 'reaction-pill';
            pill.style.background = '#fff';
            pill.style.borderRadius = '999px';
            pill.style.padding = '4px 8px';
            pill.style.display = 'flex';
            pill.style.alignItems = 'center';
            pill.style.gap = '6px';
            pill.style.boxShadow = '0 1px 2px rgba(0,0,0,0.03)';
            const em = document.createElement('div');
            em.className = 'reaction-emoji';
            em.innerText = emoji;
            const count = document.createElement('div');
            count.style.fontSize = '0.85rem';
            count.style.color = '#374151';
            count.innerText = userset.size;
            pill.appendChild(em);
            pill.appendChild(count);
            reactionBar.appendChild(pill);
          }
          bubble.appendChild(reactionBar);
        }

        // 3-dot menu button
        const menuBtn = document.createElement('button');
        menuBtn.className = 'three-dot';
        menuBtn.type = 'button';
        menuBtn.innerText = '⋯';
        menuBtn.style.border = 'none';
        menuBtn.style.background = 'transparent';
        menuBtn.style.cursor = 'pointer';
        menuBtn.style.fontSize = '18px';
        menuBtn.style.alignSelf = 'flex-end';

        menuBtn.addEventListener('click', ev => {
          ev.stopPropagation();
          document.querySelectorAll('.msg-menu-popover').forEach(n => n.remove());

          const menu = document.createElement('div');
          menu.className = 'msg-menu-popover';
          menu.style.position = 'absolute';
          menu.style.zIndex = 150000;
          menu.style.background = 'white';
          menu.style.border = '1px solid rgba(0,0,0,0.08)';
          menu.style.boxShadow = '0 8px 24px rgba(0,0,0,0.12)';
          menu.style.borderRadius = '8px';
          menu.style.padding = '8px';
          menu.style.minWidth = '150px';

          const makeItem = (text, fn) => {
            const it = document.createElement('div');
            it.textContent = text;
            it.style.padding = '6px 10px';
            it.style.cursor = 'pointer';
            it.style.borderRadius = '6px';
            it.addEventListener('click', e => {
              e.stopPropagation();
              fn();
              menu.remove();
            });
            it.addEventListener('mouseenter', () => (it.style.background = '#f3f4f6'));
            it.addEventListener('mouseleave', () => (it.style.background = 'transparent'));
            return it;
          };

          menu.appendChild(makeItem('Copy', async () => {
            navigator.clipboard.writeText(m.text || '');
          }));

          menu.appendChild(makeItem('Forward', () => {
            if (typeof sendMessage === 'function') {
              sendMessage(m.text || '', m.attachments || []);
            } else {
              navigator.clipboard.writeText(m.text || '');
              alert('Copied for forwarding');
            }
          }));

          if (m.sender === (window.cs && window.cs.myName)) {
            menu.appendChild(makeItem('Delete', async () => {
              if (!confirm('Delete this message?')) return;
              await fetch('/delete_message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: m.id })
              });
              const cont = document.getElementById('messages') || document.querySelector('.messages');
              if (cont) {
                cont.innerHTML = '';
                if (window.cs) window.cs.lastId = 0;
                if (typeof poll === 'function') poll();
              }
            }));
          }

          menu.appendChild(makeItem('React', () => showEmojiPickerForMessage(m.id, menuBtn)));

          document.body.appendChild(menu);
          const anchorRect = menuBtn.getBoundingClientRect();
          requestAnimationFrame(() => positionPopover(menu, anchorRect));
          setTimeout(() => {
            const hide = ev2 => {
              if (!menu.contains(ev2.target)) {
                menu.remove();
                document.removeEventListener('click', hide);
              }
            };
            document.addEventListener('click', hide);
          }, 50);
        });

        bubble.appendChild(menuBtn);
        body.appendChild(bubble);
        bodyContainer.appendChild(body);
        wrapper.appendChild(bodyContainer);

        const messagesEl = document.getElementById('messages') || document.querySelector('.messages');
        if (messagesEl) messagesEl.appendChild(wrapper);
        if (messagesEl) messagesEl.scrollTop = messagesEl.scrollHeight;

        if (m.status) updateMessageStatus(m.id, m.status);
      } catch (err) {
        console.error('appendMessage error', err);
      }
  }

  // createAttachmentElement: returns DOM element for an attachment
  function createAttachmentElement(a){
    const container = document.createElement('div');
    container.className = 'media-container mt-2';
    if(!a) return { element: null };

    if(a.type === 'audio' || a.type === 'voice'){
      const au = document.createElement('audio'); au.src = a.url; au.controls = true; au.className = 'mt-2';
      container.appendChild(au); return { element: container };
    }
    if(a.type === 'doc'){
      const link = document.createElement('a'); link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document');
      link.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#111827" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h11"></path><polyline points="17 2 17 8 23 8"></polyline></svg><span style="font-size:0.92rem">${escapeHtml(a.name || 'Document')}</span>`;
      container.appendChild(link); return { element: container };
    }
    if(a.type === 'location'){
      const card = document.createElement('a'); card.href = a.url || '#'; card.target = '_blank'; card.style.display='block'; card.style.maxWidth='320px'; card.style.borderRadius='10px'; card.style.overflow='hidden'; card.style.boxShadow='0 6px 18px rgba(0,0,0,0.08)'; card.style.textDecoration='none'; card.style.color='inherit';
      const img = document.createElement('img'); img.src = a.map; img.alt = 'location'; img.style.width='100%'; img.style.display='block';
      const caption = document.createElement('div'); caption.style.padding='8px'; caption.style.background = '#fff'; caption.style.fontSize = '.9rem'; caption.innerText = '📍 Shared Location';
      card.appendChild(img); card.appendChild(caption); container.appendChild(card); return { element: container };
    }
    if(a.type === 'image'){
      const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment'; img.style.maxWidth='420px'; img.style.borderRadius='10px';
      container.appendChild(img); return { element: container, mediaElement: img };
    }
    if (a.type === 'video') {
      // Treat audio containers (.webm, .mp3, .ogg, .wav) as audio, not video
      if (/\.(webm|mp3|ogg|wav)(?:\?|$)/i.test(a.url)) {
        const au = document.createElement('audio');
        au.src = a.url;
        au.controls = true;
        au.className = 'mt-2';
        container.appendChild(au);
        return { element: container };
      }

      // Otherwise, handle as video with thumbnail + click-to-play
      const thumbImg = document.createElement('img');
      thumbImg.className = 'thumb';
      thumbImg.alt = a.name || 'video';

      const playOverlay = document.createElement('div');
      playOverlay.className = 'play-overlay';
      playOverlay.innerHTML = '<div class="play-circle">▶</div>';

      container.appendChild(thumbImg);
      container.appendChild(playOverlay);

      // Try to generate a thumbnail; if fails, fallback to video
      (createVideoThumbnailFromUrl(a.url, 0.7) || Promise.resolve(null))
        .then(dataUrl => {
          if (dataUrl) {
            thumbImg.src = dataUrl;
          } else {
            const v = document.createElement('video');
            v.src = a.url;
            v.controls = true;
            v.className = 'video-attachment';
            container.innerHTML = '';
            container.appendChild(v);
          }
        })
        .catch(() => {
          const v = document.createElement('video');
          v.src = a.url;
          v.controls = true;
          v.className = 'video-attachment';
          container.innerHTML = '';
          container.appendChild(v);
        });

      container.addEventListener('click', () => {
        if (container.querySelector('video')) return;
        const v = document.createElement('video');
        v.src = a.url;
        v.controls = true;
        v.autoplay = true;
        v.playsInline = true;
        v.className = 'video-attachment';
        container.innerHTML = '';
        container.appendChild(v);
      }, { once: true });

      return { element: container, mediaElement: thumbImg };
    }
    // 🔧 NEW PATCH — treat webm with audio mime as audio, not video
    if(a.url && a.url.endsWith('.webm')){
      const au = document.createElement('audio');
      au.src = a.url;
      au.controls = true;
      au.className = 'mt-2';
      container.appendChild(au);
      return { element: container };
    }
    return { element: null };
  }
  window.createAttachmentElement = createAttachmentElement;

  /* ---------------------------
     Sticker / GIF / avatar handling & UI wiring
     --------------------------- */

  async function loadGIFs(){
    if(!panelGrid) return;
    panelGrid.innerHTML = '<div>Loading GIFs…</div>';
    try{
      const r = await fetch('https://g.tenor.com/v1/trending?limit=100');
      let data = await r.json();
      const results = data && data.results ? data.results : [];
      panelGrid.innerHTML = '';
      for(const it of results){
        const gifUrl = it.media && it.media[0] && it.media[0].gif && it.media[0].gif.url ? it.media[0].gif.url : (it.url || null);
        if(!gifUrl) continue;
        const w = document.createElement('div'); w.style.cursor='pointer';
        const img = document.createElement('img'); img.src = it.thumbnail || (it.media && it.media[0] && it.media[0].tinygif && it.media[0].tinygif.url) || gifUrl; img.style.width='100%'; img.style.borderRadius='8px';
        w.appendChild(img);
        w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url: gifUrl }] }) }); hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll(); };
        panelGrid.appendChild(w);
      }
    }catch(e){
      try{
        const r2 = await fetch('/generated_gifs');
        const list = await r2.json();
        panelGrid.innerHTML = '';
        for(const url of list){
          const w = document.createElement('div'); w.style.cursor='pointer';
          const img = document.createElement('img'); img.src = url; img.style.width='100%'; img.style.borderRadius='8px';
          w.appendChild(img);
          w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) }); hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll(); };
          panelGrid.appendChild(w);
        }
      }catch(e2){
        panelGrid.innerHTML = '<div>Error loading GIFs</div>';
      }
    }
  }
  window.loadGIFs = loadGIFs;

  async function loadAvatars(){
    if(!panelGrid) return;
    panelGrid.innerHTML = '<div>Loading avatars…</div>';
    panelGrid.innerHTML = '';
    const presets = ['hero', 'adventurer', 'brave', 'spark', 'mystic', 'dreamer', 'alpha', 'nova', 'sol', 'luna'];
    for(const seed of presets){
      const img = document.createElement('img');
      const url = `https://api.dicebear.com/9.x/adventurer/svg?seed=${encodeURIComponent(seed)}&backgroundColor=transparent`;
      const wrapper = document.createElement('div'); wrapper.style.cursor='pointer';
      img.src = url;
      img.style.width='100%'; img.style.borderRadius='8px';
      wrapper.appendChild(img);
      wrapper.onclick = async ()=> {
        await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) });
        hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll();
      };
      panelGrid.appendChild(wrapper);
    }
  }
  window.loadAvatars = loadAvatars;

  /* ---------------------------
     Typing indicator wiring (socket handlers)
     --------------------------- */

  // ensure socket handlers register only once
  function registerSocketHandlers(){
    if(!cs.socket) return;

    // typing
    cs.socket.on('typing', (d)=>{
      try{
        const nodeId = 'typing-'+(d && d.from ? d.from : 'user');
        if(document.getElementById(nodeId)) return;
        const el = document.createElement('div'); el.id = nodeId; el.className='msg-row';
        el.innerHTML = `<div class="msg-body"><div class="bubble them"><em>${escapeHtml((d && d.from) || 'Someone')} is typing…</em></div></div>`;
        messagesEl && messagesEl.appendChild(el);
        messagesEl && (messagesEl.scrollTop = messagesEl.scrollHeight);
      }catch(e){ console.warn('typing handler err', e); }
    });

    cs.socket.on('stop_typing', (d)=>{
      try{
        const nodeId = 'typing-'+(d && d.from ? d.from : 'user');
        const el = document.getElementById(nodeId); if(el) el.remove();
      }catch(e){ console.warn('stop_typing handler err', e); }
    });

    // call signaling
    cs.socket.on('call:incoming', (d) => {
      try{
        const caller = d.from;
        const callId = d.call_id;
        if(incomingCallerNameEl) incomingCallerNameEl.textContent = caller;
        if(incomingCallBanner) incomingCallBanner.classList.remove('hidden');
        cs.activeCallId = callId;
      }catch(e){ console.warn(e); }
    });

    cs.socket.on('call:accepted', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc) return;
        const offer = await call.pc.createOffer();
        await call.pc.setLocalDescription(offer);
        cs.socket.emit('call:offer', { to: d.from, from: cs.myName, sdp: offer, call_id: callId });
      }catch(e){ console.error('offer error', e); }
    });

    cs.socket.on('call:offer', async (d)=>{
      try{
        const callId = d.call_id; const fromUser = d.from;
        let localStream;
        try { localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:true }); }
        catch(e){ localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:false }).catch(()=>null); }
        cs.calls[callId] = { localStream, pc: null, isCaller: false, currentCameraId: getCurrentCameraId(localStream), peer: fromUser };
        setupPeerConnection(callId, localStream, !!(localStream && localStream.getVideoTracks().length));
        try{
          await cs.calls[callId].pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
          const answer = await cs.calls[callId].pc.createAnswer();
          await cs.calls[callId].pc.setLocalDescription(answer);
          cs.socket.emit('call:answer', { to: fromUser, from: cs.myName, sdp: answer, call_id: callId });
          showInCallUI(callId, fromUser, false);
        }catch(err){ console.error('handle offer error', err); }
      }catch(e){ console.warn('call:offer handler err', e); }
    });

    cs.socket.on('call:answer', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc) return;
        await call.pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
        updateCallStateUI(callId, 'connected');
        // optionally update server call start
      }catch(e){ console.error('call answer error', e); }
    });

    cs.socket.on('call:candidate', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc || !d.candidate) return;
        await call.pc.addIceCandidate(new RTCIceCandidate(d.candidate));
      }catch(e){ console.warn('candidate add failed', e); }
    });

    cs.socket.on('call:ended', (d)=>{
      try{ const callId = d.call_id; endCallLocal(callId, d.by); }catch(e){ console.warn(e); }
    });

    cs.socket.on('poll_update', (d)=>{
      try{
        const mid = String(d.message_id);
        const counts = d.counts || [];
        document.querySelectorAll(`.poll-option[data-message-id="${mid}"]`).forEach(btn=>{
          const idx = parseInt(btn.dataset.index, 10);
          const label = btn.dataset.label || (btn.textContent || '').split('—')[0].trim();
          const count = (counts[idx] !== undefined) ? counts[idx] : 0;
          btn.innerHTML = `${label} <span class="poll-count" style="float:right">— ${count} vote${count !== 1 ? 's' : ''}</span>`;
        });
      }catch(e){ console.warn('poll_update err', e); }
    });

    // other socket handlers (react, etc.) are handled by fetching endpoints on action
  }

  // register socket handlers once
  if(cs.socket) registerSocketHandlers();

  /* ---------------------------
     Helper: attachment selectors (file inputs)
     --------------------------- */
  function openFileSelector(camera){
    const inp = document.createElement('input'); inp.type='file'; inp.accept='image/*,video/*'; if(camera) inp.setAttribute('capture','environment');
    inp.multiple = true;
    inp.onchange = (ev)=> setAttachmentPreview(ev.target.files);
    inp.click();
  }
  function openDocSelector(){ const inp = document.createElement('input'); inp.type='file'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click(); }
  function openAudioSelector(){ const inp = document.createElement('input'); inp.type='file'; inp.accept='audio/*'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click(); }

  /* ---------------------------
     Adaptive meta color sampling (kept as in your file)
     --------------------------- */
  let _bgImg = null;
  let _bgCanvas = document.createElement('canvas');
  let _bgCtx = _bgCanvas.getContext('2d');
  let _bgDrawSize = { w: 0, h: 0 };

  async function ensureBgLoaded(){
    if(_bgImg && _bgImg.complete) return;
    return new Promise((resolve)=> {
      if(_bgImg && _bgImg.complete){ resolve(); return; }
      _bgImg = new Image();
      _bgImg.crossOrigin = 'anonymous';
      _bgImg.src = '/static/IMG_5939.jpeg';
      _bgImg.onload = ()=> resolve();
      _bgImg.onerror = ()=> resolve();
    });
  }
  function drawBgToCanvasIfNeeded(){
    const w = Math.max(1, window.innerWidth);
    const h = Math.max(1, window.innerHeight);
    if(_bgDrawSize.w === w && _bgDrawSize.h === h) return;
    _bgCanvas.width = w; _bgCanvas.height = h;
    try{
      if(_bgImg && _bgImg.complete && _bgImg.naturalWidth){
        const iw = _bgImg.naturalWidth, ih = _bgImg.naturalHeight;
        const scale = Math.max(w/iw, h/ih);
        const dw = iw * scale, dh = ih * scale;
        const dx = (w - dw) / 2, dy = (h - dh) / 2;
        _bgCtx.clearRect(0,0,w,h);
        _bgCtx.drawImage(_bgImg, 0,0, iw, ih, dx, dy, dw, dh);
      } else {
        _bgCtx.fillStyle = '#ffffff'; _bgCtx.fillRect(0,0,w,h);
      }
    }catch(e){ try{ _bgCtx.fillStyle = '#ffffff'; _bgCtx.fillRect(0,0,w,h); }catch(_){}
    }
    _bgDrawSize.w = w; _bgDrawSize.h = h;
  }
  function samplePixelAtScreenXY(x,y){
    try{
      drawBgToCanvasIfNeeded();
      const ix = Math.max(0, Math.min(_bgCanvas.width-1, Math.round(x)));
      const iy = Math.max(0, Math.min(_bgCanvas.height-1, Math.round(y)));
      const d = _bgCtx.getImageData(ix, iy, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2] };
    }catch(e){ return { r:255,g:255,b:255 }; }
  }
  function luminance(r,g,b){ return 0.299*r + 0.587*g + 0.114*b; }

  async function updateMetaColors(){
    await ensureBgLoaded();
    drawBgToCanvasIfNeeded();
    const metas = document.querySelectorAll(".msg-meta-top");
    for(const el of metas){
      const rect = el.getBoundingClientRect();
      const x = rect.left + rect.width/2;
      const y = rect.top + rect.height/2;
      const { r,g,b } = samplePixelAtScreenXY(x,y);
      const lum = luminance(r,g,b);
      el.style.color = lum > 150 ? "#111" : "#f9fafb";
    }
  }
  window.addEventListener("scroll", updateMetaColors);
  window.addEventListener("resize", ()=>{ _bgDrawSize={w:0,h:0}; updateMetaColors(); });
  setInterval(updateMetaColors, 2000);

  /* ---------------------------
     Composer elevation toggle (kept)
     --------------------------- */
  let composerMainEl = null;
  function setComposerElevated(state){ if(!composerMainEl) return; composerMainEl.classList.toggle('glass-elevated', Boolean(state)); }
  let lastTransform = '';
  setInterval(()=>{
    if(!composerMainEl) return;
    const t = window.getComputedStyle(composerMainEl).transform || '';
    if(t !== lastTransform){
      lastTransform = t;
      const isUp = !t || t === 'none' ? false : /matrix|translate/.test(t);
      setComposerElevated(isUp);
    }
  }, 250);

/* ====== Minimal helper implementations to make UI work ======
   Paste this block BEFORE your DOMContentLoaded block or above sendMessage()
   These are defensive, minimal, and practical - adapt styling/markup as needed.
*/

(function(){
  // Ensure global app state container exists
  window.cs = window.cs || { stagedFiles: [], lastId: 0, isTyping: false, typingTimer: null, socket: null, myName: 'me' };

  // Append message to messages container (used both for optimistic and incoming messages)
  window.appendMessage = function appendMessage(msg) {
      try {
        const me = msg.sender === cs.myName;
        const messagesEl = document.getElementById('messages') ||
                           document.querySelector('.messages') ||
                           document.querySelector('#chatContainer');
        if (!messagesEl) return console.warn('appendMessage: messages container not found');

        const wrapper = document.createElement('div');
        wrapper.className = msg.isSystem
          ? 'msg-row system'
          : (msg.from === cs.myName ? 'msg-row me' : 'msg-row them');

        const body = document.createElement('div');
        body.className = 'msg-body';
        const bubble = document.createElement('div');
        bubble.className = 'bubble';

        // Text content
        if (msg.text) {
          const t = document.createElement('div');
          t.className = 'msg-text';
          t.textContent = msg.text;
          bubble.appendChild(t);
        }

        // ----- Attachments -----
        if (Array.isArray(msg.attachments)) {
          msg.attachments.forEach(a => {
            if (!a) return;

            if (a.type === 'sticker' || (a.url && a.url.match(/\.(webp|gif|png|jpg|jpeg)$/i))) {
              const img = document.createElement('img');
              img.className = 'sticker-attachment';
              img.loading = 'lazy';
              img.decoding = 'async';
              img.src = a.url || a.preview || '';

              // Fallback: if WebP fails, auto-convert to PNG in-browser
              img.onerror = () => {
                if (img.src.endsWith('.webp')) {
                  const alt = img.src.replace('.webp', '.png');
                  fetch(alt, { method: 'HEAD' })
                    .then(r => { if (r.ok) img.src = alt; })
                    .catch(() => { img.style.opacity = '0.4'; });
                } else {
                  img.style.opacity = '0.4';
                }
              };

              bubble.appendChild(img);
            }

            else if (a.type === 'audio' || (a.url && a.url.match(/\.(mp3|wav|ogg|webm)$/i))) {
              const au = document.createElement('audio');
              au.controls = true;
              au.src = a.url || a.preview || '';
              bubble.appendChild(au);
            }

            else if (a.type === 'video' || (a.url && a.url.match(/\.(mp4|mov|mkv|webm)$/i))) {
              const vid = document.createElement('video');
              vid.controls = true;
              vid.playsInline = true;
              vid.muted = true;
              vid.className = 'video-attachment';
              vid.src = a.url || a.preview || '';
              bubble.appendChild(vid);
            }

            else if (a.type === 'location') {
              const link = document.createElement('a');
              link.href = a.url || '#';
              link.target = '_blank';
              link.textContent = a.url || `${a.lat},${a.lng}`;
              bubble.appendChild(link);
            }

            else {
              const d = document.createElement('div');
              d.className = 'preview-item-doc';
              d.textContent = a.name || 'file';
              bubble.appendChild(d);
            }
          });
        }
        // ---- Delivery Status (✓ system) ----
        if (msg.from === cs.myName) {
          const tick = document.createElement('span');
          tick.className = 'msg-tick';
          tick.dataset.id = msg.id;
          tick.innerHTML = '✓'; // single tick at start
          tick.style.marginLeft = '6px';
          tick.style.color = '#6b7280';
          tick.style.fontSize = '0.85rem';
          bubble.appendChild(tick);
        }

        body.appendChild(bubble);
        wrapper.appendChild(body);
        messagesEl.appendChild(wrapper);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return wrapper;

      } catch (err) {
        console.error('appendMessage error', err);
      }
  };
  window.updateMessageStatus = function (id, status) {
      const wrapper = document.querySelector(`[data-message-id="${id}"]`);
      if (!wrapper) return;

      // prefer tick-wrap
      const tickWrap = wrapper.querySelector('.tick-wrap');
      if (tickWrap) {
        const t1 = tickWrap.querySelector('.tick1');
        const t2 = tickWrap.querySelector('.tick2');
        if (!t1 || !t2) return;
        t1.style.transition = 'color .28s ease';
        t2.style.transition = 'opacity .28s ease, transform .28s ease, color .28s ease';

        if (status === 'sent') {
          t1.style.color = '#6b7280';
          t2.style.opacity = '0';
          t2.style.transform = 'scale(.8)';
        } else if (status === 'delivered') {
          t1.style.color = '#6b7280';
          t2.style.color = '#6b7280';
          t2.style.opacity = '1';
          t2.style.transform = 'scale(1)';
        } else if (status === 'seen') {
          t1.style.color = '#0ea5e9';
          t2.style.color = '#0ea5e9';
          t2.style.opacity = '1';
          t2.style.transform = 'scale(1)';
        }
        window.messageStates = window.messageStates || {};
        window.messageStates[id] = status;
        return;
      }

      // fallback to legacy .msg-tick
      const el = wrapper.querySelector(`.msg-tick[data-id="${id}"]`) || document.querySelector(`.msg-tick[data-id="${id}"]`);
      if (!el) return;
      el.style.display = 'inline-block';
      el.style.minWidth = '20px';
      el.style.transition = 'color 0.3s ease, opacity 0.3s ease';

      if (status === 'sent') {
        el.textContent = '✓'; el.style.color = '#6b7280'; el.style.opacity = '1';
      } else if (status === 'delivered') {
        el.style.opacity = '0';
        setTimeout(() => { el.textContent = '✓✓'; el.style.color = '#6b7280'; el.style.opacity = '1'; }, 150);
      } else if (status === 'seen') {
        el.textContent = '✓✓'; el.style.color = '#0ea5e9'; el.style.opacity = '1';
      }
      window.messageStates = window.messageStates || {};
      window.messageStates[id] = status;
  };

  // insertAtCursor: insert text into input/textarea at caret
  window.insertAtCursor = function insertAtCursor(input, text) {
    try {
      if (!input) return;
      if (input.selectionStart || input.selectionStart === 0) {
        const start = input.selectionStart, end = input.selectionEnd;
        const val = input.value;
        input.value = val.substring(0, start) + text + val.substring(end);
        const pos = start + text.length;
        input.selectionStart = input.selectionEnd = pos;
      } else {
        input.value += text;
      }
      // trigger input events
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.focus();
    } catch (err) { console.error('insertAtCursor error', err); }
  };

  // createVideoThumbnailFromFile(file, scale=0.7) => Promise<dataURL|string|null>
  window.createVideoThumbnailFromFile = async function createVideoThumbnailFromFile(file, scale) {
    scale = scale || 0.7;
    if (!file) return null;
    return new Promise((resolve) => {
      try {
        const url = URL.createObjectURL(file);
        const v = document.createElement('video');
        v.preload = 'metadata';
        v.muted = true;
        v.src = url;
        v.addEventListener('loadeddata', () => {
          try {
            // choose a frame ~0.5s or the middle
            const canvas = document.createElement('canvas');
            const w = v.videoWidth || 320;
            const h = v.videoHeight || 180;
            canvas.width = Math.max(1, Math.floor(w * scale));
            canvas.height = Math.max(1, Math.floor(h * scale));
            const ctx = canvas.getContext('2d');
            ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
            const data = canvas.toDataURL('image/jpeg', 0.8);
            URL.revokeObjectURL(url);
            resolve(data);
          } catch (err) {
            URL.revokeObjectURL(url);
            resolve(null);
          }
        }, { once: true });
        // timeout fallback
        setTimeout(() => { try { URL.revokeObjectURL(url); } catch(_){}; resolve(null); }, 4000);
      } catch (err) { console.error('createVideoThumbnailFromFile', err); resolve(null); }
    });
  };

  // show/hide sticker panel
  window.showStickerPanel = function showStickerPanel() {
    const panel = document.getElementById('stickerPanel') || document.querySelector('.sticker-panel');
    if (!panel) return;
    panel.classList.add('active');
    panel.style.display = panel.style.display || 'block';
    try { panel.inert = false; } catch(_) {}
  };
  window.hideStickerPanel = function hideStickerPanel() {
    const panel = document.getElementById('stickerPanel') || document.querySelector('.sticker-panel');
    if (!panel) return;
    panel.classList.remove('active');
    panel.style.display = 'none';
    try { panel.inert = true; } catch(_) {}
  };
  window.closeDrawer = window.hideStickerPanel;

  // file pickers: adds selected files to cs.stagedFiles and visits preview
  window.setAttachmentPreview = function setAttachmentPreview() {
    const preview = document.getElementById('attachmentPreview') || document.getElementById('previewContainer');
    if (!preview) return;
    preview.innerHTML = '';
    if (!Array.isArray(cs.stagedFiles) || cs.stagedFiles.length === 0) {
      preview.style.display = 'none';
      return;
    }
    preview.style.display = 'block';
    cs.stagedFiles.forEach(f => {
      const node = document.createElement('div');
      node.className = 'attachment-preview-item';
      if (f.type && f.type.startsWith('image/')) {
        const img = document.createElement('img'); img.src = URL.createObjectURL(f); img.className='preview-img';
        node.appendChild(img);
      } else {
        node.textContent = f.name || 'file';
      }
      preview.appendChild(node);
    });
  };

  // openFileSelector(camera:boolean) -> lets user pick files and stores them in cs.stagedFiles
  window.openFileSelector = function openFileSelector(camera) {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'image/*,video/*';
    if (camera) inp.capture = 'environment';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };
  window.openDocSelector = function openDocSelector() {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.pdf,.doc,.docx,.txt,application/*';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };
  window.openAudioSelector = function openAudioSelector() {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'audio/*';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };

  // Basic poll implementation: GET /poll?lastId=... or /messages?lastId=...
  window.poll = async function poll() {
    try {
      const lastId = (typeof cs.lastId !== 'undefined') ? cs.lastId : 0;
      const urls = [
        `/poll_messages?since=${lastId}`
      ];
      for (const u of urls) {
        try {
          const res = await fetch(u, { credentials: 'same-origin' });
          if (!res.ok) continue;
          const data = await res.json();
          if (!Array.isArray(data) || data.length === 0) continue;
          // render incoming messages (simple)
          for (const m of data) {
            try {
              // if messages provide id, update cs.lastId
              if (m.id && m.id > cs.lastId) cs.lastId = m.id;
              appendMessage(m);
            } catch (err) { console.error('render incoming msg error', err); }
          }
          return;
        } catch (err) {
          // try next url
        }
      }
    } catch (err) {
      console.error('poll error', err);
    }
  };

  // Register socket handlers if a socket (e.g. socket.io) exists on cs.socket
  window.registerSocketHandlers = function registerSocketHandlers() {
    try {
      const s = cs.socket;
      if (!s) return;
      // generic message handler
      if (typeof s.on === 'function') {
        s.on('message', (m) => {
          appendMessage(m);
        });
        s.on('connect', () => console.log('socket connected'));
        s.on('typing', (d) => console.log('peer typing', d));
      }
    } catch (err) { console.error('registerSocketHandlers', err); }
  };

    // === MICROPHONE TOGGLE ===
    window.toggleRecording = async function toggleRecording() {
      try {
        const micBtn = document.getElementById('micBtn') || document.querySelector('.mic-button');
        const micIcon = micBtn?.querySelector('i');

        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          return alert('Audio recording not supported in this browser.');
        }

        // --- START RECORDING ---
        if (!window._mediaRecorder || window._mediaRecorder.state === 'inactive') {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
          window._chunks = [];
          window._mediaRecorder = new MediaRecorder(stream);

          window._mediaRecorder.ondataavailable = (ev) => {
            if (ev.data && ev.data.size) window._chunks.push(ev.data);
          };

          window._mediaRecorder.onstop = async () => {
            const blob = new Blob(window._chunks, { type: 'audio/webm' });
            const file = new File([blob], `recording-${Date.now()}.webm`, { type: blob.type });

            // Add to stagedFiles (preview will show but not auto-send)
            cs.stagedFiles.push(file);
            setAttachmentPreview();

            // Clean up
            window._mediaRecorder = null;
            window._chunks = [];
          };

          window._mediaRecorder.start();
          console.log('Recording started');

          // Change mic icon to stop
          if (micIcon) {
            micIcon.classList.remove('fa-microphone');
            micIcon.classList.add('fa-stop');
          }

        } else if (window._mediaRecorder.state === 'recording') {
          // --- STOP RECORDING ---
          window._mediaRecorder.stop();
          console.log('Recording stopped and saved to stagedFiles');

          // Change icon back to mic
          if (micIcon) {
            micIcon.classList.remove('fa-stop');
            micIcon.classList.add('fa-microphone');
          }
        }

      } catch (err) {
        console.error('toggleRecording error', err);
        alert('Recording failed: ' + err.message);
      }
    };

})(); // end helper IIFE

 /* ---------------------------
   Event wiring on DOMContentLoaded - single point of initialization
   --------------------------- */
  document.addEventListener('DOMContentLoaded', () => {
    'use strict';
    try {
      window._renderedMessageIds = window._renderedMessageIds || new Set();

      // assign DOM refs (use const/let to avoid globals)
      const emojiBtn = $id('emojiBtn') || $id('emoji') || document.querySelector('.emoji-button') || document.querySelector('#emojiBtn');
      const composer = document.querySelector('.composer');
      const textarea = $id('msg') || $id('textarea');
      const inputEl = textarea;
      window.inputEl = inputEl || null;
      const micBtn = $id('micBtn') || $id('mic') || document.querySelector('.mic-button');
      const plusBtn = $id('plusBtn');
      const attachMenuVertical = $id('attachMenuVertical') || (function () {
        const el = document.createElement('div');
        el.style.display = 'none';
        // ensure querySelectorAll exists (fallback)
        el.querySelectorAll = () => [];
        return el;
      })();
      const sendBtn = $id('sendBtn');
      const emojiDrawer = $id('stickerPanel') || $id('emojiDrawer');
      const messagesEl = $id('messages');
      const composerEl = $id('composer');
      const composerMainEl = $id('composerMain') || document.querySelector('.composer-main');
      const panel = $id('stickerPanel');
      const panelGrid = $id('panelGrid');
      const incomingCallBanner = $id('incomingCallBanner');
      const incomingCallerNameEl = $id('incomingCallerName');
      const acceptCallBtn = $id('acceptCallBtn');
      const declineCallBtn = $id('declineCallBtn');
      const inCallControls = $id('inCallControls');
      const btnHangup = $id('btnHangup');
      const btnMute = $id('btnMute');
      const btnToggleVideo = $id('btnToggleVideo');
      const btnSwitchCam = $id('btnSwitchCam');

      window.appendMessage = function appendMessage(m) {
        try {
          if (!m || typeof m.id === 'undefined') return;
          const mid = Number(m.id);
          if (window._renderedMessageIds.has(mid)) return; // skip duplicate
          window._renderedMessageIds.add(mid);

          const me = (m.sender === cs.myName);

          // Wrapper row
          const wrapper = document.createElement('div');
          wrapper.className = 'msg-row';

          // Message body
          const body = document.createElement('div');
          body.className = 'msg-body';

          // Meta (sender + tick)
          const meta = document.createElement('div');
          meta.className = 'msg-meta-top';
          const leftMeta = document.createElement('div');
          leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong>`;
          const rightMeta = document.createElement('div');
            if (me) {
              const tick = document.createElement('span');
              tick.className = 'tick';

              if (m.local || m.status === 'sending') {
                tick.textContent = '✓'; // single tick (local send)
                tick.style.color = '#888';
              } else if (m.seenBy && m.seenBy.length >= (window.totalUsers - 1)) {
                tick.textContent = '✓✓'; // blue double ticks
                tick.style.color = '#1E90FF';
              } else {
                tick.textContent = '✓✓'; // gray double ticks
                tick.style.color = '#666';
              }

              rightMeta.appendChild(tick);
            }
          meta.appendChild(leftMeta);
          meta.appendChild(rightMeta);
          body.appendChild(meta);

          // Bubble
          const bubble = document.createElement('div');
          bubble.className = 'bubble ' + (me ? 'me' : 'them');

          // Text
          if (m.text && m.text.trim().length > 0) {
            const textNode = document.createElement('div');
            textNode.innerHTML =
              escapeHtml(m.text) +
              (m.edited ? '<span style="font-size:.7rem;color:#9ca3af">(edited)</span>' : '');
            bubble.appendChild(textNode);
          }

          // Attachments
          (m.attachments || []).forEach(a => {
            if (a.type === 'sticker') {
              const s = document.createElement('img');
              s.src = a.url;
              s.className = 'sticker';
              s.style.marginTop = '8px';
              s.style.maxWidth = '180px';
              s.style.borderRadius = '8px';
              bubble.appendChild(s);
            } else if (a.type === 'image' || (a.url && a.url.match(/\.(jpg|jpeg|png|gif|webp)$/i))) {
              const img = document.createElement('img');
              img.src = a.url;
              img.className = 'image-attachment';
              img.style.opacity = m.status === 'sending' ? '0.6' : '1';
              bubble.appendChild(img);

            } else if (a.type === 'video') {
              const v = document.createElement('video');
              v.src = a.url;
              v.controls = true;
              v.autoplay = false;
              v.playsInline = true;
              v.className = 'video-attachment';
              v.style.borderRadius = '8px';
              v.style.maxWidth = '300px';
              v.style.opacity = m.status === 'sending' ? '0.6' : '1';
              bubble.appendChild(v);

            } else if (a.type === 'poll') {
              const pollEl = document.createElement('div');
              pollEl.className = 'poll';
              pollEl.style.marginTop = '8px';

              if (m.text && m.text.trim()) {
                const qEl = document.createElement('div');
                qEl.style.fontWeight = '600';
                qEl.style.marginBottom = '6px';
                qEl.textContent = m.text;
                pollEl.appendChild(qEl);
              }

              const counts = a.counts || new Array(a.options.length).fill(0);
              a.options.forEach((opt, i) => {
                const btn = document.createElement('button');
                btn.className = 'poll-option w-full px-3 py-2 rounded bg-gray-100 text-left';
                const count = counts[i] || 0;
                btn.innerHTML = `${opt} <span class="poll-count" style="float:right">— ${count} vote${count !== 1 ? 's' : ''}</span>`;
                btn.dataset.messageId = m.id;
                btn.dataset.index = i;
                btn.addEventListener('click', async (ev) => {
                  ev.preventDefault();
                  try {
                    await fetch('/vote_poll', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ message_id: m.id, option: i, user: cs.myName })
                    });
                    cs.lastId = 0;
                    if (typeof poll === 'function') await poll();
                  } catch (err) {
                    console.warn('vote failed', err);
                  }
                });
                pollEl.appendChild(btn);
              });
              bubble.appendChild(pollEl);
            } else {
              const d = document.createElement('div');
              d.className = 'preview-item-doc';
              d.textContent = a.name || (a.url || 'file');
              bubble.appendChild(d);
            }
          });

          // Reactions
          if (m.reactions && m.reactions.length) {
            const agg = {};
            m.reactions.forEach(r => {
              agg[r.emoji] = agg[r.emoji] || new Set();
              agg[r.emoji].add(r.user);
            });

            const reactionBar = document.createElement('div');
            reactionBar.className = 'reaction-bar';
            for (const emoji in agg) {
              const userset = agg[emoji];
              const pill = document.createElement('div');
              pill.className = 'reaction-pill';
              const em = document.createElement('div');
              em.className = 'reaction-emoji';
              em.innerText = emoji;
              const count = document.createElement('div');
              count.style.fontSize = '0.85rem';
              count.style.color = '#374151';
              count.innerText = userset.size;
              pill.appendChild(em);
              pill.appendChild(count);
              reactionBar.appendChild(pill);
            }
            bubble.appendChild(reactionBar);
          }

          // 3-dot menu
          const menuBtn = document.createElement('button');
          menuBtn.className = 'three-dot';
          menuBtn.innerText = '⋯';
          menuBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            showMessageMenu(m, menuBtn);
          });
          bubble.appendChild(menuBtn);

          body.appendChild(bubble);
          wrapper.appendChild(body);

          // Append to messages container
          const messagesElLocal = document.getElementById('messages') || document.querySelector('.messages');
          if (messagesElLocal) {
            messagesElLocal.appendChild(wrapper);
            messagesElLocal.scrollTop = messagesElLocal.scrollHeight;
          }
        } catch (err) {
          console.error('appendMessage error', err);
        }
        if (!me) observeMessageSeen(wrapper, m);
      };

      // click outside handlers to close drawers/panels
      document.addEventListener('click', (ev) => {
        const insidePanel = ev.target && ev.target.closest && ev.target.closest('#stickerPanel');
        const insideComposer = ev.target && ev.target.closest && ev.target.closest('.composer');
        const clickedEmojiBtn = ev.target && ev.target.closest && ev.target.closest('#emojiBtn');

        if (!insidePanel && !insideComposer && !clickedEmojiBtn) {
          if (emojiDrawer) emojiDrawer.classList.remove('active');
          if (composer && composer.style) composer.style.bottom = '0px';
          if (attachMenuVertical) attachMenuVertical.style.display = 'none';
        }
      });

      // sticker panel close button
      const closeStickerPanelBtn = $id('closeStickerPanel');
      if (closeStickerPanelBtn) closeStickerPanelBtn.addEventListener('click', hideStickerPanel);

      // tabs: stickers / gifs / avatars / emoji
      const tab_stickers = $id('tab_stickers');
      const tab_gifs = $id('tab_gifs');
      const tab_avatars = $id('tab_avatars');
      const tab_emoji = $id('tab_emoji');

      if (tab_stickers) {
        tab_stickers.addEventListener('click', async () => {
          if (typeof loadStickers === 'function') await loadStickers();
        });
      }
      if (tab_gifs) {
        tab_gifs.addEventListener('click', async () => {
          if (typeof loadGIFs === 'function') await loadGIFs();
        });
      }
      if (tab_avatars) {
        tab_avatars.addEventListener('click', async () => {
          if (typeof loadAvatars === 'function') await loadAvatars();
        });
      }
      if (tab_emoji && emojiBtn) {
        tab_emoji.addEventListener('click', () => { emojiBtn.click(); });
      }

      // sticker picker button (show panel)
      const stickerPickerBtn = $id('stickerPickerBtn');
      if (stickerPickerBtn) stickerPickerBtn.addEventListener('click', () => showStickerPanel && showStickerPanel());

      // attach menu (plus button)
      if (plusBtn && attachMenuVertical) {
        // toggle menu
        plusBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const showing = window.getComputedStyle(attachMenuVertical).display === 'flex';
          attachMenuVertical.style.display = showing ? 'none' : 'flex';
          attachMenuVertical.style.flexDirection = 'column';
          if (!showing) {
            // auto-hide on next scroll
            window.addEventListener('scroll', () => { attachMenuVertical.style.display = 'none'; }, { once: true });
          }
        });

        // click outside closes menu
        document.addEventListener('click', (ev) => {
          if (!ev.target.closest('#attachMenuVertical') && !ev.target.closest('#plusBtn')) {
            attachMenuVertical.style.display = 'none';
          }
        });

        // attach-card actions (delegation)
        attachMenuVertical.addEventListener('click', async (ev) => {
          const card = ev.target.closest('.attach-card');
          if (!card) return;
          const action = card.dataset.action;
          attachMenuVertical.style.display = 'none';

          try {
            if (action === 'camera') openFileSelector && openFileSelector(true);
            else if (action === 'gallery') openFileSelector && openFileSelector(false);
            else if (action === 'document') openDocSelector && openDocSelector();
            else if (action === 'audio') openAudioSelector && openAudioSelector();
            else if (action === 'location') {
              if (!navigator.geolocation) return alert('Geolocation not supported.');
              navigator.geolocation.getCurrentPosition(async (pos) => {
                const lat = pos.coords.latitude.toFixed(6);
                const lng = pos.coords.longitude.toFixed(6);
                const url = `https://www.google.com/maps?q=${lat},${lng}`;
                const mapImg = `https://static-maps.yandex.ru/1.x/?ll=${lng},${lat}&size=600,300&z=15&l=map&pt=${lng},${lat},pm2rdm`;
                try {
                  await fetch('/send_message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: '', attachments: [{ type: 'location', lat, lng, url, map: mapImg }] }),
                    credentials: 'same-origin'
                  });
                  cs.lastId = 0;
                  if (typeof poll === 'function') await poll();
                } catch (err) { console.error('send location error', err); }
              }, (err) => { alert('Could not get location: ' + err.message); });
            }
          } catch (err) {
            console.error('attach action error', err);
            alert('Attach action failed: ' + (err.message || err));
          }
        });
      }

      // poll modal wiring
      const pollBtn = $id('pollBtn');
      if (pollBtn) pollBtn.addEventListener('click', () => {
        const modal = $id('pollModal');
        if (modal) { modal.style.display = 'block'; modal.classList.remove('hidden'); }
      });
      const cancelPoll = $id('cancelPoll');
      if (cancelPoll) cancelPoll.addEventListener('click', () => {
        const modal = $id('pollModal');
        if (modal) { modal.style.display = 'none'; modal.classList.add('hidden'); }
      });
      const addPollOption = $id('addPollOption');
      if (addPollOption) addPollOption.addEventListener('click', () => {
        const container = $id('pollOptions'); if (!container) return;
        if (container.querySelectorAll('input[name="option"]').length >= 12) return alert('Max 12 options');
        const inp = document.createElement('input');
        inp.name = 'option';
        inp.placeholder = 'Option ' + (container.querySelectorAll('input[name="option"]').length + 1);
        inp.className = 'w-full p-2 border rounded mb-2';
        container.appendChild(inp);
      });
      const pollForm = $id('pollForm');
      if (pollForm) pollForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const q = ($id('poll_question') && $id('poll_question').value || '').trim();
        const opts = Array.from(document.querySelectorAll('input[name="option"]')).map(i => i.value.trim()).filter(v => v);
        if (!q || opts.length < 2) return alert('Question and at least 2 options required');
        await fetch('/send_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: q, attachments: [{ type: 'poll', options: opts }] }) });
        const modal = $id('pollModal'); if (modal) { modal.style.display = 'none'; modal.classList.add('hidden'); }
        const container = document.getElementById('messages') || document.querySelector('.messages');
        if (container) container.innerHTML = '';
        cs.lastId = 0;
        await poll();
      });

      // message send wiring
      if (sendBtn) {
        try { sendBtn.removeAttribute && sendBtn.removeAttribute('onclick'); } catch (_) {}
        sendBtn.addEventListener('click', async (e) => {
          e && e.preventDefault && e.preventDefault();
          e && e.stopPropagation && e.stopPropagation();
          if (typeof window.sendMessage === 'function') {
            try { await window.sendMessage(); } catch (err) { console.error('sendBtn -> sendMessage failed', err); }
          } else {
            console.warn('sendBtn clicked but sendMessage not ready');
          }
        });
      }

      if (inputEl) {
        inputEl.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            if (sendBtn) sendBtn.click();
          }
        });

        // typing indicator
        inputEl.addEventListener('input', () => {
          if (!cs.isTyping && cs.socket) { cs.socket.emit('typing', { from: cs.myName }); cs.isTyping = true; }
          clearTimeout(cs.typingTimer);
          cs.typingTimer = setTimeout(() => {
            if (cs.isTyping && cs.socket) { cs.socket.emit('stop_typing', { from: cs.myName }); cs.isTyping = false; }
          }, 1200);
        });
      }

      // micButton behavior
      if (micBtn) {
          let micBusy = false;
          micBtn.addEventListener('click', async (ev) => {
            ev.preventDefault();
            if (micBusy) return;
            micBusy = true;
            try {
              if (typeof toggleRecording === 'function') {
                await toggleRecording();
              } else if (typeof toggleMic === 'function') {
                await toggleMic();
              } else {
                console.warn('No recording function found');
              }
            } catch (err) {
              console.error('Mic click error:', err);
            } finally {
              setTimeout(() => { micBusy = false; }, 400); // debounce
            }
          });

          // Optional keyboard accessibility
          micBtn.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' || ev.key === ' ') {
              ev.preventDefault();
              micBtn.click();
            }
          });
      }

      // legacy send binding (if page uses different references)
      const legacySend = $id('sendBtn');
      if (legacySend && legacySend !== sendBtn) {
        legacySend.addEventListener('click', async () => {
          const text = (inputEl ? (inputEl.value || '').trim() : '');
          if (!text && cs.stagedFiles.length === 0) return;
          await (sendMessage && sendMessage());
        });
      }

      // profile toggles
      const profileBtn = $id('profileBtn');
      if (profileBtn) profileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const menu = $id('profileMenu');
        if (menu) { menu.classList.toggle('hidden'); menu.style.display = menu.classList.contains('hidden') ? 'none' : 'block'; }
      });
      const viewProfileBtn = $id('viewProfileBtn');
      if (viewProfileBtn) viewProfileBtn.addEventListener('click', async () => {
        const menu = $id('profileMenu'); if (menu) { menu.classList.add('hidden'); menu.style.display = 'none'; }
        const modal = $id('profileModal'); if (modal) { modal.classList.remove('hidden'); }
        try {
          const r = await fetch('/profile_get');
          if (r.ok) {
            const j = await r.json();
            $id('profile_display_name') && ($id('profile_display_name').value = j.name || '');
            $id('profile_status') && ($id('profile_status').value = j.status || '');
          }
        } catch (err) { console.error('profile fetch error', err); }
      });
      const closeProfile = $id('closeProfile'); if (closeProfile) closeProfile.addEventListener('click', () => { const modal = $id('profileModal'); if (modal) modal.classList.add('hidden'); });
      const profileCancel = $id('profileCancel'); if (profileCancel) profileCancel.addEventListener('click', () => { const modal = $id('profileModal'); if (modal) modal.classList.add('hidden'); });

      // ------------------- GOOGLE MEET CALL FLOW -------------------

        // quick DOM helpers
        function $id(id) { return document.getElementById(id); }
        function showEl(id){ const e = $id(id); if(e) e.classList.remove('hidden'); }
        function hideEl(id){ const e = $id(id); if(e) e.classList.add('hidden'); }

        // UI elements
        const onlineUsersModal = $id('onlineUsersModal');
        const onlineUsersList = $id('onlineUsersList');
        const closeOnlineUsers = $id('closeOnlineUsers');
        const meetShareBox = $id('meetShareBox'); // a small div with input+button (see below)
        const meetShareInput = $id('meetShareInput');
        const meetShareBtn = $id('meetShareBtn');

        // header call buttons
        const audioBtn = $id('audioCallBtn');
        const videoBtn = $id('videoCallBtn');
        if(audioBtn) audioBtn.addEventListener('click', e => { e.preventDefault(); openOnlineUsers('audio'); });
        if(videoBtn) videoBtn.addEventListener('click', e => { e.preventDefault(); openOnlineUsers('video'); });

        // internal state
        let pendingCallType = 'audio';
        let pendingTargetUser = null;
        let pendingCallId = null;

        // open modal of online users
        function openOnlineUsers(type) {
          pendingCallType = type || 'audio';
          pendingTargetUser = null;

          // Clear old list while waiting
          onlineUsersList.innerHTML = '<div style="padding:12px;color:#666">Loading online users...</div>';

          // Send fresh request to server
          cs.socket && cs.socket.emit && cs.socket.emit('get_online_users');

          // Set a short timeout to show modal after data arrives
          showEl('onlineUsersModal');
        }

        // Handle new list from server
        cs.socket && cs.socket.on && cs.socket.on('online_users', (data) => {
          try {
            const users = (data && data.users) ? data.users.slice() : [];
            onlineUsersList.innerHTML = '';

            if (!users.length) {
              onlineUsersList.innerHTML = '<div style="padding:12px;color:#666">No users online</div>';
              return;
            }

            users.sort();
            for (const u of users) {
              if (!u || u === cs.myName) continue; // skip self
              const tile = document.createElement('div');
              tile.className = 'online-user-tile';
              tile.innerHTML = `
                <div style="width:40px;height:40px;border-radius:50%;background:#eef;display:flex;align-items:center;justify-content:center;font-weight:700">
                  ${escapeHtml(u[0] || 'U')}
                </div>
                <div style="flex:1">${escapeHtml(u)}</div>
                <div style="font-size:.9rem;opacity:.85">
                  ${pendingCallType === 'video' ? 'Video' : 'Audio'}
                </div>`;

              tile.addEventListener('click', () => startMeetCall(u));
              onlineUsersList.appendChild(tile);
            }
          } catch (err) {
            console.warn('online_users render error', err);
            onlineUsersList.innerHTML = '<div style="padding:12px;color:#c00">Error loading users</div>';
          }
        });

        closeOnlineUsers && closeOnlineUsers.addEventListener('click', ()=> hideEl('onlineUsersModal') );

        // caller starts Meet call
        function startMeetCall(username){
          pendingTargetUser = username;
          pendingCallId = 'call-' + Date.now() + '-' + Math.random().toString(36).slice(2,8);
          hideEl('onlineUsersModal');

          // notify server a call is starting
          cs.socket.emit('call_outgoing', { to: username, from: cs.myName, isVideo: (pendingCallType==='video') });

          // open Meet in new tab
          window.open('https://meet.google.com/new', '_blank');

          // show local box to paste/share link
          showEl('meetShareBox');
          meetShareInput.value = '';
        }

        // when user clicks share
        meetShareBtn && meetShareBtn.addEventListener('click', () => {
          const link = meetShareInput.value.trim();
          if(!link || !pendingTargetUser) return alert('Paste the Meet link first.');
          cs.socket.emit('share_meet_invite', {
            call_id: pendingCallId,
            to: pendingTargetUser,
            from: cs.myName,
            url: link
          });
          hideEl('meetShareBox');
          alert('Meet link sent to ' + pendingTargetUser);
        });

        // receiver sees banner
        cs.socket.on('incoming_meet_invite', data => {
          const { from, url, call_id } = data;
          const banner = document.createElement('div');
          banner.className = 'incoming-meet-banner';
          banner.innerHTML = `
            <div class="banner-content">
              <span><b>${escapeHtml(from)}</b> is inviting you to a Meet call</span>
              <div class="banner-actions">
                <button id="acceptMeetBtn" class="accept-btn">✅ Accept</button>
                <button id="declineMeetBtn" class="decline-btn">❌ Decline</button>
              </div>
            </div>`;
          document.body.appendChild(banner);

          $id('acceptMeetBtn').onclick = () => {
            cs.socket.emit('meet_accept', { call_id, url });
            banner.remove();
            window.open(url, '_blank');
          };
          $id('declineMeetBtn').onclick = () => {
            cs.socket.emit('meet_decline', { call_id });
            banner.remove();
          };
        });

        // caller & callee get this when accepted
        cs.socket.on('open_meet', d => {
          if(!d || !d.url) return;
          window.open(d.url, '_blank');
        });

      // close emoji/other drawers on background click
      document.addEventListener('click', (ev) => {
        if (ev.target && ev.target.closest && !ev.target.closest('.composer') && !ev.target.closest('#stickerPanel')) {
          emojiDrawer && emojiDrawer.classList.remove('active');
          composer && composer.classList.remove('up');
          attachMenuVertical && (attachMenuVertical.style.display = 'none');
        }
      });

      // start initial poll and periodic polling
      cs.lastId = 0;
      if (typeof poll === 'function') {
        poll();
        setInterval(() => { try { poll(); } catch (err) { console.error('poll error', err); } }, 2000);
      }

      // register socket handlers now (if socket was created earlier)
      if (cs.socket && typeof registerSocketHandlers === 'function') registerSocketHandlers();

    } catch (err) {
      console.error('Initialization error', err);
    }

  }); // end DOMContentLoaded

  /* ---------------------------
     Other small helpers
     --------------------------- */

  function insertAtCursor(el, text){
    try{
      const start = el.selectionStart || 0;
      const end = el.selectionEnd || 0;
      const val = el.value || '';
      el.value = val.slice(0,start) + text + val.slice(end);
      const pos = start + text.length;
      el.selectionStart = el.selectionEnd = pos;
    }catch(e){ /* ignore */ }
  }
  window.insertAtCursor = insertAtCursor;

  // prompt for peer and begin call (used by header buttons)
  async function promptForPeerAndCall(isVideo){
    let peer = null;
    // attempt to infer
    const headerEl = $id('header') || document.querySelector('.chat-header') || document.querySelector('.header');
    if(headerEl && headerEl.dataset && headerEl.dataset.peer) peer = headerEl.dataset.peer;
    if(!peer){
      const titleEl = $id('chatTitle') || document.querySelector('.chat-title') || document.querySelector('.title .username');
      if(titleEl && titleEl.textContent && titleEl.textContent.trim()){
        const txt = titleEl.textContent.trim();
        if(txt && txt !== cs.myName) peer = txt;
      }
    }
    if(!peer){
      const rows = document.querySelectorAll('#messages .msg-row');
      for(let i=rows.length-1;i>=0;i--){
        const strong = rows[i].querySelector('.msg-meta-top strong') || rows[i].querySelector('strong');
        if(strong && strong.textContent){
          const name = strong.textContent.trim();
          if(name && name !== cs.myName){ peer = name; break; }
        }
      }
    }
    if (!peer) {
      // don't prompt — open the online users modal so user can pick from currently online contacts
      if (typeof openOnlineUsers === 'function') {
        openOnlineUsers(isVideo ? 'video' : 'audio');
      } else {
        // fallback: if modal function isn't present, bail out quietly
        console.warn('openOnlineUsers not available; cannot start call without peer');
      }
      return;
    }
    try {
      await startCall(peer, !!isVideo);
    } catch (err) {
      console.error('startCall failed', err);
      alert('Could not start call: ' + (err && err.message ? err.message : err));
    }
  }
  window.promptForPeerAndCall = promptForPeerAndCall;

  // updateCallStateUI stub
  function updateCallStateUI(callId, state){ /* placeholder - extend as needed */ console.log('call state', callId, state); }

})(); // end IIFE


// NOTE: The following functions are intentionally outside the IIFE (as in your original).
// They remain unchanged in behavior and placement.

async function loadStickers(){
  try {
    const res = await fetch('/stickers_list');
    if(!res.ok) throw new Error("Failed to load stickers");
    const stickers = await res.json();

    const container = document.getElementById('stickersContainer');
    if(!container) return;

    container.innerHTML = '';
    stickers.forEach(url=>{
      const img = document.createElement('img');
      img.src = url;
      img.alt = "sticker";
      img.className = "w-16 h-16 m-1 cursor-pointer rounded shadow";
      img.onclick = ()=> insertSticker(url);
      container.appendChild(img);
    });
  } catch(err){
    console.error("Sticker load error:", err);
  }
}

function insertSticker(url){
  const textarea = document.getElementById('chatInput');
  if(textarea){
    textarea.value += ` [sticker:${url}] `;
    textarea.focus();
  }
}
function showMessageMenu(ev, menuBtn, wrapper, m) {
  ev.stopPropagation();
  // remove existing
  document.querySelectorAll('.msg-menu-popover').forEach(n => n.remove());

  // build menu
  const menu = document.createElement('div');
  menu.className = 'msg-menu-popover';
  menu.style.minWidth = '150px';
  menu.style.background = '#fff';
  menu.style.border = '1px solid rgba(0,0,0,0.08)';
  menu.style.boxShadow = '0 8px 24px rgba(0,0,0,0.12)';
  menu.style.borderRadius = '10px';
  menu.style.padding = '8px';
  menu.style.zIndex = 150000;

  const makeItem = (text, fn) => {
    const it = document.createElement('div');
    it.textContent = text;
    it.style.padding = '8px 10px';
    it.style.cursor = 'pointer';
    it.style.borderRadius = '8px';
    it.addEventListener('mouseenter', () => it.style.background = '#f3f4f6');
    it.addEventListener('mouseleave', () => it.style.background = 'transparent');
    it.addEventListener('click', (e) => { e.stopPropagation(); fn(); menu.remove(); });
    return it;
  };

  menu.appendChild(makeItem('Copy', () => navigator.clipboard.writeText(m.text || '')));
  menu.appendChild(makeItem('Forward', () => {
    // resend message to chat (text + attachments if any)
    if (typeof sendMessage === 'function') {
      const atts = (m.attachments || []).map(a => {
        // if attachments are in-server attachments, you might prefer to forward as links
        return a;
      });
      // sendMessage(text, attachments) — attachments here depends on your sendMessage implementation
      sendMessage(m.text || '', atts);
    } else {
      console.warn('sendMessage not available to forward');
    }
  }));

  // Delete only allowed for own messages
  if (m.sender === (window.cs && window.cs.myName)) {
    menu.appendChild(makeItem('Delete', async () => {
      if (!confirm('Delete this message?')) return;
      try {
        await fetch('/delete_message', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ id: m.id }) });
        // refresh messages list or remove element
        const container = document.getElementById('messages') || document.querySelector('.messages');
        if (container) { container.innerHTML = ''; if (typeof poll === 'function') poll(); }
      } catch (err) { console.warn('delete failed', err); }
    }));
  }

  menu.appendChild(makeItem('React', () => {
    // open emoji picker anchored to menuBtn
    showEmojiPickerForMessage(m.id, menuBtn);
  }));

  document.body.appendChild(menu);
  // position it relative to the button's bounding rect (anchor to menuBtn)
  const anchorRect = menuBtn.getBoundingClientRect();
  requestAnimationFrame(() => positionPopover(menu, anchorRect));

  // close on outside click
  setTimeout(() => {
    const hide = (e) => { if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click', hide); } };
    document.addEventListener('click', hide);
  }, 50);
}

function positionPopover(menu, anchorRect) {
  // anchorRect should be a DOMRect from the button (getBoundingClientRect())
  const pad = 8;
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  // measure menu after it's in the DOM
  const mRect = menu.getBoundingClientRect();
  const menuW = mRect.width || 180;
  const menuH = mRect.height || 160;

  // calculate absolute coords
  const absLeft = anchorRect.left + window.scrollX;
  const absRight = anchorRect.right + window.scrollX;
  const absTop = anchorRect.top + window.scrollY;
  const absBottom = anchorRect.bottom + window.scrollY;

  // try place below the anchor, aligned to anchor's right edge, but adjust to fit in viewport
  let left = absRight - menuW; // align right edge of menu to anchor right
  if (left < window.scrollX + pad) left = absLeft; // fallback to left align
  if (left + menuW > window.scrollX + vw - pad) left = window.scrollX + vw - menuW - pad;
  if (left < window.scrollX + pad) left = window.scrollX + pad;

  // prefer below anchor
  let top = absBottom + pad;
  // if not enough space below, try above anchor
  if (top + menuH > window.scrollY + vh - pad) {
    top = absTop - menuH - pad;
    if (top < window.scrollY + pad) top = window.scrollY + pad; // clamp
  }

  menu.style.left = left + 'px';
  menu.style.top = top + 'px';
  menu.style.position = 'absolute';
}

function observeMessageSeen(msgEl, msg) {
  if (!msgEl || !msg.id) return;
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        fetch('/mark_seen', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: msg.id, user: cs.myName })
        }).catch(console.warn);
        observer.disconnect();
      }
    });
  });
  observer.observe(msgEl);
}
if (cs.stagedFiles && cs.stagedFiles.length) {
  const file = cs.stagedFiles[0];
  const url = URL.createObjectURL(file);
  const type = file.type.startsWith('video')
    ? 'video'
    : file.type.startsWith('audio')
      ? 'audio'
      : 'image';
  const localMsg = {
    id: 'local-' + Date.now(),
    sender: cs.myName,
    text: document.querySelector('#msg')?.value || '',
    attachments: [{ type, url }],
    local: true,
    status: 'sending',
  };
  appendMessage(localMsg); // use your message-render function
}

function openPollVotesDrawer(m, pollData) {
  let drawer = document.getElementById('pollVotesDrawer');
  if (!drawer) {
    drawer = document.createElement('div');
    drawer.id = 'pollVotesDrawer';
    drawer.style.position = 'fixed';
    drawer.style.right = '0';
    drawer.style.top = '0';
    drawer.style.height = '100%';
    drawer.style.width = '340px';
    drawer.style.background = '#fff';
    drawer.style.boxShadow = '-3px 0 10px rgba(0,0,0,0.15)';
    drawer.style.transition = 'transform .3s ease';
    drawer.style.transform = 'translateX(100%)';
    drawer.style.overflowY = 'auto';
    drawer.style.zIndex = '99999';
    document.body.appendChild(drawer);
  }

  drawer.innerHTML = `
    <div style="padding:16px; font-weight:600; border-bottom:1px solid #eee">${m.text || 'Poll votes'}</div>
    <div style="padding:12px;">
      ${pollData.options.map((op, i) => `
        <div style="margin-top:12px;">
          <div style="font-weight:500;">${op}</div>
          ${(pollData.voters?.[i] || []).map(v => `
            <div style="display:flex; align-items:center; gap:8px; margin-top:6px;">
              <img src="${v.avatar || '/static/m1.webp'}" style="width:28px;height:28px;border-radius:50%;object-fit:cover;">
              <div>${v.name}</div>
            </div>
          `).join('') || '<div style="color:#888; font-size:0.9em;">No votes yet</div>'}
        </div>
      `).join('')}
    </div>
  `;
  requestAnimationFrame(() => drawer.style.transform = 'translateX(0)');
}
</script>
<script>
(async function drawerMic_v4_infinite_patched() {
  'use strict';

  // ---------- Helpers & elements ----------
  let drawer = document.querySelector('#emojiDrawer');
  if (!drawer) {
    drawer = document.createElement('div');
    drawer.id = 'emojiDrawer';
    Object.assign(drawer.style, {
      position: 'fixed', left: 0, right: 0, bottom: 0,
      height: '45vh', background: '#fff',
      borderTopLeftRadius: '14px', borderTopRightRadius: '14px',
      boxShadow: '0 -10px 40px rgba(0,0,0,0.15)',
      display: 'none', zIndex: '99999', overflowY: 'auto'
    });
    document.body.appendChild(drawer);
  }

  const composer = document.querySelector('.composer') || document.querySelector('.composer-main') || document.getElementById('composer');
  const emojiBtn = document.querySelector('#emojiBtn');
  const micBtn = document.querySelector('#micBtn') || document.querySelector('.mic-button');

  function shiftComposer() {
    if (!composer) return;
    requestAnimationFrame(() => {
      const h = drawer.style.display === 'block' ? drawer.offsetHeight || Math.round(window.innerHeight * 0.45) : 0;
      composer.style.bottom = h ? (h + 8) + 'px' : '0';
    });
  }

  // ---------- Drawer markup (keeps search placement) ----------
  drawer.innerHTML = `
    <div id="drawerHeader" style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:1px solid #eee;">
      <div>
        <button data-tab="sticker">🙋‍♂️ Stickers</button>
        <button data-tab="gif">🎞️ Gif's</button>
        <button data-tab="avatar">🤾‍♂️ Avatars</button>
      </div>
      <button id="drawerClose" style="background:transparent;border:0;cursor:pointer">✕</button>
    </div>
    <div id="drawerSearch" style="padding:6px 12px;display:none;">
      <input id="drawerSearchInput" type="text" placeholder="Search Stickers or GIFs..." style="width:100%;padding:6px 8px;border:1px solid #ccc;border-radius:6px;">
    </div>
    <div id="drawerBody" style="padding:10px;overflow-y:auto;max-height:calc(45vh - 90px);display:flex;flex-wrap:wrap;gap:8px;justify-content:center;"></div>
  `;

  const body = drawer.querySelector('#drawerBody');
  const searchWrapper = drawer.querySelector('#drawerSearch');
  const searchInput = drawer.querySelector('#drawerSearchInput');

  // Prevent clicks inside drawer from bubbling (so outside click closes only when appropriate)
  drawer.addEventListener('click', e => e.stopPropagation());
  if (searchInput) {
    searchInput.addEventListener('click', e => e.stopPropagation());
    searchInput.addEventListener('focus', e => { e.stopPropagation(); shiftComposer(); });
  }

  // ---------- Sticker sources: user avatars (m1..m20, a1..a20) + moving-sticker generators ----------
  const avatarStickers = [];

  // Fetch current user info from backend
  let userIsOwner = false;
  try {
      const res = await fetch("/api/current_user");
      if (res.ok) {
        const data = await res.json();
        userIsOwner = data.is_owner === true;
      }
    } catch (err) {
      console.warn("Could not get user info:", err);
    }

    // Build sticker list based on ownership
    for (let i = 1; i <= 78; i++) {
      if (i === 47) continue; // skip missing file
      const prefix = userIsOwner ? "m" : "a";
      avatarStickers.push(`/static/${prefix}${i}.webp`);
  }

  const GIPHY_IDS = [
    '26BRzozg4TCBXv6QU','l0MYC0LajbaPoEADu','3oEjI6SIIHBdRxXI40','ASd0Ukj0y3qMM',
    'xT9IgG50Fb7Mi0prBC','3oEjHP8ELRNNlnlLGM','yFQ0ywscgobJK','5ntdy5Ban1dIY',
    '3o7TKtnuHOHHUjR38Y','3o6ZtaO9BZHcOjmErm','l4pTfx2qLszoacZRS','3oKIPwoeGErMmaI43S',
    '3ohzdIuqJoo8QdKlnW','3o6gbbuLW76jkt8vIc','3o7aD2saalBwwftBIY','xTiTnHv0j8TxmI2dWk',
    '3o6ZsXwPZ0kHeCtYxC','3o6Mb4ct0p5m3A1R1O','3o7aD2saalBwwftBIY','l0Exk8EUzSLsrErEQ',
    'l0HlOvJ7yaacpuSas','3oEduQAsYcJKQH2XsI','3oFzmkk9QGqzW3mGkQ','3o6Zt6D4u2Z2rjW7W0',
    '3o6Ztqk0kV3b3xYg7e','3o6Zt8s7K9k8kd7f8g','3o7aD2saalBwwftABC','3o7btQv5x8h3tYg0Xe',
    '3o7aE6bqfK0xpl2xgk','3o7aD2saa9BwwftB12','3o6ZtaO9BZHcOjmErm'
  ];
  const TENOR_IDS = [
    'Z0G3b1I5ZoYwq','fUa1B2b4kMZb2','b8l3e7Oa1qQw','b1Yb2o3qA5pL',
    'N2b3F8v9XzqH','k1J8s3PqRwN6','6f3c2d1bA8gH'
  ];

  // Combined sticker-id pool (use for moving stickers too)
  const STICKER_ID_POOL = GIPHY_IDS.concat(TENOR_IDS);

  // GIF pool for the gif tab (bigger now)
  const GIF_ID_POOL = GIPHY_IDS.concat([
    '3o7aD2saalBwwftBIY','xT0BKqhdlKCxCNsVd6','3o7aCSPqXE9XhbnBCk','l0ExnX0bQx0q4o1wM',
    '3o6Zt8s7K9k8kd7f8g','3o6Ztqk0kV3b3xYg7e','3o6ZtaO9BZHcOjmErm','l0MYt5jPR6QX5pnqM','3oEjX8Q3q5w6'
  ]);

  // URL patterns to vary returned GIFs/stickers
  const GIF_PATTERNS = [
    id => `https://media.giphy.com/media/${id}/giphy.gif`,
    id => `https://media.giphy.com/media/${id}/giphy-downsized.gif`,
    id => `https://media.giphy.com/media/${id}/giphy-preview.gif`,
    id => `https://media.tenor.com/images/${id}/tenor.gif`,
    id => `https://c.tenor.com/${id}.gif`
  ];

  // generator helpers
  let stickerCursor = 0;
  function generateStickerURL(index) {
    // first avatars already handled by loadedItems flow; here generate moving sticker GIF URLs
    const poolIndex = index % STICKER_ID_POOL.length;
    const id = STICKER_ID_POOL[poolIndex];
    const pattern = GIF_PATTERNS[(index + stickerCursor) % GIF_PATTERNS.length];
    // slightly mix in index to vary mapping
    stickerCursor = (stickerCursor + 1) % 97;
    return pattern(id);
  }

  let gifCursor = 0;
  function nextGifURL(i) {
    const id = GIF_ID_POOL[(gifCursor + i) % GIF_ID_POOL.length];
    const pattern = GIF_PATTERNS[(gifCursor + i) % GIF_PATTERNS.length];
    // advance cursor occasionally to vary sequence
    if ((gifCursor + i) % 13 === 0) gifCursor = (gifCursor + 5) % GIF_ID_POOL.length;
    return pattern(id);
  }

  // ---------- Infinite loader state ----------
  let currentTab = 'sticker'
  let loadedItems = [];   // items currently loaded (URLs)
  let pageIndex = 0;
  const PAGE_SIZE = 40;

  function clearBody() {
    body.innerHTML = '';
    loadedItems = [];
    pageIndex = 0;
  }

  // ensure we have enough items in loadedItems for the next page
  function ensureItemsForPage() {
    const need = (pageIndex + 1) * PAGE_SIZE;
    while (loadedItems.length < need) {
      const nextIndex = loadedItems.length;
      if (currentTab === 'sticker') {
        const genIndex = nextIndex;
        loadedItems.push(generateStickerURL(genIndex));
      } else if (currentTab === 'gif') {
        const genIndex = nextIndex;
        loadedItems.push(nextGifURL(genIndex));
      } else if (currentTab === 'avatar'){
        if (nextIndex < avatarStickers.length) {
          const genIndex = nextIndex;
          loadedItems.push(avatarStickers[nextIndex]);
      } else {
        break;
        };
      }
    }
  }

  // render the next page
  function renderPage() {
    ensureItemsForPage();
    const start = pageIndex * PAGE_SIZE;
    const slice = loadedItems.slice(start, start + PAGE_SIZE);
    slice.forEach(src => {
      const wrapper = document.createElement('div');
      Object.assign(wrapper.style, {
        width: currentTab === 'gif' ? '140px' : '96px',
        height: '96px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        cursor: 'pointer',
        borderRadius: '8px',
        overflow: 'hidden',
        background: '#fafafa'
      });

      const img = document.createElement('img');
      img.loading = 'lazy';
      img.src = src;
      img.style.maxWidth = '100%';
      img.style.maxHeight = '100%';
      img.style.objectFit = 'cover';
      img.onerror = () => {
        img.style.opacity = '0.45';
      };

      wrapper.appendChild(img);

      wrapper.addEventListener('click', async (ev) => {
        ev.stopPropagation();
        try {
          await fetch('/send_message', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              text: '',
              attachments: [{ type: currentTab === 'sticker' ? 'sticker' : 'gif', url: src }]
            })
          });
          if (typeof poll === 'function') { cs.lastId = 0; poll(); }
        } catch (err) {
          console.warn('send failed', err);
        }
      });

      body.appendChild(wrapper);
    });
    pageIndex++;
  }

  // infinite scroll
  body.addEventListener('scroll', () => {
    const nearBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 120;
    if (nearBottom) renderPage();
  });

  // ---------- Search only filters loadedItems (keeps search bar DOM position) ----------
  if (searchInput) {
    let searchTimer = null;
    searchInput.addEventListener('input', () => {
      const q = (searchInput.value || '').trim().toLowerCase();
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        body.innerHTML = '';
        if (!q) {
          pageIndex = 0;
          renderPage();
          return;
        }
        const filtered = loadedItems.filter(u => (u || '').toLowerCase().includes(q)).slice(0, 200);
        filtered.forEach(src => {
          const img = document.createElement('img');
          img.src = src;
          img.style.width = currentTab === 'gif' ? '140px' : '84px';
          img.style.margin = '6px';
          img.style.cursor = 'pointer';
          img.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            try {
              await fetch('/send_message', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: '', attachments: [{ type: currentTab === 'sticker' ? 'sticker' : 'gif', url: src }] })
              });
              if (typeof poll === 'function') { cs.lastId = 0; poll(); }
            } catch (err) { console.warn(err); }
          });
          body.appendChild(img);
        });
      }, 180);
    });
  }

  // ---------- Tabs wiring ----------
  const tabs = drawer.querySelectorAll('#drawerHeader [data-tab]');
  tabs.forEach(btn => btn.addEventListener('click', () => {
      tabs.forEach(b => b.style.background = '');
      btn.style.background = '#f1f1f1';
      currentTab = btn.dataset.tab;

      // show search only for sticker, avatar, gif
      searchWrapper.style.display = (currentTab === 'sticker' || currentTab === 'avatar' || currentTab === 'gif') ? 'block' : 'none';

      clearBody();

      if (currentTab === 'sticker') {
        loadedItems = []; pageIndex = 0;
        ensureItemsForPage(); renderPage();
      } else if (currentTab === 'avatar') {
        loadedItems = []; pageIndex = 0;
        ensureItemsForPage(); renderPage();
      } else if (currentTab === 'gif') {
        loadedItems = []; pageIndex = 0;
        ensureItemsForPage(); renderPage();
      }

      shiftComposer();
  }));


  drawer.querySelector('#drawerClose').onclick = () => { drawer.style.display = 'none'; shiftComposer(); };

  if (emojiBtn) {
    emojiBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = drawer.style.display === 'block';
      drawer.style.display = open ? 'none' : 'block';
      if (!open) {
        const stickTab = Array.from(tabs).find(x => x.dataset.tab === 'sticker') || tabs[0];
        stickTab.click();
      } else {
        shiftComposer();
      }
    });
  }

  // ---------- MIC RECORDER (unchanged) ----------
  if (micBtn) {
    const ICON_START = '🎙️';
    const ICON_PAUSE = '⏸️';
    micBtn.textContent = ICON_START;
    window.updateMicUI = window.updateMicUI || function (recording) {
      try {
        micBtn.textContent = recording ? ICON_PAUSE : ICON_START;
        micBtn.style.color = recording ? '#fff' : '';
      } catch (e) {}
    };

    function renderAudioPreviewAndStage(file) {
      window.cs = window.cs || {};
      window.cs.stagedFiles = [file];
      let preview = document.getElementById('attachmentPreview') || document.getElementById('previewContainer');
      if (!preview) {
        preview = document.createElement('div');
        preview.id = 'attachmentPreview';
        if (composer) composer.appendChild(preview);
        else document.body.appendChild(preview);
      }
      Array.from(preview.querySelectorAll('audio,video')).forEach(n => n.remove());
      const au = document.createElement('audio');
      au.controls = true;
      au.src = URL.createObjectURL(file);
      au.style.maxWidth = '260px';
      au.style.display = 'block';
      preview.appendChild(au);
    }

    let mediaRecorder = null;
    let micStream = null;

    micBtn.addEventListener('click', async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (mediaRecorder && mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
        return;
      }
      try {
        micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const chunks = [];
        mediaRecorder = new MediaRecorder(micStream);
        window.mediaRecorder = mediaRecorder;
        mediaRecorder.onstart = () => window.updateMicUI(true);
        mediaRecorder.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
        mediaRecorder.onstop = () => {
          window.updateMicUI(false);
          try { micStream.getTracks().forEach(t => t.stop()); } catch (e) {}
          micStream = null;
          const blob = new Blob(chunks, { type: 'audio/webm' });
          const file = new File([blob], `voice-${Date.now()}.webm`, { type: 'audio/webm' });
          renderAudioPreviewAndStage(file);
        };
        mediaRecorder.onerror = (ev) => { console.warn('mediaRecorder error', ev); };
        mediaRecorder.start();
      } catch (err) {
        console.error('mic error', err);
        try { window.updateMicUI(false); } catch (e) {}
        alert('Mic error: ' + (err && err.message ? err.message : err));
      }
    });
  }

// === UNIVERSAL PATCH: three-dot menu (works on new messages + external emoji bar) ===
(() => {
  /* === helper: add reaction === */
  window.addReactionToMessageDOM = function (messageId, emoji) {
    const msgRow = document.querySelector(`.msg-row[data-message-id="${messageId}"]`);
    if (!msgRow) return;
    const bubble = msgRow.querySelector('.bubble');
    if (!bubble) return;

    let bar = bubble.querySelector('.reaction-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.className = 'reaction-bar';
      bar.style.marginTop = '6px';
      bar.style.display = 'flex';
      bar.style.flexWrap = 'wrap';
      bar.style.gap = '6px';
      bubble.appendChild(bar);
    }

    let pill = Array.from(bar.children).find(p => p.dataset.emoji === emoji);
    if (!pill) {
      pill = document.createElement('div');
      pill.dataset.emoji = emoji;
      pill.className = 'reaction-pill';
      pill.style.background = '#fff';
      pill.style.borderRadius = '999px';
      pill.style.padding = '4px 8px';
      pill.style.display = 'flex';
      pill.style.alignItems = 'center';
      pill.style.gap = '6px';
      pill.style.boxShadow = '0 1px 2px rgba(0,0,0,0.03)';

      const e = document.createElement('div');
      e.className = 'reaction-emoji';
      e.innerText = emoji;
      const c = document.createElement('div');
      c.style.fontSize = '0.85rem';
      c.style.color = '#374151';
      c.innerText = '1';
      pill.appendChild(e);
      pill.appendChild(c);
      bar.appendChild(pill);
    } else {
      const c = pill.querySelector('div:last-child');
      c.innerText = String(Number(c.innerText || '0') + 1);
    }
  };

  /* === style tweak: meta row expands bubble properly (single line) === */
  const style = document.createElement('style');
  style.textContent = `
    /* force meta row into single line and let bubble expand */
    .msg-meta-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      /* prevent wrapping so it's one straight line */
      flex-wrap: nowrap !important;
      width: 100%;
      /* don't force wrapping; allow overflow if necessary */
      white-space: nowrap;
      overflow: hidden;
    }
    /* prevent child shrinking problems in flex */
    .msg-meta-top > * { min-width: 0; }

    /* ensure bubble can expand vertically if needed */
    .bubble {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .emoji-floating-bar {
      position: absolute;
      background: #fff;
      border: 1px solid rgba(0,0,0,0.1);
      border-radius: 12px;
      padding: 6px 10px;
      box-shadow: 0 4px 18px rgba(0,0,0,0.15);
      display: flex;
      gap: 8px;
      z-index: 999999;
    }
    .emoji-floating-bar button {
      border: none;
      background: transparent;
      font-size: 20px;
      cursor: pointer;
    }
    .emoji-floating-bar button:hover { transform: scale(1.2); }
  `;
  document.head.appendChild(style);

  /* === binding function (works for new and old messages) === */

  // robust extractors to handle different message shapes
  const extractTextFromMsg = (m, msgRow) => {
    if (!m && !msgRow) return '';
    // try many likely properties
    const candidates = [
      m?.text, m?.body, m?.message, m?.content, m?.html,
      // some apps use `textContent`, `msg`, or `payload`
      m?.textContent, m?.msg, m?.payload?.text
    ];
    for (const c of candidates) {
      if (typeof c === 'string' && c.trim()) return c.trim();
    }
    // parts/blocks arrays
    if (Array.isArray(m?.parts)) {
      const joined = m.parts.map(p => (p?.text || p?.body || p?.content || '')).filter(Boolean).join('\n').trim();
      if (joined) return joined;
    }
    // attachments may have captions
    if (Array.isArray(m?.attachments)) {
      const captions = m.attachments.map(a => a?.caption || a?.title || '').filter(Boolean).join('\n').trim();
      if (captions) return captions;
    }
    // fallback to DOM text (if available)
    if (msgRow) {
      const bubble = msgRow.querySelector('.bubble');
      if (bubble) {
        // try common DOM selectors
        const domTextSelectors = ['.text', '.msg-text', '.message-text', '.content', '.bubble-text'];
        for (const s of domTextSelectors) {
          const el = bubble.querySelector(s);
          if (el && el.innerText && el.innerText.trim()) return el.innerText.trim();
        }
        const raw = bubble.innerText || '';
        if (raw.trim()) return raw.trim();
      }
    }
    return '';
  };

  const extractAttachmentsFromMsg = (m) => {
    if (!m) return [];
    return (
      m.attachments ||
      m.files ||
      m.media ||
      m.images ||
      m._attachments ||
      m?.attachments_list ||
      []
    );
  };

  window.attachThreeDotMenus = function () {
    document.querySelectorAll('.three-dot').forEach(btn => {
      if (btn.dataset.bound === '1') return;
      btn.dataset.bound = '1';

      btn.addEventListener('click', ev => {
        ev.stopPropagation();
        document.querySelectorAll('.msg-menu-popover, .emoji-floating-bar').forEach(p => p.remove());

        const msgRow = btn.closest('.msg-row');
        if (!msgRow) return;
        const msgId = msgRow.dataset.messageId;
        const msg = (window.cs?.messages || []).find(x => String(x.id) === String(msgId) || String(x._id) === String(msgId) || String(x.message_id) === String(msgId));

        const menu = document.createElement('div');
        menu.className = 'msg-menu-popover';
        menu.style.position = 'absolute';
        menu.style.background = '#fff';
        menu.style.border = '1px solid rgba(0,0,0,0.08)';
        menu.style.borderRadius = '8px';
        menu.style.boxShadow = '0 8px 24px rgba(0,0,0,0.12)';
        menu.style.padding = '8px';
        menu.style.minWidth = '150px';
        menu.style.zIndex = 999999;

        const makeItem = (label, fn) => {
          const i = document.createElement('div');
          i.textContent = label;
          i.style.padding = '6px 10px';
          i.style.cursor = 'pointer';
          i.style.borderRadius = '6px';
          i.addEventListener('mouseenter', () => i.style.background = '#f3f4f6');
          i.addEventListener('mouseleave', () => i.style.background = 'transparent');
          i.addEventListener('click', e => { e.stopPropagation(); fn(); });
          return i;
        };

        menu.appendChild(makeItem('Copy', () => {
          const txt = extractTextFromMsg(msg, msgRow) || '';
          navigator.clipboard.writeText(txt);
          alert('Copied!');
          menu.remove();
        }));

        menu.appendChild(makeItem('Forward', async () => {
          try {
            const text = extractTextFromMsg(msg, msgRow);
            const attachments = extractAttachmentsFromMsg(msg) || [];

            if (!text && attachments.length === 0) {
              alert('Nothing to forward (empty message).');
              menu.remove();
              return;
            }

            const payload = { sender: window.cs?.myName || 'unknown', text: text, attachments: attachments };
            const res = await fetch('/send_message', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });

            if (res.ok && typeof poll === 'function') poll();
            else {
              console.warn('Forward failed', res.status, await res.text());
              alert('Forward failed (see console).');
            }
          } catch (e) {
            console.error('Forward error', e);
            alert('Forward error (see console).');
          }
          menu.remove();
        }));

        menu.appendChild(makeItem('Delete', async () => {
          if (!confirm('Delete this message?')) return;
          try {
            await fetch('/delete_message', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: msgId })
            });
            msgRow.remove();
          } catch (e) { console.error('Delete failed', e); alert('Delete failed (see console).'); }
          menu.remove();
        }));

        // React option — opens separate floating emoji bar
        menu.appendChild(makeItem('React', () => {
          const rect = btn.getBoundingClientRect();
          const bar = document.createElement('div');
          bar.className = 'emoji-floating-bar';
          ['😀','😂','😍','👍','🔥','😮','😢','👏','❤️'].forEach(em => {
            const b = document.createElement('button');
            b.textContent = em;
            b.onclick = async e => {
              e.stopPropagation();
              addReactionToMessageDOM(msgId, em);
              try {
                await fetch('/react_message', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ id: msgId, emoji: em, user: window.cs?.myName })
                });
              } catch {}
              bar.remove();
            };
            bar.appendChild(b);
          });
          document.body.appendChild(bar);
          const scrollY = window.scrollY || document.documentElement.scrollTop;
          const scrollX = window.scrollX || document.documentElement.scrollLeft;
          bar.style.top = `${rect.bottom + scrollY + 6}px`;
          bar.style.left = `${rect.left + scrollX - 20}px`;

          const closeBar = e => {
            if (!bar.contains(e.target)) {
              bar.remove();
              document.removeEventListener('click', closeBar);
            }
          };
          setTimeout(() => document.addEventListener('click', closeBar), 100);
        }));

        document.body.appendChild(menu);

        const rect = btn.getBoundingClientRect();
        const scrollY = window.scrollY || document.documentElement.scrollTop;
        const scrollX = window.scrollX || document.documentElement.scrollLeft;
        menu.style.top = `${rect.bottom + scrollY + 4}px`;
        menu.style.left = `${rect.left + scrollX - 100}px`;

        const close = e => {
          if (!menu.contains(e.target)) {
            menu.remove();
            document.removeEventListener('click', close);
          }
        };
        setTimeout(() => document.addEventListener('click', close), 50);
      });
    });
  };

  /* initial bind */
  window.attachThreeDotMenus();

  /* observer to auto-bind new messages */
  const observer = new MutationObserver(() => window.attachThreeDotMenus());
  observer.observe(document.body, { childList: true, subtree: true });
})();

})();

// Inside your chat app frontend (runs in the browser)
window.addEventListener('message', (ev) => {
  // Only trust your own main site origin
  if (ev.origin !== 'http://127.0.0.1:5010' && ev.origin !== 'https://your-game-app.example')
    return;

  const { type, token } = ev.data || {};
  if (type === 'init') {
    // Send token to your backend for validation
    fetch('/api/auth/validate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ token })
    })
    .then(r => r.json())
    .then(data => {
      if (data.ok) {
        // Initialize chat using the user info
        initializeChat(data.user);
      }
    });
  }
});

</script>
</body>
</html>
'''

# --------- Routes & API ----------
@app.context_processor
def util():
    return dict(load_user=lambda name: load_user_by_name(name))

@app.route("/")
def index():
    first = load_first_user() is None
    return render_template_string(LOGIN_HTML, first_user_none=first, heading_img=HEADING_IMG)

@app.route("/profile_get")
def profile_get():
    username = flask_session.get('username')
    if not username: return jsonify({"error":"not signed in"}), 401
    u = load_user_by_name(username)
    return jsonify({"name": u['name'], "status": u.get('status',''), "avatar": u.get('avatar')})

@app.route("/profile_update", methods=["POST"])
def profile_update():
    username = flask_session.get('username')
    if not username: return "not signed in", 401
    new_name = request.form.get('name', '').strip() or None
    status = request.form.get('status', None)
    avatar_file = request.files.get('avatar')
    avatar_url = None
    if avatar_file and avatar_file.filename:
        fn = secure_filename(avatar_file.filename)
        save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
        path = os.path.join(app.static_folder, save_name)
        avatar_file.save(path)
        avatar_url = url_for('static', filename=save_name)
    conn = db_conn(); c = conn.cursor()
    if new_name and new_name != username:
        c.execute("UPDATE users SET name = ? WHERE name = ?", (new_name, username))
        c.execute("UPDATE messages SET sender = ? WHERE sender = ?", (new_name, username))
        username = new_name
    if avatar_url:
        c.execute("UPDATE users SET avatar = ? WHERE name = ?", (avatar_url, username))
    if status is not None:
        c.execute("UPDATE users SET status = ? WHERE name = ?", (status, username))
    conn.commit(); conn.close()
    flask_session['username'] = username
    return jsonify({"status":"ok"})

@app.route("/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    name = body.get("name", "").strip()
    passkey = body.get("passkey")

    if not name or not passkey:
        return "Missing username or passkey", 400

    # --- Step 1: Allow only if no users exist yet ---
    first_user = load_first_user()
    if first_user is not None:
        # Prevent registration after the first user is created
        return jsonify({"error": "Registration closed. The first user already exists."}), 403

    # --- Step 2: Create the first (owner) user ---
    salt, hash_val = hash_pass(passkey)
    save_user(name, salt, hash_val, make_owner=True)

    # --- Step 3: Clear session and log them in immediately ---
    flask_session.clear()
    flask_session["username"] = name
    touch_user_presence(name)

    app.logger.info(f"First user registered: {name}")
    return jsonify({"status": "ok", "owner": True})

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    name = body.get("name", "").strip()
    passkey = body.get("passkey")

    app.logger.info("Login attempt: %s", name)

    # If no user exists, force registration
    if load_first_user() is None:
        return jsonify({"error": "No users yet. Please register first."}), 403

    user = load_user_by_name(name)

    if not user:
        # If user does not exist, clone credentials from the "owner" account
        owner = get_owner()
        if not owner:
            return "Unauthorized", 401  # No owner set yet
        clone_user(name, owner['pass_salt'], owner['pass_hash'])
        user = load_user_by_name(name)

    # Verify password
    if not verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        return "Unauthorized", 401

    flask_session.clear()
    flask_session['username'] = user['name']
    touch_user_presence(user['name'])
    return jsonify({"status": "ok"})

@app.route("/logout", methods=["POST"])
def logout():
    flask_session.pop('username', None)
    return redirect(url_for('index'))

@app.route("/api/current_user")
def api_current_user():
    username = flask_session.get("username")
    if not username:
        return jsonify({"logged_in": False}), 401
    user = load_user_by_name(username)
    return jsonify({
        "logged_in": True,
        "name": user["name"],
        "is_owner": bool(user.get("is_owner"))
    })

@app.route("/chat")
def chat():
    from flask import request, redirect, url_for, render_template_string, current_app

    # --- Step 1: Try to get from session ---
    username = flask_session.get('username')

    # --- Step 2: If not logged in, allow ?username= for dev/testing ---
    if not username:
        q_user = request.args.get('username')
        if q_user:
            flask_session['username'] = q_user
            username = q_user
            current_app.logger.info(f"[DEV] Auto-set session username via query param: {q_user}")

    # --- Step 3: Redirect if still missing (production guard) ---
    if not username:
        return redirect(url_for('index'))

    # --- Step 4: Load user and safety check ---
    user = load_user_by_name(username)
    if not user:
        return redirect(url_for('index'))

    owner = get_owner()
    partner = get_partner()
    is_owner = user.get("is_owner", False)
    is_partner = user.get("is_partner", False)
    owner_name = owner["name"] if owner else None
    partner_name = partner["name"] if partner else None
    is_member = is_owner or is_partner

    # Mark active presence
    touch_user_presence(username)

    # --- Step 5: Read peer token for the chat (from ?t=xxxx or ?peer=) ---
    peer_token = request.args.get('t') or request.args.get('peer')
    current_app.logger.info(f"Opening chat for {username} peer_token={peer_token}")

    # --- Step 6: Render chat page ---
    return render_template_string(
        CHAT_HTML,
        username=username,
        user_status=user.get('status', ''),
        user_avatar=user.get('avatar', ''),
        is_owner=is_owner,
        is_partner=is_partner,
        owner_name=owner_name,
        partner_name=partner_name,
        is_member=is_member,
        heading_img=HEADING_IMG,
        peer_token=peer_token
    )

@app.route("/send_composite_message", methods=["POST"])
def send_composite_message():
    """
    Handles multipart messages with text + attachments (files).
    Returns the authoritative message object just like /send_message.
    """
    try:
        username = flask_session.get('username')
        if not username:
            return jsonify({"error": "not signed in"}), 401

        text = (request.form.get('text') or '').strip()
        files = request.files.getlist('file') or []
        attachments = []

        # process each uploaded file
        for file in files:
            if not file or not file.filename:
                continue

            fn = secure_filename(file.filename)
            save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
            abs_path = os.path.join(app.static_folder, save_name)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            file.save(abs_path)

            url = url_for('static', filename=save_name)
            ext = fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
            if ext in ALLOWED_IMAGE_EXT:
                kind = 'image'
            elif ext in ALLOWED_VIDEO_EXT:
                kind = 'video'
            elif ext in ALLOWED_AUDIO_EXT:
                kind = 'audio'
            else:
                kind = 'doc'

            attachments.append({
                "type": kind,
                "url": url,
                "name": fn
            })

        if not text and not attachments:
            return jsonify({'error': 'Empty message'}), 400

        # save message (returns full message dict)
        message = save_message(username, text, attachments=attachments)

        # broadcast via socket
        try:
            socketio.emit('new_message', message)
        except Exception:
            app.logger.exception("socket emit failed for new_message")

        # optional: update user activity timestamp
        try:
            touch_user_presence(username)
        except Exception:
            pass

        return jsonify({"ok": True, "message": message}), 200

    except Exception as e:
        current_app.logger.exception("send_composite_message error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/resolve_peer')
def api_resolve_peer():
    from flask import request, session as flask_session, jsonify, current_app
    token = request.args.get('t') or request.args.get('token') or (request.query_string.decode() if request.query_string else '')
    if not token:
        return jsonify({'error':'missing_token'}), 400

    username = flask_session.get('username')
    if not username:
        # Not logged in on server — client may still have local profile, but server needs session
        return jsonify({'error': 'not_logged_in'}), 401

    try:
        conn = _db_conn()
        cur = conn.cursor()
        # find contact row where token matches and user is owner or contact
        cur.execute("""
            SELECT owner, contact_name FROM contacts WHERE peer_token = ? LIMIT 1
        """, (token,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return jsonify({'error':'not_found'}), 404
        owner, contact_name = r
        # pick the other side as the peer
        if owner == username:
            peer = contact_name
        elif contact_name == username:
            peer = owner
        else:
            # token exists but not for this session; return owner/contact so client can handle access
            peer = contact_name if contact_name != username else owner
        return jsonify({'peer': peer, 'owner': owner, 'contact_name': contact_name})
    except Exception as e:
        current_app.logger.exception("resolve_peer failed: %s", e)
        return jsonify({'error':'server_error'}), 500

@app.route('/contacts_list')
def contacts_list_api():
    from flask import jsonify, request, current_app, session as flask_session
    import sqlite3, time

    username = flask_session.get('username') or request.args.get('username')
    if not username:
        return jsonify({'contacts': [], 'debug': {'note': 'no username provided'}})

    uname_trim = username.strip()
    uname_lower = uname_trim.lower()

    conn = None
    debug = {}
    contacts = []
    seen = set()

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        debug['db_path'] = DB_PATH
        debug['query_username'] = uname_trim

        # fetch contacts table info to see if peer_token column exists
        try:
            cur.execute("PRAGMA table_info(contacts);")
            contact_cols_info = cur.fetchall()
            contact_cols = [r[1] for r in contact_cols_info]
            debug['contacts_table_info'] = contact_cols_info
        except Exception as e:
            contact_cols = []
            debug['contacts_table_info_error'] = str(e)

        # Pull all contacts for owner (case-insensitive match)
        try:
            cur.execute("SELECT owner, contact_name, phone, avatar, added_at, source, " +
                        ("peer_token" if 'peer_token' in contact_cols else "'' as peer_token") +
                        " FROM contacts")
            all_rows = cur.fetchall()
            debug['total_contacts'] = len(all_rows)
        except Exception as e:
            all_rows = []
            debug['contacts_select_error'] = str(e)

        for owner, cname, phone, avatar, added_at, source, peer_token in all_rows:
            if not owner:
                continue
            if (owner.strip() == uname_trim) or (owner.strip().lower() == uname_lower):
                cid = (phone or cname or '').strip()
                if not cid or cid in seen:
                    continue
                contacts.append({
                    'contact': cid,
                    'name': cname or cid,
                    'phone': phone,
                    'avatar_url': avatar or f'/avatar/{cname or cid}',
                    'peer_token': peer_token or '',
                    'last_text': '',
                    'last_ts': int(added_at) if added_at else None,
                    'source': source or 'manual'
                })
                seen.add(cid)

        # Merge message-based contacts (optional, non-fatal)
        try:
            cur.execute("""
                SELECT
                  CASE WHEN sender = ? THEN recipient ELSE sender END AS contact,
                  MAX(timestamp) as last_ts
                FROM messages
                WHERE sender = ? OR recipient = ?
                GROUP BY contact
                ORDER BY last_ts DESC
            """, (uname_trim, uname_trim, uname_trim))
            for c, ts in cur.fetchall():
                if not c or c in seen:
                    continue
                contacts.append({
                    'contact': c,
                    'name': c,
                    'phone': None,
                    'avatar_url': f'/avatar/{c}',
                    'peer_token': '',
                    'last_text': '',
                    'last_ts': int(ts) if ts else None,
                    'source': 'messages'
                })
                seen.add(c)
        except Exception as e:
            debug['messages_merge_error'] = str(e)

        contacts.sort(key=lambda x: x.get('last_ts') or 0, reverse=True)
        debug['returned_contacts'] = len(contacts)
        return jsonify({'contacts': contacts, 'debug': debug})
    except Exception as e:
        current_app.logger.exception("contacts_list error: %s", e)
        return jsonify({'contacts': [], 'debug': {'exception': str(e)}})
    finally:
        if conn:
            conn.close()

@app.route('/poll_messages')
def poll_messages():
    since = request.args.get('since', 0, type=int)
    msgs = fetch_messages(since)
    return jsonify(msgs)

@app.route('/mark_seen', methods=['POST'])
def mark_seen():
    data = request.get_json(force=True)
    msg_id = data.get('messageId')
    user = flask_session.get('username') or 'anonymous'
    if not msg_id:
        return jsonify({'ok': False})
    # Example: add user to "seenBy"
    # Implement your own persistence logic here (DB, in-memory, etc.)
    for m in messages_db:
        if str(m['id']) == str(msg_id):
            if 'seenBy' not in m:
                m['seenBy'] = []
            if user not in m['seenBy']:
                m['seenBy'].append(user)
    return jsonify({'ok': True})

@app.route("/edit_message", methods=["POST"])
def route_edit_message():
    username = flask_session.get('username');
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id"); text = body.get("text","").strip()
    ok, err = edit_message_db(msg_id, text, username)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/delete_message", methods=["POST"])
def route_delete_message():
    username = flask_session.get('username');
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    ok, err = delete_message_db(msg_id, username)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/react_message", methods=["POST"])
def route_react_message():
    username = flask_session.get('username');
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id"); emoji = body.get("emoji","❤️")
    ok, err = react_message_db(msg_id, username, emoji)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/partner_info")
def partner_info():
    p = get_partner()
    return jsonify(p or {})

# socket handlers
@socketio.on('identify')
def on_identify(data):
    name = data.get('name')
    if not name: return
    USER_SID[name] = request.sid
    print("📡 identify() called ->", username, "SID:", request.sid)
    print("📡 USER_SID now =", USER_SID)
    emit('identified', {'status':'ok'})
    emit('presence', {'user': name, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for u, s in list(USER_SID.items()):
        if s == sid:
            del USER_SID[u]
            emit('presence', {'user': u, 'online': False}, broadcast=True)
            break

@socketio.on('call_outgoing')
def on_call_outgoing(data):
    to = data.get('to')
    caller = data.get('from') or 'unknown'
    isVideo = data.get('isVideo', False)
    if not to or not caller:
        return

    call_id = secrets.token_hex(12)
    save_call(call_id, caller, to, isVideo, status='ringing')
    CALL_INVITES[call_id] = {"caller": caller, "callee": to, "isVideo": isVideo}

    sid_callee = USER_SID.get(to)
    # Always inform caller immediately using the caller's request.sid (guarantees sender receives)
    try:
        emit('open_meet_creator', {'call_id': call_id}, room=request.sid)
    except Exception:
        # fallback: if request.sid not available, try mapping
        sid_caller = USER_SID.get(caller)
        if sid_caller:
            emit('open_meet_creator', {'call_id': call_id}, room=sid_caller)

    # Inform callee if online (pre-inform, optional)
    if sid_callee:
        emit('incoming_meet_invite', {'from': caller, 'call_id': call_id}, room=sid_callee)


@socketio.on('share_meet_invite')
def on_share_meet_invite(data):
    call_id = data.get('call_id')
    url = data.get('url')
    if not call_id or not url:
        return
    info = CALL_INVITES.get(call_id)
    if not info:
        # store the link with info so callee gets it later
        return
    sid_callee = USER_SID.get(info['callee'])
    if sid_callee:
        emit('incoming_meet_invite', {'from': info['caller'], 'call_id': call_id, 'url': url}, room=sid_callee)
    else:
        current_app.logger.info("share_meet_invite: callee offline for call_id %s", call_id)

@socketio.on('meet_accept')
def on_meet_accept(data):
    call_id = data.get('call_id')
    meet_url = data.get('url')
    if not call_id or not meet_url:
        return
    info = CALL_INVITES.pop(call_id, None)
    if not info:
        return
    update_call_started(call_id)
    sid_caller = USER_SID.get(info.get('caller'))
    sid_callee = USER_SID.get(info.get('callee'))
    if sid_caller:
        emit('open_meet', {'url': meet_url}, room=sid_caller)
    if sid_callee:
        emit('open_meet', {'url': meet_url}, room=sid_callee)
    if sid_caller:
        emit('call_accepted', {'call_id': call_id, 'from': info.get('callee')}, room=sid_caller)
    current_app.logger.info("meet_accept: call %s accepted, open_meet -> %s", call_id, meet_url)


@socketio.on('meet_decline')
def on_meet_decline(data):
    call_id = data.get('call_id')
    info = CALL_INVITES.pop(call_id, None)
    if not info:
        return
    sid_caller = USER_SID.get(info.get('caller'))
    if sid_caller:
        emit('meet_declined', {'call_id': call_id}, room=sid_caller)
    save_call(call_id, info['caller'], info['callee'], 0, status='declined')
    current_app.logger.info("meet_decline: call %s declined by %s", call_id, info.get('callee'))

@socketio.on('call_end')
def on_call_end(data):
    """Either side ends an in-progress call. Notify the other side."""
    call_id = data.get('call_id')
    try:
        update_call_ended(call_id)
    except Exception:
        app.logger.exception("call_end: update failed for %s", call_id)

    log = fetch_call_log_by_id(call_id)
    if log and log.get('started_at') and log.get('ended_at'):
        duration = log['ended_at'] - log['started_at']
        socketio.emit('call_summary', {'duration': duration, 'isVideo': log.get('is_video', False)})

    # Clean up invites if any
    info = CALL_INVITES.pop(call_id, None)
    if info:
        sid_caller = USER_SID.get(info.get('caller'))
        sid_callee = USER_SID.get(info.get('callee'))
        if sid_caller:
            emit('call_ended', {'call_id': call_id}, room=sid_caller)
        if sid_callee:
            emit('call_ended', {'call_id': call_id}, room=sid_callee)
# --- end of CALL / MEET SIGNALING block ---

# WebRTC signaling passthrough
@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('webrtc_offer', data, room=sid)

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('webrtc_answer', data, room=sid)

@socketio.on('ice_candidate')
def on_ice_candidate(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('ice_candidate', data, room=sid)

# New: call control relay (mute/unmute/hold/other UI states)
@socketio.on('call_control')
def on_call_control(data):
    # data should include: type, from, call_id, optional payload
    to = None
    call_id = data.get('call_id')
    if not call_id:
        return
    info = CALL_INVITES.get(call_id)
    if not info:
        # if not found, try to find by caller/callee
        # naive scan
        for cid, val in CALL_INVITES.items():
            if cid == call_id:
                info = val; break
    if not info:
        return
    # choose recipient: if sender == caller then recipient is callee, else caller
    sender = data.get('from')
    if sender == info.get('caller'):
        to = info.get('callee')
    else:
        to = info.get('caller')
    sid = USER_SID.get(to)
    if sid:
        emit('call_control', data, room=sid)
@socketio.on('identify')
def handle_identify(data):
    name = data.get('name')
    if name:
        USER_SID[name] = request.sid
        emit('identified', {'ok': True})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    to_remove = [u for u, s in USER_SID.items() if s == sid]
    for u in to_remove:
        USER_SID.pop(u, None)

@socketio.on('vote_poll')
def handle_vote_poll(data):
    """
    data: { message_id, option, user }
    """
    mid = str(data.get('message_id'))
    option = data.get('option')
    user = data.get('user')
    if mid not in polls_store:
        emit('poll_error', {'message': 'Poll not found', 'message_id': mid})
        return

    poll = polls_store[mid]
    votes = poll.setdefault('votes', {})
    try:
        opt_i = int(option)
    except:
        return

    if poll.get('allow_multi'):
        user_set = votes.setdefault(user, set())
        if opt_i in user_set:
            user_set.remove(opt_i)
            if not user_set:
                votes.pop(user, None)
        else:
            user_set.add(opt_i)
    else:
        cur = votes.get(user, set())
        if len(cur) == 1 and opt_i in cur:
            votes.pop(user, None)
        else:
            votes[user] = {opt_i}

    # compute counts
    counts = [0] * len(poll['options'])
    for sel in votes.values():
        for i in sel:
            if 0 <= i < len(counts):
                counts[i] += 1

    # broadcast update to all clients
    socketio.emit('poll_update', {'message_id': mid, 'counts': counts})

    # send private poll view to this user
    sid = USER_SID.get(user)
    private = {
        'message_id': mid,
        'user': user,
        'selected': list(votes.get(user, [])),
        'counts': counts,
        'question': poll['question'],
        'options': poll['options']
    }
    if sid:
        socketio.emit('poll_private', private, to=sid)
    else:
        emit('poll_private_missing', {'message': 'You must connect via socket to see private poll'})

@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Accepts JSON { text, sender?, attachments? } and stores the message to DB.
    Returns the stored message object (with id) and broadcasts it via SocketIO.
    Also sends a push notification (title=sender, body="Notification").
    """
    try:
        data = request.get_json() or {}
        text = (data.get('text') or "").strip()
        attachments = data.get('attachments') or []

        # Prefer authenticated flask_session username when available
        sender = data.get('sender') or flask_session.get('username') or data.get('from') or 'Unknown'

        if not text and (not attachments or len(attachments) == 0):
            return jsonify({'error': 'Empty message'}), 400

        # Patch avatar if user has one
        avatar = None
        try:
            user = load_user_by_name(sender)
            if user:
                avatar = user.get('avatar')
                if avatar and not avatar.startswith('/') and re.match(r'^m\d+\.(webp|png|jpg|jpeg)$', avatar, re.I):
                    if avatar.lower() != 'm47.webp':  # skip m47 intentionally
                        avatar = f'/static/{avatar}'
        except Exception:
            avatar = None

        # Save message to DB
        message = save_message(sender, text, attachments)
        if not message:
            return jsonify({'error': 'Failed to save message'}), 500

        # Inject avatar into message object for frontend
        message['avatar'] = avatar

        # Broadcast to all connected SocketIO clients
        try:
            socketio.emit('new_message', message)
        except Exception:
            app.logger.exception("socket emit failed for new_message")

        # ✅ PUSH NOTIFICATION LOGIC (inside try block)
        payload = {
            "title": sender,         # notification title = sender name
            "body": "Notification",  # fixed message body (not actual text)
            "icon": message.get("avatar") or "/static/default-avatar.png",
            "url": f"/?open_chat={sender}"
        }

        # find push subscriptions for recipients (here: all users except sender)
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT id, username, subscription FROM push_subscriptions WHERE username != ?", (sender,))
        rows = c.fetchall()
        conn.close()

        for sub_id, sub_username, sub_json in rows:
            try:
                subscription = json.loads(sub_json)
            except Exception:
                # malformed -> remove
                conn = db_conn()
                c = conn.cursor()
                c.execute("DELETE FROM push_subscriptions WHERE id=?", (sub_id,))
                conn.commit()
                conn.close()
                continue

            # skip if recipient is currently online
            if sub_username and sub_username in ONLINE_USERS:
                continue

            resp = send_web_push(subscription, payload)

            # if resp indicates gone (410/404) remove
            if resp is False or (isinstance(resp, int) and resp in (404, 410)):
                conn = db_conn()
                c = conn.cursor()
                c.execute("DELETE FROM push_subscriptions WHERE id=?", (sub_id,))
                conn.commit()
                conn.close()

        # ✅ Everything inside try; function ends cleanly
        return jsonify({'ok': True, 'message': message}), 200

    except Exception as e:
        app.logger.exception('send_message error')
        return jsonify({'error': str(e)}), 500

@app.route("/api/set_session", methods=["POST"])
def api_set_session():
    from flask import jsonify, request, session as flask_session, current_app

    data = request.get_json(force=True) or {}
    username = data.get("username")
    if not username:
        return jsonify({"error": "missing username"}), 400

    # store username in session
    flask_session["username"] = username
    flask_session.modified = True

    # Build the response
    resp = jsonify({"ok": True, "session_username": username})

    # Flask 3.x: session cookie name is now in app.config
    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")

    # Explicitly set a secure cookie for Render + Safari
    resp.set_cookie(
        cookie_name,
        value=flask_session.get("_id", os.urandom(16).hex()),
        secure=True,
        httponly=True,
        samesite="None",
        path="/"
    )

    return resp

@app.route('/poll')
@app.route('/messages')
@app.route('/get_messages')
def poll_alias():
    since = request.args.get('lastId', request.args.get('since', 0, type=int), type=int)
    for msg in messages:
        if "seenBy" not in msg:
            msg["seenBy"] = []

    msgs = fetch_messages(since)
    return jsonify(msgs)
    
# ----- run -----
if __name__ == "__main__":
    print("DB:", DB_PATH)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=False, allow_unsafe_werkzeug=True)
