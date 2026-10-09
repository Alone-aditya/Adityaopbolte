"""
============================================================
  AadixSMS API Manager — SMOOTH EDITION
  Developer: ADITYAxOSHIT
  Fixes: SQLite lock, SECRET_KEY stability, cache freeze,
         gunicorn timeouts, redirect loops
============================================================
"""

import os
import re
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from flask import (
    Flask, request, jsonify, render_template_string,
    redirect, url_for, flash, session, g, make_response
)

# ============================================================
#  CONFIG  — SECRET_KEY must be STABLE across restarts
# ============================================================
UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "https://aadixsms-production.up.railway.app")
ADMIN_USER    = os.environ.get("ADMIN_USER", "aditya")
ADMIN_PASS    = os.environ.get("ADMIN_PASS", "Aditya@2025")

# ⚠️ CRITICAL: A fixed default. If you don't set SECRET_KEY in Railway,
# sessions survive restarts because this string never changes.
SECRET_KEY    = os.environ.get("SECRET_KEY", "adx-fixed-secret-key-9f2b7c1d4e8a-2025")

DATABASE      = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "apikeys.db"))

OLD_BRAND = re.compile(r"@ftgamer2|@ftgamer_2|aadixsms", re.IGNORECASE)
NEW_BRAND = "@Aditya05712"

app = Flask(__name__)
app.config.update(
    SECRET_KEY                 = SECRET_KEY,
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
    TEMPLATES_AUTO_RELOAD      = False,
)

# ============================================================
#  SERVICES
# ============================================================
SERVICES = {
    "all":      {"label":"SEND ALL",       "path":"/api/all/{phone}",                "icon":"bi-send-fill",       "has_phone":True,  "desc":"Send all types (SMS + Call + WhatsApp)"},
    "sms":      {"label":"SMS",            "path":"/api/sms/{phone}",                "icon":"bi-chat-dots-fill",  "has_phone":True,  "desc":"Send SMS flood"},
    "call":     {"label":"CALL",           "path":"/api/call/{phone}",               "icon":"bi-telephone-fill",  "has_phone":True,  "desc":"Send call flood"},
    "whatsapp": {"label":"WHATSAPP ALL",   "path":"/api/whatsapp/{phone}",           "icon":"bi-whatsapp",        "has_phone":True,  "desc":"All WhatsApp sections"},
    "wa1":      {"label":"WA · SECTION 1", "path":"/api/whatsapp/section1/{phone}",  "icon":"bi-whatsapp",        "has_phone":True,  "desc":"WhatsApp - Meta / Facebook"},
    "wa2":      {"label":"WA · SECTION 2", "path":"/api/whatsapp/section2/{phone}",  "icon":"bi-whatsapp",        "has_phone":True,  "desc":"WhatsApp - Twilio & SMS Gateways"},
    "wa3":      {"label":"WA · SECTION 3", "path":"/api/whatsapp/section3/{phone}",  "icon":"bi-whatsapp",        "has_phone":True,  "desc":"WhatsApp - Third Party Services"},
    "wa4":      {"label":"WA · SECTION 4", "path":"/api/whatsapp/section4/{phone}",  "icon":"bi-whatsapp",        "has_phone":True,  "desc":"WhatsApp - Gupshup & Others"},
    "gambling": {"label":"GAMBLING",       "path":"/api/gambling/{phone}",           "icon":"bi-dice-5-fill",     "has_phone":True,  "desc":"Gambling SMS flood"},
    "master":   {"label":"MASTER",         "path":"/api/master/{phone}",             "icon":"bi-sliders",         "has_phone":True,  "desc":"Master with ?types=sms&count=2"},
    "health":   {"label":"HEALTH",         "path":"/api/health",                     "icon":"bi-heart-pulse-fill","has_phone":False, "desc":"Health check"},
    "stats":    {"label":"STATS",          "path":"/api/stats",                      "icon":"bi-bar-chart-fill",  "has_phone":False, "desc":"API statistics"},
}


# ============================================================
#  DATABASE  —  WAL mode + timeout for smooth concurrency
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            DATABASE,
            timeout      = 15,               # wait 15s before "database is locked"
            check_same_thread = False,       # allow thread reuse
            isolation_level = None,          # autocommit, fewer locks
        )
        g.db.row_factory = sqlite3.Row
        # WAL mode = readers & writers don't block each other
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA busy_timeout=15000")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try: db.close()
        except Exception: pass


def init_db():
    try:
        with sqlite3.connect(DATABASE, timeout=15) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_name   TEXT DEFAULT '',
                    key_name      TEXT DEFAULT '',
                    service       TEXT NOT NULL,
                    prefix        TEXT NOT NULL,
                    key_hash      TEXT NOT NULL UNIQUE,
                    is_active     INTEGER DEFAULT 1,
                    expires_at    TEXT,
                    search_limit  INTEGER,
                    searches_used INTEGER DEFAULT 0,
                    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_used_at  TEXT
                )
            """)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(api_keys)").fetchall()]
            if "client_name" not in cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN client_name TEXT DEFAULT ''")
            if "key_name" not in cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN key_name TEXT DEFAULT ''")
            conn.commit()
    except Exception as e:
        print(f"[DB INIT ERROR] {e}")


# ============================================================
#  UTILITIES
# ============================================================
def generate_api_key():
    raw = "adx_" + secrets.token_urlsafe(24)
    return raw, hashlib.sha256(raw.encode()).hexdigest()

def hash_key(raw):
    return hashlib.sha256(raw.encode()).hexdigest()

def make_prefix(raw):
    return raw[:10] + "_" + secrets.token_hex(2)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def key_status(row):
    try:
        if not row["is_active"]:
            return "Inactive"
        if row["expires_at"]:
            exp = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > exp.replace(tzinfo=timezone.utc):
                return "Expired"
        if row["search_limit"] is not None and row["searches_used"] >= row["search_limit"]:
            return "Limit Reached"
        return "Active"
    except Exception:
        return "Active"

def validate_key(row):
    try:
        if not row["is_active"]:
            return False, "API key is deactivated"
        if row["expires_at"]:
            exp = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > exp.replace(tzinfo=timezone.utc):
                return False, "API key has expired"
        if row["search_limit"] is not None and row["searches_used"] >= row["search_limit"]:
            return False, "Search limit reached"
        return True, None
    except Exception as e:
        return False, f"Validation error: {e}"

def rewrite_json(obj):
    if isinstance(obj, dict):
        return {k: rewrite_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [rewrite_json(i) for i in obj]
    if isinstance(obj, str):
        return OLD_BRAND.sub(NEW_BRAND, obj)
    return obj


# ============================================================
#  ACCESS GUARD  —  no redirect loop
# ============================================================
PUBLIC_PATHS = ("/login", "/logout", "/favicon.ico", "/healthz")

@app.before_request
def restrict_access():
    path = request.path
    if path.startswith("/api/") or path in PUBLIC_PATHS or path.startswith("/static/"):
        return
    if not session.get("logged_in"):
        return redirect(url_for("login"))


# ============================================================
#  NO-CACHE HEADERS  —  prevents browser freeze on stale HTML
# ============================================================
@app.after_request
def no_cache(response):
    # Only apply to HTML pages; leave API responses alone
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"]        = "no-cache"
        response.headers["Expires"]       = "0"
    return response


# ============================================================
#  GLOBAL ERROR HANDLERS  —  prevents crash-freeze
# ============================================================
@app.errorhandler(500)
def err500(e):
    return "Internal Server Error — please retry", 500

@app.errorhandler(404)
def err404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return redirect(url_for("dashboard"))


# ============================================================
#  HEALTH CHECK  —  keeps Railway happy
# ============================================================
@app.route("/healthz")
def healthz():
    return "ok", 200


# ============================================================
#  BASE LAYOUT
# ============================================================
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · AadixSMS Manager</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root{--bg:#070b14;--bg-2:#0d1424;--sidebar:#0a0f1c;--card:#101827;--border:#1e293b;
        --text:#e5e7eb;--muted:#6b7280;--green:#00ff88;--green-2:#10b981;
        --red:#ef4444;--amber:#f59e0b;}
  *{box-sizing:border-box;} html,body{height:100%;}
  body{margin:0;background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;
       font-size:14px;overflow-x:hidden;}
  .layout{display:flex;min-height:100vh;}
  .sidebar{width:250px;background:var(--sidebar);border-right:1px solid var(--border);
           padding:20px 14px;display:flex;flex-direction:column;position:fixed;
           top:0;bottom:0;left:0;z-index:100;transition:transform .25s;}
  .brand{display:flex;align-items:center;gap:10px;padding:4px 8px 22px;margin-bottom:6px;
         border-bottom:1px solid var(--border);}
  .brand-logo{width:36px;height:36px;border-radius:10px;
              background:linear-gradient(135deg,var(--green),var(--green-2));
              display:flex;align-items:center;justify-content:center;
              color:#062c1a;font-weight:800;font-size:18px;
              box-shadow:0 0 20px rgba(0,255,136,.35);}
  .brand-name{font-weight:700;font-size:15px;}
  .brand-sub{font-size:10px;color:var(--muted);letter-spacing:1.5px;}
  .nav-section{font-size:10px;color:var(--muted);letter-spacing:1.5px;font-weight:600;
               padding:18px 12px 8px;}
  .nav-link{display:flex;align-items:center;gap:12px;padding:10px 14px;color:#94a3b8;
            border-radius:10px;margin-bottom:3px;font-weight:500;font-size:13.5px;
            text-decoration:none;transition:.15s;}
  .nav-link:hover{background:var(--card);color:var(--text);}
  .nav-link.active{background:linear-gradient(90deg,rgba(0,255,136,.15),rgba(16,185,129,.05));
                   color:var(--green);box-shadow:inset 2px 0 0 var(--green);}
  .nav-link i{font-size:17px;width:20px;}
  .sidebar-foot{margin-top:auto;border-top:1px solid var(--border);padding-top:14px;}
  .admin-card{display:flex;align-items:center;gap:10px;padding:10px;border-radius:10px;
              background:var(--card);border:1px solid var(--border);margin-bottom:10px;}
  .avatar{width:34px;height:34px;border-radius:50%;
          background:linear-gradient(135deg,var(--green),var(--green-2));
          color:#062c1a;font-weight:800;display:flex;align-items:center;
          justify-content:center;font-size:14px;}
  .admin-info small{color:var(--muted);font-size:11px;display:block;}
  .admin-info b{font-size:13px;}
  .logout-btn{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;
              padding:9px;border-radius:9px;background:transparent;color:#94a3b8;
              border:1px solid var(--border);font-size:12.5px;font-weight:600;text-decoration:none;}
  .logout-btn:hover{color:var(--red);border-color:var(--red);}
  .main{margin-left:250px;flex:1;padding:22px 28px;min-width:0;}
  .topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px;gap:16px;}
  .search-box{flex:1;max-width:380px;position:relative;}
  .search-box input{width:100%;background:var(--card);border:1px solid var(--border);
                    color:var(--text);padding:9px 14px 9px 38px;border-radius:10px;font-size:13px;}
  .search-box input:focus{outline:none;border-color:var(--green-2);}
  .search-box i{position:absolute;left:13px;top:50%;transform:translateY(-50%);
                color:var(--muted);font-size:15px;}
  .top-actions{display:flex;align-items:center;gap:10px;}
  .icon-btn{width:38px;height:38px;display:flex;align-items:center;justify-content:center;
            background:var(--card);border:1px solid var(--border);color:#94a3b8;
            border-radius:10px;text-decoration:none;}
  .icon-btn:hover{color:var(--green);border-color:var(--green-2);}
  .card-dark{background:var(--card);border:1px solid var(--border);border-radius:14px;
             padding:18px;margin-bottom:18px;}
  .card-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
  .card-title h5{margin:0;font-size:15px;font-weight:700;
                 display:flex;align-items:center;gap:8px;}
  .card-title h5 i{color:var(--green);}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:14px;
        padding:16px 18px;position:relative;overflow:hidden;transition:.2s;}
  .stat:hover{border-color:#26324a;}
  .stat::before{content:"";position:absolute;top:0;left:0;width:100%;height:3px;
                background:linear-gradient(90deg,var(--green),var(--green-2));opacity:.8;}
  .stat-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;}
  .stat-label{font-size:10.5px;color:var(--muted);letter-spacing:1.2px;font-weight:600;}
  .stat-icon{width:30px;height:30px;border-radius:8px;background:rgba(0,255,136,.1);
             color:var(--green);display:flex;align-items:center;justify-content:center;font-size:15px;}
  .stat-value{font-size:26px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px;}
  .stat-sub{font-size:11.5px;color:var(--green);font-weight:600;}
  .stat-sub.muted{color:var(--muted);}
  .form-label{font-size:10.5px;letter-spacing:1.2px;color:var(--muted);font-weight:600;
              text-transform:uppercase;margin-bottom:8px;display:block;}
  .form-control-dark{width:100%;background:var(--bg-2);border:1px solid var(--border);
                     color:var(--text);padding:11px 14px;border-radius:10px;
                     font-size:13.5px;font-family:inherit;transition:.15s;}
  .form-control-dark:focus{outline:none;border-color:var(--green-2);
                           box-shadow:0 0 0 3px rgba(16,185,129,.15);}
  .form-control-dark::placeholder{color:#4b5563;}
  .service-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;}
  .svc-radio{display:none;}
  .svc-card{background:var(--bg-2);border:1.5px solid var(--border);border-radius:11px;
            padding:14px 8px;text-align:center;cursor:pointer;transition:.18s;
            display:flex;flex-direction:column;align-items:center;gap:8px;}
  .svc-card i{font-size:22px;color:#94a3b8;transition:.18s;}
  .svc-card span{font-size:10.5px;font-weight:700;letter-spacing:.6px;color:#94a3b8;}
  .svc-radio:checked + .svc-card{border-color:var(--green);
    background:linear-gradient(180deg,rgba(0,255,136,.1),rgba(0,255,136,.02));
    box-shadow:0 0 20px rgba(0,255,136,.15);}
  .svc-radio:checked + .svc-card i{color:var(--green);}
  .svc-radio:checked + .svc-card span{color:var(--green);}
  .expiry-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}
  .exp-radio{display:none;}
  .exp-card{background:var(--bg-2);border:1.5px solid var(--border);border-radius:11px;
            padding:14px 12px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:.18s;}
  .exp-card i{font-size:18px;color:#94a3b8;}
  .exp-card div{line-height:1.2;}
  .exp-card b{font-size:12.5px;display:block;}
  .exp-card small{font-size:10.5px;color:var(--muted);}
  .exp-radio:checked + .exp-card{border-color:var(--green);
    background:linear-gradient(180deg,rgba(0,255,136,.1),rgba(0,255,136,.02));}
  .exp-radio:checked + .exp-card i{color:var(--green);}
  .btn-green{background:linear-gradient(135deg,var(--green),var(--green-2));color:#052e16;
             border:none;padding:12px 22px;border-radius:10px;font-weight:700;font-size:13.5px;
             letter-spacing:.3px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;
             box-shadow:0 4px 20px rgba(0,255,136,.25);transition:.2s;text-decoration:none;}
  .btn-green:hover{transform:translateY(-1px);box-shadow:0 6px 26px rgba(0,255,136,.4);color:#052e16;}
  .btn-ghost{background:var(--bg-2);border:1px solid var(--border);color:#94a3b8;
             padding:10px 16px;border-radius:9px;font-size:12.5px;font-weight:600;
             text-decoration:none;display:inline-flex;align-items:center;gap:6px;}
  .btn-ghost:hover{color:var(--text);border-color:#26324a;}
  .table-dark-custom{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;}
  .table-dark-custom th{text-align:left;font-size:10.5px;letter-spacing:1.2px;color:var(--muted);
                        font-weight:600;text-transform:uppercase;padding:10px 14px;
                        border-bottom:1px solid var(--border);}
  .table-dark-custom td{padding:14px;border-bottom:1px solid var(--border);vertical-align:middle;}
  .table-dark-custom tr:last-child td{border-bottom:none;}
  .table-dark-custom tr:hover td{background:rgba(255,255,255,.015);}
  .badge-status{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;
                font-size:10.5px;font-weight:700;letter-spacing:.5px;}
  .badge-status.active{background:rgba(0,255,136,.12);color:var(--green);}
  .badge-status.inactive{background:rgba(107,114,128,.18);color:#9ca3af;}
  .badge-status.expired{background:rgba(239,68,68,.15);color:var(--red);}
  .badge-status.limit{background:rgba(245,158,11,.15);color:var(--amber);}
  .badge-status::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;}
  .action-btn{width:30px;height:30px;border-radius:8px;display:inline-flex;align-items:center;
              justify-content:center;background:var(--bg-2);border:1px solid var(--border);
              color:#94a3b8;text-decoration:none;margin-right:4px;transition:.15s;font-size:13px;}
  .action-btn:hover{color:var(--green);border-color:var(--green-2);}
  .action-btn.danger:hover{color:var(--red);border-color:var(--red);}
  .code-pill{background:var(--bg-2);border:1px solid var(--border);padding:3px 8px;
             border-radius:6px;font-family:'Courier New',monospace;font-size:11.5px;color:var(--green);}
  .section-head{margin-bottom:20px;}
  .section-head h2{font-size:22px;font-weight:800;margin:0 0 4px 0;}
  .section-head p{color:var(--muted);font-size:13px;margin:0;}
  @media (max-width:900px){
    .sidebar{transform:translateX(-100%);}
    .sidebar.open{transform:translateX(0);}
    .main{margin-left:0;padding:16px;}
    .menu-toggle{display:flex !important;}
    .expiry-grid{grid-template-columns:1fr;}
  }
  .menu-toggle{display:none;width:38px;height:38px;align-items:center;justify-content:center;
               background:var(--card);border:1px solid var(--border);border-radius:10px;
               color:var(--text);font-size:18px;cursor:pointer;}
</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-logo">A</div>
      <div><div class="brand-name">AADIXSMS</div>
        <div class="brand-sub">CONTROL PANEL</div></div>
    </div>
    <div class="nav-section">MAIN</div>
    <a href="/dashboard" class="nav-link {{ 'active' if page=='dashboard' else '' }}">
      <i class="bi bi-grid-1x2-fill"></i> Dashboard</a>
    <a href="/keys" class="nav-link {{ 'active' if page=='keys' else '' }}">
      <i class="bi bi-key-fill"></i> API Keys</a>
    <a href="/docs" class="nav-link {{ 'active' if page=='docs' else '' }}">
      <i class="bi bi-book-fill"></i> API Docs</a>
    <a href="/settings" class="nav-link {{ 'active' if page=='settings' else '' }}">
      <i class="bi bi-gear-fill"></i> Settings</a>
    <div class="sidebar-foot">
      <div class="admin-card">
        <div class="avatar">A</div>
        <div class="admin-info">
          <b>{{ session.get('user','Admin') }}</b><small>Administrator</small>
        </div>
      </div>
      <a href="/logout" class="logout-btn"><i class="bi bi-box-arrow-right"></i> Logout</a>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')">
        <i class="bi bi-list"></i></button>
      <div class="search-box">
        <i class="bi bi-search"></i><input type="text" placeholder="Search...">
      </div>
      <div class="top-actions">
        <a href="/docs" class="icon-btn"><i class="bi bi-book"></i></a>
        <div class="avatar" style="width:38px;height:38px;">A</div>
      </div>
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat, msg in messages %}
        <div class="alert alert-{{ cat }} alert-dismissible fade show"
             style="background:var(--card);border:1px solid var(--border);color:var(--text)">
          {{ msg }}<button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endwith %}
    {{ body|safe }}
  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


# ============================================================
#  LOGIN
# ============================================================
LOGIN_HTML = """
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  body{margin:0;background:#070b14;color:#e5e7eb;font-family:'Inter',sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;}
  .box{width:380px;background:#101827;border:1px solid #1e293b;border-radius:16px;
       padding:36px 30px;box-shadow:0 20px 60px rgba(0,255,136,.06);}
  .logo{width:52px;height:52px;border-radius:14px;margin:0 auto 16px;
        background:linear-gradient(135deg,#00ff88,#10b981);color:#052e16;
        display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;
        box-shadow:0 0 30px rgba(0,255,136,.4);}
  h2{text-align:center;margin:0 0 6px;font-size:20px;}
  p.sub{text-align:center;color:#6b7280;font-size:12.5px;margin:0 0 26px;}
  label{font-size:11px;color:#6b7280;letter-spacing:1.2px;font-weight:600;
        text-transform:uppercase;display:block;margin-bottom:7px;}
  input{width:100%;background:#0d1424;border:1px solid #1e293b;color:#e5e7eb;
        padding:12px 14px;border-radius:10px;font-size:14px;margin-bottom:16px;font-family:inherit;}
  input:focus{outline:none;border-color:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.15);}
  button{width:100%;background:linear-gradient(135deg,#00ff88,#10b981);color:#052e16;
         border:none;padding:13px;border-radius:10px;font-weight:700;font-size:14px;
         cursor:pointer;box-shadow:0 4px 20px rgba(0,255,136,.25);}
  button:hover{transform:translateY(-1px);}
  .err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);
       color:#fca5a5;padding:10px;border-radius:8px;font-size:12.5px;margin-bottom:16px;}
</style></head><body>
<form class="box" method="POST">
  <div class="logo">A</div>
  <h2>Welcome Back</h2>
  <p class="sub">Sign in to AadixSMS Control Panel</p>
  {% with messages = get_flashed_messages() %}
    {% for m in messages %}<div class="err">{{ m }}</div>{% endfor %}
  {% endwith %}
  <label>Username</label>
  <input type="text" name="username" required autofocus autocomplete="username">
  <label>Password</label>
  <input type="password" name="password" required autocomplete="current-password">
  <button type="submit"><i class="bi bi-box-arrow-in-right"></i> Login</button>
  <p style="text-align:center;font-size:11px;color:#4b5563;margin-top:20px">
    Developer: <b style="color:#00ff88">ADITYAxOSHIT</b></p>
</form></body></html>
"""


# ============================================================
#  DASHBOARD / KEYS / DOCS / RESULT HTML
# ============================================================
DASHBOARD_HTML = """
<div class="section-head"><h2>Good Morning, Admin 👋</h2>
  <p>Here's what's happening today.</p></div>
<div class="row g-3 mb-4">
  <div class="col-6 col-lg-3"><div class="stat">
    <div class="stat-top"><div class="stat-label">TOTAL KEYS</div>
      <div class="stat-icon"><i class="bi bi-key-fill"></i></div></div>
    <div class="stat-value">{{ total }}</div>
    <div class="stat-sub">{{ active }} active</div></div></div>
  <div class="col-6 col-lg-3"><div class="stat">
    <div class="stat-top"><div class="stat-label">ACTIVE KEYS</div>
      <div class="stat-icon"><i class="bi bi-shield-check"></i></div></div>
    <div class="stat-value">{{ active }}</div>
    <div class="stat-sub">{{ pct_active }}% utilization</div></div></div>
  <div class="col-6 col-lg-3"><div class="stat">
    <div class="stat-top"><div class="stat-label">TOTAL API CALLS</div>
      <div class="stat-icon"><i class="bi bi-activity"></i></div></div>
    <div class="stat-value">{{ total_calls }}</div>
    <div class="stat-sub muted">All time</div></div></div>
  <div class="col-6 col-lg-3"><div class="stat">
    <div class="stat-top"><div class="stat-label">TODAY'S CALLS</div>
      <div class="stat-icon"><i class="bi bi-lightning-charge-fill"></i></div></div>
    <div class="stat-value">{{ today_calls }}</div>
    <div class="stat-sub muted">{{ pct_today }}% of total</div></div></div>
</div>
<div class="card-dark">
  <div class="card-title"><h5><i class="bi bi-plus-circle-fill"></i> Create API Key</h5></div>
  <form method="POST" action="/create">
    <div class="row g-3 mb-3">
      <div class="col-md-6"><label class="form-label">Client Name</label>
        <input type="text" name="client_name" class="form-control-dark"
               placeholder="e.g. Rajesh Kumar" required></div>
      <div class="col-md-6"><label class="form-label">Key Name</label>
        <input type="text" name="key_name" class="form-control-dark"
               placeholder="e.g. Premium-SMS-Key" required></div>
    </div>
    <div class="mb-3"><label class="form-label">Custom API Key (leave blank to auto-generate)</label>
      <input type="text" name="custom_key" class="form-control-dark"
             placeholder="Enter unique API key or leave empty"></div>
    <label class="form-label">Select Endpoint</label>
    <div class="service-grid mb-3">
      {% for sid, svc in services.items() %}
      <label style="margin:0">
        <input type="radio" name="service" value="{{ sid }}" class="svc-radio"
               {{ 'checked' if loop.first }}>
        <div class="svc-card"><i class="bi {{ svc.icon }}"></i>
          <span>{{ svc.label }}</span></div></label>
      {% endfor %}
    </div>
    <div class="row g-3 mb-3">
      <div class="col-md-4"><label class="form-label">Search Limit</label>
        <input type="number" name="search_limit" class="form-control-dark"
               placeholder="e.g. 100 (blank = unlimited)" min="1"></div>
      <div class="col-md-8"><label class="form-label">Expiry Type</label>
        <div class="expiry-grid">
          <label style="margin:0"><input type="radio" name="expiry_type" value="demo" class="exp-radio">
            <div class="exp-card"><i class="bi bi-lightning-charge-fill"></i>
              <div><b>Demo</b><small>Hourly</small></div></div></label>
          <label style="margin:0"><input type="radio" name="expiry_type" value="premium" class="exp-radio" checked>
            <div class="exp-card"><i class="bi bi-gem"></i>
              <div><b>Premium</b><small>Days</small></div></div></label>
          <label style="margin:0"><input type="radio" name="expiry_type" value="permanent" class="exp-radio">
            <div class="exp-card"><i class="bi bi-infinity"></i>
              <div><b>Permanent</b><small>No expiry</small></div></div></label>
        </div></div>
    </div>
    <div class="row g-3 mb-4" id="durationRow">
      <div class="col-md-4"><label class="form-label" id="durationLabel">Duration (Days)</label>
        <input type="number" name="duration_value" id="durationInput"
               class="form-control-dark" value="30" min="1"></div>
    </div>
    <button type="submit" class="btn-green"><i class="bi bi-plus-lg"></i> Create Key</button>
  </form>
</div>
<div class="card-dark">
  <div class="card-title"><h5><i class="bi bi-clock-history"></i> Recent API Keys</h5>
    <a href="/keys" class="btn-ghost">View All <i class="bi bi-arrow-right"></i></a></div>
  {% if keys %}
  <div style="overflow-x:auto"><table class="table-dark-custom">
    <thead><tr><th>Client</th><th>Key Name</th><th>Endpoint</th>
      <th>Prefix</th><th>Status</th><th>Calls</th><th>Actions</th></tr></thead>
    <tbody>{% for k in keys %}<tr>
      <td><b>{{ k['client_name'] or '—' }}</b></td>
      <td style="color:#9ca3af">{{ k['key_name'] or '—' }}</td>
      <td><span class="badge-status active">{{ services[k['service']].label }}</span></td>
      <td><span class="code-pill">{{ k['prefix'] }}…</span></td>
      <td>{% set st = k['status'] %}
        <span class="badge-status {{ 'active' if st=='Active' else 'inactive' if st=='Inactive' else 'expired' if st=='Expired' else 'limit' }}">{{ st }}</span></td>
      <td>{{ k['searches_used'] }} / {{ k['search_limit'] if k['search_limit'] is not none else '∞' }}</td>
      <td><a href="/toggle/{{ k['id'] }}" class="action-btn"><i class="bi bi-power"></i></a>
        <a href="/delete/{{ k['id'] }}" class="action-btn danger"
           onclick="return confirm('Delete this key?')"><i class="bi bi-trash"></i></a></td>
    </tr>{% endfor %}</tbody></table></div>
  {% else %}<p style="color:#6b7280;margin:0;text-align:center;padding:30px 0">
    No API keys yet. Create your first one above 👆</p>{% endif %}
</div>
<script>
(function(){
  const radios=document.querySelectorAll('input[name="expiry_type"]');
  const row=document.getElementById('durationRow');
  const label=document.getElementById('durationLabel');
  const input=document.getElementById('durationInput');
  const defaults={demo:24,premium:30};let lastType='premium';
  function update(){
    const s=document.querySelector('input[name="expiry_type"]:checked');
    if(!s)return;const v=s.value;
    if(v==='permanent'){row.style.display='none';return;}
    row.style.display='';
    if(v!==lastType){input.value=defaults[v]||1;lastType=v;}
    label.textContent=(v==='demo')?'Duration (Hours)':'Duration (Days)';
  }
  radios.forEach(r=>r.addEventListener('change',update));update();
})();
</script>
"""

KEYS_HTML = """
<div class="section-head"><h2>API Keys</h2><p>All keys with their status and usage.</p></div>
<div class="card-dark">
  {% if keys %}
  <div style="overflow-x:auto"><table class="table-dark-custom">
    <thead><tr><th>Client</th><th>Key Name</th><th>Endpoint</th><th>Prefix</th>
      <th>Status</th><th>Expires</th><th>Calls</th><th>Last Used</th><th>Actions</th></tr></thead>
    <tbody>{% for k in keys %}<tr>
      <td><b>{{ k['client_name'] or '—' }}</b></td>
      <td style="color:#9ca3af">{{ k['key_name'] or '—' }}</td>
      <td><span class="badge-status active">{{ services[k['service']].label }}</span></td>
      <td><span class="code-pill">{{ k['prefix'] }}…</span></td>
      <td>{% set st = k['status'] %}
        <span class="badge-status {{ 'active' if st=='Active' else 'inactive' if st=='Inactive' else 'expired' if st=='Expired' else 'limit' }}">{{ st }}</span></td>
      <td>{{ k['expires_at'][:16] if k['expires_at'] else '♾️ Permanent' }}</td>
      <td>{{ k['searches_used'] }} / {{ k['search_limit'] if k['search_limit'] is not none else '∞' }}</td>
      <td>{{ k['last_used_at'][:16] if k['last_used_at'] else '—' }}</td>
      <td><a href="/toggle/{{ k['id'] }}" class="action-btn"><i class="bi bi-power"></i></a>
        <a href="/delete/{{ k['id'] }}" class="action-btn danger"
           onclick="return confirm('Delete this key?')"><i class="bi bi-trash"></i></a></td>
    </tr>{% endfor %}</tbody></table></div>
  {% else %}<p style="color:#6b7280;margin:0;text-align:center;padding:40px 0">No keys yet.</p>{% endif %}
</div>
"""

RESULT_HTML = """
<div class="section-head"><h2>✅ API Key Created</h2>
  <p>Copy this key now — it will never be shown again.</p></div>
<div class="card-dark">
  <label class="form-label">Your API Key</label>
  <div style="background:#0d1424;border:1px dashed #10b981;padding:16px;border-radius:10px;
              font-family:monospace;color:#00ff88;font-size:14px;word-break:break-all;
              margin-bottom:14px" id="rawkey">{{ raw_key }}</div>
  <button class="btn-green" onclick="copyKey()"><i class="bi bi-clipboard"></i> Copy Key</button>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:26px">
    <div><div class="form-label">Client Name</div><b>{{ client_name }}</b></div>
    <div><div class="form-label">Key Name</div><b>{{ key_name }}</b></div>
    <div><div class="form-label">Endpoint</div><b>{{ svc.label }}</b></div>
    <div><div class="form-label">Expires</div><b>{{ expires }}</b></div>
    <div><div class="form-label">Search Limit</div><b>{{ limit }}</b></div>
  </div>
  <label class="form-label" style="margin-top:26px">Usage Example</label>
  <div style="background:#0d1424;border:1px solid #1e293b;padding:12px;border-radius:10px;
              font-family:monospace;font-size:12.5px;color:#00ff88;word-break:break-all">{{ example_url }}</div>
  <div style="margin-top:26px">
    <a href="/dashboard" class="btn-green"><i class="bi bi-arrow-left"></i> Back to Dashboard</a></div>
</div>
<script>
function copyKey(){navigator.clipboard.writeText(
  document.getElementById('rawkey').innerText.trim()).then(()=>alert('API Key copied!'));}
</script>
"""

DOCS_HTML = """
<div class="section-head"><h2>API Documentation</h2>
  <p>Replace <code style="color:#00ff88">{key}</code> with your API key.</p></div>
<div class="card-dark"><div style="overflow-x:auto"><table class="table-dark-custom">
  <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
  <tbody>
    <tr><td><code style="color:#00ff88">/api/all/{phone}?key={key}&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>Send ALL types</td></tr>
    <tr><td><code style="color:#00ff88">/api/sms/{phone}?key={key}&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>Send SMS flood</td></tr>
    <tr><td><code style="color:#00ff88">/api/call/{phone}?key={key}&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>Send Call flood</td></tr>
    <tr><td><code style="color:#00ff88">/api/whatsapp/{phone}?key={key}&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>All WhatsApp sections</td></tr>
    <tr><td><code style="color:#00ff88">/api/whatsapp/section1/{phone}?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>WhatsApp · Meta / Facebook</td></tr>
    <tr><td><code style="color:#00ff88">/api/whatsapp/section2/{phone}?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>WhatsApp · Twilio & SMS Gateways</td></tr>
    <tr><td><code style="color:#00ff88">/api/whatsapp/section3/{phone}?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>WhatsApp · Third Party Services</td></tr>
    <tr><td><code style="color:#00ff88">/api/whatsapp/section4/{phone}?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>WhatsApp · Gupshup & Others</td></tr>
    <tr><td><code style="color:#00ff88">/api/gambling/{phone}?key={key}&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>Gambling SMS flood</td></tr>
    <tr><td><code style="color:#00ff88">/api/master/{phone}?key={key}&types=sms&count=2</code></td>
      <td><span class="badge-status active">GET</span></td><td>Master with filter</td></tr>
    <tr><td><code style="color:#00ff88">/api/health?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>Health check</td></tr>
    <tr><td><code style="color:#00ff88">/api/stats?key={key}</code></td>
      <td><span class="badge-status active">GET</span></td><td>API statistics</td></tr>
  </tbody></table></div></div>
"""


def render(body, title="Dashboard", page="dashboard"):
    return render_template_string(BASE_HTML, body=body, title=title,
                                  page=page, year=datetime.now().year, session=session)


# ============================================================
#  ROUTES
# ============================================================
@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == ADMIN_USER and request.form["password"] == ADMIN_PASS:
            session.permanent = True
            session["logged_in"]  = True
            session["user"]       = request.form["username"].capitalize()
            return redirect(url_for("dashboard"))
        flash("Invalid username or password")
    return render_template_string(LOGIN_HTML)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    rows = db.execute("SELECT * FROM api_keys ORDER BY id DESC LIMIT 10").fetchall()
    keys = []
    for r in rows:
        d = dict(r); d["status"] = key_status(r); keys.append(d)

    all_rows    = db.execute("SELECT * FROM api_keys").fetchall()
    total       = len(all_rows)
    active      = sum(1 for r in all_rows if key_status(r) == "Active")
    total_calls = sum(r["searches_used"] for r in all_rows)
    today_str   = datetime.now(timezone.utc).date().isoformat()
    today_calls = sum(r["searches_used"] for r in all_rows
                      if r["last_used_at"] and r["last_used_at"][:10] == today_str)
    pct_active  = round((active / total * 100), 1) if total else 0
    pct_today   = round((today_calls / total_calls * 100), 1) if total_calls else 0

    body = render_template_string(DASHBOARD_HTML, keys=keys, services=SERVICES,
                                  total=total, active=active, total_calls=total_calls,
                                  today_calls=today_calls,
                                  pct_active=pct_active, pct_today=pct_today)
    return render(body, "Dashboard", "dashboard")


@app.route("/keys")
@login_required
def keys_page():
    db = get_db()
    rows = db.execute("SELECT * FROM api_keys ORDER BY id DESC").fetchall()
    keys = []
    for r in rows:
        d = dict(r); d["status"] = key_status(r); keys.append(d)
    body = render_template_string(KEYS_HTML, keys=keys, services=SERVICES)
    return render(body, "API Keys", "keys")


@app.route("/docs")
@login_required
def docs_page():
    return render(DOCS_HTML, "API Docs", "docs")


@app.route("/settings")
@login_required
def settings():
    body = """
    <div class="section-head"><h2>Settings</h2><p>System configuration.</p></div>
    <div class="card-dark"><p style="margin:0;color:#9ca3af">
      Admin credentials set via environment variables
      (<code style="color:#00ff88">ADMIN_USER</code>,
      <code style="color:#00ff88">ADMIN_PASS</code>).</p></div>
    """
    return render(body, "Settings", "settings")


@app.route("/create", methods=["POST"])
@login_required
def create_key():
    client_name = request.form.get("client_name", "").strip() or "Unknown Client"
    key_name    = request.form.get("key_name", "").strip() or "Unnamed Key"
    custom_key  = request.form.get("custom_key", "").strip()
    service     = request.form.get("service", "all")

    if service not in SERVICES:
        flash("Unknown service", "danger"); return redirect(url_for("dashboard"))

    limit_str    = request.form.get("search_limit", "").strip()
    search_limit = int(limit_str) if limit_str.isdigit() and int(limit_str) > 0 else None

    expiry_type = request.form.get("expiry_type", "premium")
    duration    = int(request.form.get("duration_value") or 0)

    if expiry_type == "permanent":
        expires_at = None
    elif expiry_type == "demo":
        hours = duration or 24
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    else:
        days = duration or 30
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    if custom_key:
        raw_key  = custom_key
        key_hash = hash_key(raw_key)
    else:
        raw_key, key_hash = generate_api_key()
    prefix = make_prefix(raw_key)

    db = get_db()
    if db.execute("SELECT id FROM api_keys WHERE key_hash=?", (key_hash,)).fetchone():
        flash("❌ This exact API key already exists.", "danger")
        return redirect(url_for("dashboard"))

    try:
        db.execute("""
            INSERT INTO api_keys (client_name, key_name, service, prefix, key_hash, expires_at, search_limit)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (client_name, key_name, service, prefix, key_hash, expires_at, search_limit))
    except sqlite3.IntegrityError as e:
        flash(f"❌ DB error: {e}", "danger"); return redirect(url_for("dashboard"))

    svc = SERVICES[service]
    base = request.host_url.rstrip("/")
    if svc["has_phone"]:
        example_url = f"{base}/api/{service}/9876543210?key={raw_key}&count=2"
    else:
        example_url = f"{base}/api/{service}?key={raw_key}"

    body = render_template_string(
        RESULT_HTML, raw_key=raw_key, client_name=client_name, key_name=key_name,
        service=service, svc=svc,
        expires=expires_at[:16] if expires_at else "♾️ Permanent",
        limit=search_limit if search_limit is not None else "♾️ Unlimited",
        example_url=example_url,
    )
    return render(body, "Key Created", "dashboard")


@app.route("/toggle/<int:key_id>")
@login_required
def toggle_key(key_id):
    db = get_db()
    row = db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        flash("Key not found", "danger"); return redirect(url_for("dashboard"))
    new_state = 0 if row["is_active"] else 1
    db.execute("UPDATE api_keys SET is_active=? WHERE id=?", (new_state, key_id))
    flash(f"Key '{row['key_name']}' {'deactivated' if new_state==0 else 'activated'}.", "info")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/delete/<int:key_id>")
@login_required
def delete_key(key_id):
    db = get_db()
    row = db.execute("SELECT key_name FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if row:
        db.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        flash(f"Key '{row['key_name']}' deleted.", "success")
    return redirect(request.referrer or url_for("dashboard"))


# ============================================================
#  PUBLIC API GATEWAY
# ============================================================
def _proxy_common(service, phone=None):
    if service not in SERVICES:
        return jsonify({"error": "Unknown service", "available": list(SERVICES.keys())}), 404

    raw_key = request.args.get("key")
    if not raw_key:
        return jsonify({"error": "API key required. Pass ?key=YOUR_KEY"}), 401

    db = get_db()
    row = db.execute("SELECT * FROM api_keys WHERE key_hash=?",
                     (hash_key(raw_key),)).fetchone()
    if not row:
        return jsonify({"error": "Invalid API key"}), 403

    valid, msg = validate_key(row)
    if not valid:
        return jsonify({"error": msg}), 403

    svc = SERVICES[service]
    if svc["has_phone"] and not phone:
        return jsonify({"error": f"Phone required. Use /api/{service}/<phone>"}), 400
    if not svc["has_phone"] and phone:
        return jsonify({"error": f"/api/{service} does not take a phone"}), 400

    path = svc["path"].replace("{phone}", phone) if svc["has_phone"] else svc["path"]
    url  = UPSTREAM_BASE + path
    params = {k: v for k, v in request.args.items() if k != "key"}

    try:
        r = requests.get(url, params=params, timeout=25)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        status = r.status_code
    except requests.Timeout:
        return jsonify({"error": "Upstream timeout"}), 504
    except Exception as e:
        return jsonify({"error": f"Upstream error: {str(e)}"}), 502

    data = rewrite_json(data)

    try:
        db.execute("""
            UPDATE api_keys SET searches_used = searches_used + 1, last_used_at = ?
            WHERE id = ?
        """, (datetime.now(timezone.utc).isoformat(), row["id"]))
    except Exception:
        pass

    return jsonify(data), status


@app.route("/api/<service>", methods=["GET"])
def proxy_no_phone(service):
    return _proxy_common(service, phone=None)


@app.route("/api/<service>/<phone>", methods=["GET"])
def proxy_with_phone(service, phone):
    return _proxy_common(service, phone=phone)


@app.route("/api/whatsapp/section<int:section>/<phone>", methods=["GET"])
def proxy_whatsapp_section(section, phone):
    sid = f"wa{section}"
    if sid not in SERVICES:
        return jsonify({"error": "Unknown WhatsApp section"}), 404
    return _proxy_common(sid, phone=phone)


# ============================================================
#  INIT DB (idempotent, safe to call on every import)
# ============================================================
init_db()


# ============================================================
#  ENTRY
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🚀 AadixSMS API Manager on :{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)