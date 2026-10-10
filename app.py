"""
============================================================
  ASURxADITYA API Manager — SQLite Edition
  Developer: ADITYAxOSHIT
  APIs: Num→Info, Aadhaar Info, Aadhaar Family
  No PostgreSQL required — SQLite with WAL mode
  Handles 100+ concurrent users via threading
============================================================
"""

import os, sys, re, time, hashlib, secrets, logging, threading, sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict, deque
from contextlib import contextmanager

import requests
from requests.adapters import HTTPAdapter
from flask import (
    Flask, request, jsonify, render_template_string,
    redirect, url_for, flash, session
)

# ============================================================
#  LOGGING
# ============================================================
logging.basicConfig(
    level  = logging.INFO,
    format = "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt= "%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("asur")

# ============================================================
#  CONFIG
# ============================================================
MASTER_KEY         = os.environ.get("MASTER_KEY", "@ASUR_ABOUT")
ADMIN_USER         = os.environ.get("ADMIN_USER", "aditya05712")
ADMIN_PASS         = os.environ.get("ADMIN_PASS", "aditya@29007")
SECRET_KEY         = os.environ.get("SECRET_KEY", "asurxaditya-fixed-secret-9f2b7c1d4e8a-2025")
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "120"))
UPSTREAM_TIMEOUT   = int(os.environ.get("UPSTREAM_TIMEOUT", "25"))

# SQLite path — writable location for Railway
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/tmp/apikeys.db")

log.info(f"[BOOT] Python {sys.version.split()[0]}")
log.info(f"[BOOT] SQLite DB: {SQLITE_PATH}")

# ============================================================
#  SERVICES  (upstream URLs hidden from clients)
# ============================================================
SERVICES = {
    "number": {
        "label":       "NUM → INFO",
        "upstream":    "https://num-to-info.asurpapa.workers.dev/api",
        "param":       "number",
        "icon":        "bi-telephone-fill",
        "has_value":   True,
        "desc":        "Mobile number full information",
        "placeholder": "9876543210",
    },
    "aadhar": {
        "label":       "AADHAAR INFO",
        "upstream":    "https://aadhaar.asurpapa.workers.dev/api",
        "param":       "aadhaar",
        "icon":        "bi-person-vcard-fill",
        "has_value":   True,
        "desc":        "Aadhaar card information lookup",
        "placeholder": "123412341234",
    },
    "aadhar-family": {
        "label":       "AADHAAR FAMILY",
        "upstream":    "https://aadhaar-family.asurpapa.workers.dev/api",
        "param":       "aadhaar",
        "icon":        "bi-people-fill",
        "has_value":   True,
        "desc":        "Aadhaar family members info",
        "placeholder": "352283381852",
    },
}

# ============================================================
#  FLASK APP
# ============================================================
app = Flask(__name__)
app.config.update(
    SECRET_KEY                 = SECRET_KEY,
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12),
    JSON_SORT_KEYS             = False,
)


# ============================================================
#  DATABASE  —  SQLite with WAL mode for high concurrency
# ============================================================
_write_lock = threading.Lock()   # serialize writes to avoid lock errors


def _new_conn():
    conn = sqlite3.connect(
        SQLITE_PATH,
        timeout           = 30,       # wait up to 30s before lock error
        check_same_thread = False,
        isolation_level   = None,     # autocommit
    )
    conn.row_factory = sqlite3.Row
    # WAL mode: readers and writers don't block each other
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-64000")
    return conn


@contextmanager
def db_cursor():
    conn = _new_conn()
    try:
        cur = conn.cursor()
        yield cur
    finally:
        try: cur.close()
        except Exception: pass
        try: conn.close()
        except Exception: pass


def db_fetch_one(sql, params=()):
    try:
        with db_cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        log.error(f"[DB FETCH1] {e}")
        return None


def db_fetch_all(sql, params=()):
    try:
        with db_cursor() as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        log.error(f"[DB FETCH-ALL] {e}")
        return []


def db_execute(sql, params=()):
    try:
        with _write_lock:
            with db_cursor() as cur:
                cur.execute(sql, params)
                return cur.rowcount
    except Exception as e:
        log.error(f"[DB EXEC] {e}")
        return -1


def init_db():
    try:
        with _write_lock:
            with db_cursor() as cur:
                cur.execute("""
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
                cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (is_active)")
        log.info("[DB] Schema + indexes ready ✅")
    except Exception as e:
        log.error(f"[DB INIT ERROR] {e}")


# ============================================================
#  UPSTREAM HTTP CLIENT
# ============================================================
_http = requests.Session()
_http.headers.update({
    "User-Agent": "ASURxADITYA/1.0",
    "Accept":     "application/json, */*",
})
_adapter = HTTPAdapter(pool_connections=25, pool_maxsize=50, max_retries=0)
_http.mount("https://", _adapter)
_http.mount("http://",  _adapter)


def call_upstream(url, params):
    last_err = None
    for attempt in (1, 2):
        try:
            r = _http.get(url, params=params, timeout=UPSTREAM_TIMEOUT)
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, {"raw": r.text}
        except requests.Timeout:
            last_err = ("timeout", f"Upstream timeout after {UPSTREAM_TIMEOUT}s")
            log.warning(f"[UPSTREAM] Timeout attempt {attempt}")
        except requests.ConnectionError:
            last_err = ("connection", "Cannot reach upstream service")
            log.warning(f"[UPSTREAM] ConnErr attempt {attempt}")
        except Exception as e:
            last_err = ("error", f"{type(e).__name__}")
            log.error(f"[UPSTREAM] Error: {e}")
            break
    return None, last_err


# ============================================================
#  RATE LIMITER
# ============================================================
rate_store = defaultdict(deque)
rate_lock  = threading.Lock()


def check_rate_limit(key_hash):
    now = time.time()
    with rate_lock:
        dq = rate_store[key_hash]
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_PER_MIN:
            return False, 0
        dq.append(now)
        return True, RATE_LIMIT_PER_MIN - len(dq)


# ============================================================
#  UTILITIES
# ============================================================
def gen_key():
    raw = "adx_" + secrets.token_urlsafe(24)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def make_prefix(raw):
    return raw[:10] + "_" + secrets.token_hex(2)


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w


def key_status(row):
    try:
        if not row["is_active"]:
            return "Inactive"
        if row["expires_at"]:
            exp = datetime.fromisoformat(str(row["expires_at"]))
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
            exp = datetime.fromisoformat(str(row["expires_at"]))
            if datetime.now(timezone.utc) > exp.replace(tzinfo=timezone.utc):
                return False, "API key has expired"
        if row["search_limit"] is not None and row["searches_used"] >= row["search_limit"]:
            return False, "Search limit reached"
        return True, None
    except Exception as e:
        return False, f"Validation error: {e}"


# ============================================================
#  🔁 RESPONSE REBRANDING
#  - name     → "ASUR/ADITYA"
#  - contact  → REMOVED
#  - footer   → "Powered by ASURxADITYA"
# ============================================================
OLD_BRAND_STR = re.compile(r"@ASURPAPA|@asurpapa|ASUR_ABOUT|asurpapa", re.IGNORECASE)


def rewrite_credit(credit):
    if not isinstance(credit, dict):
        return credit
    new_credit = {}
    for k, v in credit.items():
        lk = k.lower()
        if lk == "name":
            new_credit[k] = "ASUR/ADITYA"
        elif lk == "contact":
            continue   # removed completely
        elif lk == "footer":
            new_credit[k] = "Powered by ASURxADITYA"
        else:
            new_credit[k] = rewrite_json(v)
    return new_credit


def rewrite_json(obj):
    if isinstance(obj, dict):
        keys_lower = {k.lower() for k in obj.keys()}
        # Detect credit block: contains "name" + ("footer" or "developer")
        if "name" in keys_lower and ("footer" in keys_lower or "developer" in keys_lower):
            return rewrite_credit(obj)
        return {k: rewrite_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [rewrite_json(i) for i in obj]
    if isinstance(obj, str):
        return OLD_BRAND_STR.sub("@Aditya05712", obj)
    return obj


# ============================================================
#  GUARDS & ERROR HANDLERS
# ============================================================
PUBLIC_PATHS = ("/login", "/logout", "/favicon.ico", "/healthz", "/_health")


@app.before_request
def restrict_access():
    p = request.path
    if p.startswith("/api/") or p in PUBLIC_PATHS or p.startswith("/static/"):
        return
    if not session.get("logged_in"):
        return redirect(url_for("login"))


@app.after_request
def add_headers(resp):
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.errorhandler(500)
def e500(e):
    log.exception("Unhandled 500")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal error, retry"}), 500
    return "Internal server error — retry in a moment", 500


@app.errorhandler(404)
def e404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return redirect(url_for("dashboard"))


@app.errorhandler(Exception)
def e_all(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    log.exception("Unhandled exception")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal error"}), 500
    return "Error — retry in a moment", 500


@app.route("/healthz")
@app.route("/_health")
def healthz():
    try:
        row = db_fetch_one("SELECT 1 AS ok")
        return ("ok" if row else "db-empty"), 200
    except Exception as e:
        return f"db error: {e}", 500


# ============================================================
#  TEMPLATES
# ============================================================
BASE_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · ASURxADITYA</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#070b14;--bg-2:#0d1424;--sidebar:#0a0f1c;--card:#101827;--border:#1e293b;
--text:#e5e7eb;--muted:#6b7280;--green:#00ff88;--green-2:#10b981;--red:#ef4444;--amber:#f59e0b;}
*{box-sizing:border-box;}html,body{height:100%;}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;overflow-x:hidden;}
.layout{display:flex;min-height:100vh;}
.sidebar{width:250px;background:var(--sidebar);border-right:1px solid var(--border);padding:20px 14px;
display:flex;flex-direction:column;position:fixed;top:0;bottom:0;left:0;z-index:100;transition:transform .25s;}
.brand{display:flex;align-items:center;gap:10px;padding:4px 8px 22px;margin-bottom:6px;border-bottom:1px solid var(--border);}
.brand-logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--green),var(--green-2));
display:flex;align-items:center;justify-content:center;color:#062c1a;font-weight:800;font-size:18px;}
.brand-name{font-weight:700;font-size:14px;}.brand-sub{font-size:9.5px;color:var(--muted);letter-spacing:1.5px;}
.nav-section{font-size:10px;color:var(--muted);letter-spacing:1.5px;font-weight:600;padding:18px 12px 8px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:10px 14px;color:#94a3b8;border-radius:10px;
margin-bottom:3px;font-weight:500;font-size:13.5px;text-decoration:none;transition:.15s;}
.nav-link:hover{background:var(--card);color:var(--text);}
.nav-link.active{background:linear-gradient(90deg,rgba(0,255,136,.15),rgba(16,185,129,.05));
color:var(--green);box-shadow:inset 2px 0 0 var(--green);}
.nav-link i{font-size:17px;width:20px;}
.sidebar-foot{margin-top:auto;border-top:1px solid var(--border);padding-top:14px;}
.admin-card{display:flex;align-items:center;gap:10px;padding:10px;border-radius:10px;background:var(--card);
border:1px solid var(--border);margin-bottom:10px;}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--green),var(--green-2));
color:#062c1a;font-weight:800;display:flex;align-items:center;justify-content:center;font-size:14px;}
.admin-info small{color:var(--muted);font-size:11px;display:block;}.admin-info b{font-size:13px;}
.logout-btn{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;padding:9px;border-radius:9px;
background:transparent;color:#94a3b8;border:1px solid var(--border);font-size:12.5px;font-weight:600;text-decoration:none;}
.logout-btn:hover{color:var(--red);border-color:var(--red);}
.main{margin-left:250px;flex:1;padding:22px 28px;min-width:0;}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px;gap:16px;}
.top-actions{display:flex;align-items:center;gap:10px;}
.icon-btn{width:38px;height:38px;display:flex;align-items:center;justify-content:center;background:var(--card);
border:1px solid var(--border);color:#94a3b8;border-radius:10px;text-decoration:none;}
.icon-btn:hover{color:var(--green);border-color:var(--green-2);}
.card-dark{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:18px;}
.card-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.card-title h5{margin:0;font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px;}
.card-title h5 i{color:var(--green);}
.stat{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px 18px;position:relative;overflow:hidden;}
.stat::before{content:"";position:absolute;top:0;left:0;width:100%;height:3px;
background:linear-gradient(90deg,var(--green),var(--green-2));opacity:.8;}
.stat-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;}
.stat-label{font-size:10.5px;color:var(--muted);letter-spacing:1.2px;font-weight:600;}
.stat-icon{width:30px;height:30px;border-radius:8px;background:rgba(0,255,136,.1);color:var(--green);
display:flex;align-items:center;justify-content:center;font-size:15px;}
.stat-value{font-size:26px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px;}
.stat-sub{font-size:11.5px;color:var(--green);font-weight:600;}.stat-sub.muted{color:var(--muted);}
.form-label{font-size:10.5px;letter-spacing:1.2px;color:var(--muted);font-weight:600;
text-transform:uppercase;margin-bottom:8px;display:block;}
.form-control-dark{width:100%;background:var(--bg-2);border:1px solid var(--border);color:var(--text);
padding:11px 14px;border-radius:10px;font-size:13.5px;font-family:inherit;}
.form-control-dark:focus{outline:none;border-color:var(--green-2);box-shadow:0 0 0 3px rgba(16,185,129,.15);}
.form-control-dark::placeholder{color:#4b5563;}
.service-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;}
.svc-radio{display:none;}
.svc-card{background:var(--bg-2);border:1.5px solid var(--border);border-radius:11px;padding:16px 10px;
text-align:center;cursor:pointer;transition:.18s;display:flex;flex-direction:column;align-items:center;gap:8px;}
.svc-card i{font-size:24px;color:#94a3b8;}.svc-card span{font-size:11px;font-weight:700;letter-spacing:.6px;color:#94a3b8;}
.svc-card small{font-size:9.5px;color:#4b5563;display:block;margin-top:2px;line-height:1.2;}
.svc-radio:checked + .svc-card{border-color:var(--green);background:linear-gradient(180deg,rgba(0,255,136,.1),rgba(0,255,136,.02));}
.svc-radio:checked + .svc-card i,.svc-radio:checked + .svc-card span{color:var(--green);}
.expiry-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}
.exp-radio{display:none;}
.exp-card{background:var(--bg-2);border:1.5px solid var(--border);border-radius:11px;padding:14px 12px;
cursor:pointer;display:flex;align-items:center;gap:10px;transition:.18s;}
.exp-card i{font-size:18px;color:#94a3b8;}.exp-card b{font-size:12.5px;display:block;}.exp-card small{font-size:10.5px;color:var(--muted);}
.exp-radio:checked + .exp-card{border-color:var(--green);background:linear-gradient(180deg,rgba(0,255,136,.1),rgba(0,255,136,.02));}
.exp-radio:checked + .exp-card i{color:var(--green);}
.btn-green{background:linear-gradient(135deg,var(--green),var(--green-2));color:#052e16;border:none;
padding:12px 22px;border-radius:10px;font-weight:700;font-size:13.5px;cursor:pointer;display:inline-flex;
align-items:center;gap:8px;text-decoration:none;box-shadow:0 4px 20px rgba(0,255,136,.25);}
.btn-green:hover{transform:translateY(-1px);color:#052e16;}
.btn-ghost{background:var(--bg-2);border:1px solid var(--border);color:#94a3b8;padding:10px 16px;
border-radius:9px;font-size:12.5px;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;gap:6px;}
.table-dark-custom{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;}
.table-dark-custom th{text-align:left;font-size:10.5px;letter-spacing:1.2px;color:var(--muted);font-weight:600;
text-transform:uppercase;padding:10px 14px;border-bottom:1px solid var(--border);}
.table-dark-custom td{padding:14px;border-bottom:1px solid var(--border);vertical-align:middle;}
.badge-status{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:10.5px;font-weight:700;}
.badge-status.active{background:rgba(0,255,136,.12);color:var(--green);}
.badge-status.inactive{background:rgba(107,114,128,.18);color:#9ca3af;}
.badge-status.expired{background:rgba(239,68,68,.15);color:var(--red);}
.badge-status.limit{background:rgba(245,158,11,.15);color:var(--amber);}
.badge-status::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;}
.action-btn{width:30px;height:30px;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;
background:var(--bg-2);border:1px solid var(--border);color:#94a3b8;text-decoration:none;margin-right:4px;}
.action-btn:hover{color:var(--green);}.action-btn.danger:hover{color:var(--red);}
.code-pill{background:var(--bg-2);border:1px solid var(--border);padding:3px 8px;border-radius:6px;
font-family:'Courier New',monospace;font-size:11.5px;color:var(--green);}
.section-head{margin-bottom:20px;}.section-head h2{font-size:22px;font-weight:800;margin:0 0 4px 0;}
.section-head p{color:var(--muted);font-size:13px;margin:0;}
@media(max-width:900px){.sidebar{transform:translateX(-100%);}.sidebar.open{transform:translateX(0);}
.main{margin-left:0;padding:16px;}.menu-toggle{display:flex !important;}.expiry-grid{grid-template-columns:1fr;}}
.menu-toggle{display:none;width:38px;height:38px;align-items:center;justify-content:center;background:var(--card);
border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:18px;cursor:pointer;}
</style></head><body>
<div class="layout">
<aside class="sidebar" id="sidebar">
<div class="brand"><div class="brand-logo">A</div><div><div class="brand-name">ASURxADITYA</div>
<div class="brand-sub">API MANAGER</div></div></div>
<div class="nav-section">MAIN</div>
<a href="/dashboard" class="nav-link {{ 'active' if page=='dashboard' else '' }}"><i class="bi bi-grid-1x2-fill"></i> Dashboard</a>
<a href="/keys" class="nav-link {{ 'active' if page=='keys' else '' }}"><i class="bi bi-key-fill"></i> API Keys</a>
<a href="/docs" class="nav-link {{ 'active' if page=='docs' else '' }}"><i class="bi bi-book-fill"></i> API Docs</a>
<a href="/settings" class="nav-link {{ 'active' if page=='settings' else '' }}"><i class="bi bi-gear-fill"></i> Settings</a>
<div class="sidebar-foot"><div class="admin-card"><div class="avatar">A</div>
<div class="admin-info"><b>{{ session.get('user','Admin') }}</b><small>Administrator</small></div></div>
<a href="/logout" class="logout-btn"><i class="bi bi-box-arrow-right"></i> Logout</a></div>
</aside>
<main class="main">
<div class="topbar">
<button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')">
<i class="bi bi-list"></i></button>
<div style="flex:1"></div>
<div class="top-actions"><a href="/docs" class="icon-btn"><i class="bi bi-book"></i></a>
<div class="avatar" style="width:38px;height:38px;">A</div></div>
</div>
{% with messages = get_flashed_messages(with_categories=true) %}
{% for cat, msg in messages %}
<div class="alert alert-{{ cat }} alert-dismissible fade show" style="background:var(--card);border:1px solid var(--border);color:var(--text)">
{{ msg }}<button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button></div>
{% endfor %}{% endwith %}
{{ body|safe }}
</main></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
"""

LOGIN_HTML = """
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Login · ASURxADITYA</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>body{margin:0;background:#070b14;color:#e5e7eb;font-family:'Inter',sans-serif;min-height:100vh;
display:flex;align-items:center;justify-content:center;}
.box{width:380px;background:#101827;border:1px solid #1e293b;border-radius:16px;padding:36px 30px;}
.logo{width:52px;height:52px;border-radius:14px;margin:0 auto 16px;background:linear-gradient(135deg,#00ff88,#10b981);
color:#052e16;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;}
h2{text-align:center;margin:0 0 6px;font-size:20px;}
p.sub{text-align:center;color:#6b7280;font-size:12.5px;margin:0 0 26px;}
label{font-size:11px;color:#6b7280;letter-spacing:1.2px;font-weight:600;text-transform:uppercase;
display:block;margin-bottom:7px;}
input{width:100%;background:#0d1424;border:1px solid #1e293b;color:#e5e7eb;padding:12px 14px;border-radius:10px;
font-size:14px;margin-bottom:16px;font-family:inherit;}
input:focus{outline:none;border-color:#10b981;}
button{width:100%;background:linear-gradient(135deg,#00ff88,#10b981);color:#052e16;border:none;padding:13px;
border-radius:10px;font-weight:700;font-size:14px;cursor:pointer;}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:10px;
border-radius:8px;font-size:12.5px;margin-bottom:16px;}</style></head><body>
<form class="box" method="POST"><div class="logo">A</div><h2>Welcome Back</h2>
<p class="sub">Sign in to ASURxADITYA Control Panel</p>
{% with messages = get_flashed_messages() %}{% for m in messages %}<div class="err">{{ m }}</div>{% endfor %}{% endwith %}
<label>Username</label><input type="text" name="username" required autofocus autocomplete="username">
<label>Password</label><input type="password" name="password" required autocomplete="current-password">
<button type="submit"><i class="bi bi-box-arrow-in-right"></i> Login</button>
<p style="text-align:center;font-size:11px;color:#4b5563;margin-top:20px">
Developer: <b style="color:#00ff88">ADITYAxOSHIT</b></p>
</form></body></html>
"""

DASHBOARD_HTML = """
<div class="section-head"><h2>Good Morning, Admin 👋</h2><p>Here's what's happening today.</p></div>
<div class="row g-3 mb-4">
<div class="col-6 col-lg-3"><div class="stat"><div class="stat-top"><div class="stat-label">TOTAL KEYS</div>
<div class="stat-icon"><i class="bi bi-key-fill"></i></div></div>
<div class="stat-value">{{ total }}</div><div class="stat-sub">{{ active }} active</div></div></div>
<div class="col-6 col-lg-3"><div class="stat"><div class="stat-top"><div class="stat-label">ACTIVE KEYS</div>
<div class="stat-icon"><i class="bi bi-shield-check"></i></div></div>
<div class="stat-value">{{ active }}</div><div class="stat-sub">{{ pct_active }}%</div></div></div>
<div class="col-6 col-lg-3"><div class="stat"><div class="stat-top"><div class="stat-label">TOTAL CALLS</div>
<div class="stat-icon"><i class="bi bi-activity"></i></div></div>
<div class="stat-value">{{ total_calls }}</div><div class="stat-sub muted">All time</div></div></div>
<div class="col-6 col-lg-3"><div class="stat"><div class="stat-top"><div class="stat-label">TODAY</div>
<div class="stat-icon"><i class="bi bi-lightning-charge-fill"></i></div></div>
<div class="stat-value">{{ today_calls }}</div><div class="stat-sub muted">{{ pct_today }}%</div></div></div>
</div>
<div class="card-dark"><div class="card-title"><h5><i class="bi bi-plus-circle-fill"></i> Create API Key</h5></div>
<form method="POST" action="/create">
<div class="row g-3 mb-3">
<div class="col-md-6"><label class="form-label">Client Name</label>
<input type="text" name="client_name" class="form-control-dark" placeholder="Rajesh Kumar" required></div>
<div class="col-md-6"><label class="form-label">Key Name</label>
<input type="text" name="key_name" class="form-control-dark" placeholder="Premium-Key" required></div>
</div>
<div class="mb-3"><label class="form-label">Custom API Key (blank = auto)</label>
<input type="text" name="custom_key" class="form-control-dark" placeholder="leave empty"></div>
<label class="form-label">Select API</label>
<div class="service-grid mb-3">
{% for sid, svc in services.items() %}
<label style="margin:0"><input type="radio" name="service" value="{{ sid }}" class="svc-radio" {{ 'checked' if loop.first }}>
<div class="svc-card"><i class="bi {{ svc.icon }}"></i><span>{{ svc.label }}</span>
<small>{{ svc.desc }}</small></div></label>
{% endfor %}</div>
<div class="row g-3 mb-3">
<div class="col-md-4"><label class="form-label">Search Limit</label>
<input type="number" name="search_limit" class="form-control-dark" placeholder="blank=unlimited" min="1"></div>
<div class="col-md-8"><label class="form-label">Expiry</label>
<div class="expiry-grid">
<label style="margin:0"><input type="radio" name="expiry_type" value="demo" class="exp-radio">
<div class="exp-card"><i class="bi bi-lightning-charge-fill"></i><div><b>Demo</b><small>Hourly</small></div></div></label>
<label style="margin:0"><input type="radio" name="expiry_type" value="premium" class="exp-radio" checked>
<div class="exp-card"><i class="bi bi-gem"></i><div><b>Premium</b><small>Days</small></div></div></label>
<label style="margin:0"><input type="radio" name="expiry_type" value="permanent" class="exp-radio">
<div class="exp-card"><i class="bi bi-infinity"></i><div><b>Permanent</b><small>No expiry</small></div></div></label>
</div></div></div>
<div class="row g-3 mb-4" id="durationRow"><div class="col-md-4">
<label class="form-label" id="durationLabel">Duration (Days)</label>
<input type="number" name="duration_value" id="durationInput" class="form-control-dark" value="30" min="1"></div></div>
<button type="submit" class="btn-green"><i class="bi bi-plus-lg"></i> Create Key</button>
</form></div>
<div class="card-dark"><div class="card-title">
<h5><i class="bi bi-clock-history"></i> Recent Keys</h5>
<a href="/keys" class="btn-ghost">View All <i class="bi bi-arrow-right"></i></a></div>
{% if keys %}<div style="overflow-x:auto"><table class="table-dark-custom">
<thead><tr><th>Client</th><th>Key</th><th>API</th><th>Status</th><th>Calls</th><th>Actions</th></tr></thead>
<tbody>{% for k in keys %}<tr>
<td><b>{{ k.client_name or '—' }}</b></td>
<td style="color:#9ca3af">{{ k.key_name or '—' }}</td>
<td><span class="badge-status active">{{ services[k.service].label }}</span></td>
<td><span class="badge-status {{ 'active' if k.status=='Active' else 'inactive' if k.status=='Inactive' else 'expired' if k.status=='Expired' else 'limit' }}">{{ k.status }}</span></td>
<td>{{ k.searches_used }} / {{ k.search_limit if k.search_limit is not none else '∞' }}</td>
<td><a href="/toggle/{{ k.id }}" class="action-btn"><i class="bi bi-power"></i></a>
<a href="/delete/{{ k.id }}" class="action-btn danger" onclick="return confirm('Delete?')"><i class="bi bi-trash"></i></a></td>
</tr>{% endfor %}</tbody></table></div>
{% else %}<p style="color:#6b7280;text-align:center;padding:30px 0">No keys yet 👆</p>{% endif %}</div>
<script>
(function(){var rs=document.querySelectorAll('input[name="expiry_type"]');var rw=document.getElementById('durationRow');
var l=document.getElementById('durationLabel');var i=document.getElementById('durationInput');
var d={demo:24,premium:30};var t='premium';
function u(){var s=document.querySelector('input[name="expiry_type"]:checked');if(!s)return;
if(s.value==='permanent'){rw.style.display='none';return;}rw.style.display='';
if(s.value!==t){i.value=d[s.value]||1;t=s.value;}
l.textContent=(s.value==='demo')?'Duration (Hours)':'Duration (Days)';}
rs.forEach(function(x){x.addEventListener('change',u);});u();})();
</script>
"""

KEYS_HTML = """
<div class="section-head"><h2>API Keys</h2><p>All keys.</p></div>
<div class="card-dark">{% if keys %}<div style="overflow-x:auto"><table class="table-dark-custom">
<thead><tr><th>Client</th><th>Key</th><th>API</th><th>Status</th><th>Expires</th><th>Calls</th><th>Actions</th></tr></thead>
<tbody>{% for k in keys %}<tr>
<td><b>{{ k.client_name or '—' }}</b></td><td style="color:#9ca3af">{{ k.key_name or '—' }}</td>
<td><span class="badge-status active">{{ services[k.service].label }}</span></td>
<td><span class="badge-status {{ 'active' if k.status=='Active' else 'inactive' if k.status=='Inactive' else 'expired' if k.status=='Expired' else 'limit' }}">{{ k.status }}</span></td>
<td>{{ k.expires_at[:16] if k.expires_at else '♾️' }}</td>
<td>{{ k.searches_used }} / {{ k.search_limit if k.search_limit is not none else '∞' }}</td>
<td><a href="/toggle/{{ k.id }}" class="action-btn"><i class="bi bi-power"></i></a>
<a href="/delete/{{ k.id }}" class="action-btn danger" onclick="return confirm('Delete?')"><i class="bi bi-trash"></i></a></td>
</tr>{% endfor %}</tbody></table></div>
{% else %}<p style="color:#6b7280;text-align:center;padding:40px 0">No keys.</p>{% endif %}</div>
"""

RESULT_HTML = """
<div class="section-head"><h2>✅ Key Created</h2><p>Copy now — won't be shown again.</p></div>
<div class="card-dark"><label class="form-label">Your API Key</label>
<div style="background:#0d1424;border:1px dashed #10b981;padding:16px;border-radius:10px;
font-family:monospace;color:#00ff88;font-size:14px;word-break:break-all;margin-bottom:14px" id="rawkey">{{ raw_key }}</div>
<button class="btn-green" onclick="copyKey()"><i class="bi bi-clipboard"></i> Copy Key</button>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:26px">
<div><div class="form-label">Client</div><b>{{ client_name }}</b></div>
<div><div class="form-label">Key Name</div><b>{{ key_name }}</b></div>
<div><div class="form-label">API</div><b>{{ svc.label }}</b></div>
<div><div class="form-label">Expires</div><b>{{ expires }}</b></div>
<div><div class="form-label">Limit</div><b>{{ limit }}</b></div></div>
<label class="form-label" style="margin-top:26px">Usage</label>
<div style="background:#0d1424;border:1px solid #1e293b;padding:12px;border-radius:10px;
font-family:monospace;font-size:12.5px;color:#00ff88;word-break:break-all">{{ example_url }}</div>
<div style="margin-top:26px"><a href="/dashboard" class="btn-green"><i class="bi bi-arrow-left"></i> Dashboard</a></div></div>
<script>function copyKey(){navigator.clipboard.writeText(
document.getElementById('rawkey').innerText.trim()).then(function(){alert('Copied!');});}</script>
"""

DOCS_HTML = """
<div class="section-head"><h2>API Docs</h2>
<p>Replace <code style="color:#00ff88">{key}</code> with your API key.</p></div>
<div class="card-dark"><div style="overflow-x:auto"><table class="table-dark-custom">
<thead><tr><th>Endpoint</th><th>Description</th></tr></thead><tbody>
<tr><td><code style="color:#00ff88">/api/number/{number}?key={key}</code></td>
<td>Num → Info · Mobile number full information</td></tr>
<tr><td><code style="color:#00ff88">/api/aadhar/{aadhaar}?key={key}</code></td>
<td>Aadhaar Info · 12-digit Aadhaar lookup</td></tr>
<tr><td><code style="color:#00ff88">/api/aadhar-family/{aadhaar}?key={key}</code></td>
<td>Aadhaar Family · Family members info</td></tr>
</tbody></table></div>
<div style="margin-top:20px;padding:14px;background:var(--bg-2);border-radius:10px;border:1px solid var(--border)">
<p style="margin:0;color:#9ca3af;font-size:12.5px">
<b style="color:#00ff88">Response Branding:</b><br>
All responses carry the credit block:
<code style="color:#a5b4fc">name: "ASUR/ADITYA"</code>,
<code style="color:#a5b4fc">footer: "Powered by ASURxADITYA"</code>.
The original upstream is never exposed.
</p></div>
</div>
"""


def render(body, title="Dashboard", page="dashboard"):
    return render_template_string(BASE_HTML, body=body, title=title,
                                  page=page, year=datetime.now().year, session=session)


# ============================================================
#  WEB ROUTES
# ============================================================
@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session.permanent = True
            session["logged_in"] = True
            session["user"] = ADMIN_USER.capitalize()
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
    rows = db_fetch_all("SELECT * FROM api_keys ORDER BY id DESC LIMIT 10")
    for k in rows:
        k["status"] = key_status(k)

    all_rows    = db_fetch_all("SELECT * FROM api_keys")
    total       = len(all_rows)
    active      = sum(1 for r in all_rows if key_status(r) == "Active")
    total_calls = sum(r.get("searches_used", 0) or 0 for r in all_rows)
    today_str   = datetime.now(timezone.utc).date().isoformat()
    today_calls = sum(r.get("searches_used", 0) or 0 for r in all_rows
                      if r.get("last_used_at") and str(r["last_used_at"])[:10] == today_str)
    pct_active  = round((active / total * 100), 1) if total else 0
    pct_today   = round((today_calls / total_calls * 100), 1) if total_calls else 0

    body = render_template_string(DASHBOARD_HTML, keys=rows, services=SERVICES,
                                  total=total, active=active, total_calls=total_calls,
                                  today_calls=today_calls, pct_active=pct_active, pct_today=pct_today)
    return render(body, "Dashboard", "dashboard")


@app.route("/keys")
@login_required
def keys_page():
    rows = db_fetch_all("SELECT * FROM api_keys ORDER BY id DESC")
    for k in rows:
        k["status"] = key_status(k)
    return render(render_template_string(KEYS_HTML, keys=rows, services=SERVICES), "API Keys", "keys")


@app.route("/docs")
@login_required
def docs_page():
    return render(DOCS_HTML, "API Docs", "docs")


@app.route("/settings")
@login_required
def settings():
    body = f"""
    <div class="section-head"><h2>Settings</h2></div>
    <div class="card-dark"><p style="margin:0;color:#9ca3af;line-height:1.8">
    <b style="color:#00ff88">Database:</b> SQLite ({SQLITE_PATH})<br>
    <b style="color:#00ff88">Rate limit:</b> {RATE_LIMIT_PER_MIN} req/min per key<br>
    <b style="color:#00ff88">Timeout:</b> {UPSTREAM_TIMEOUT}s<br>
    <b style="color:#00ff88">Active APIs:</b> {len(SERVICES)}
    </p></div>
    """
    return render(body, "Settings", "settings")


@app.route("/create", methods=["POST"])
@login_required
def create_key():
    client_name = (request.form.get("client_name") or "").strip() or "Unknown Client"
    key_name    = (request.form.get("key_name")    or "").strip() or "Unnamed Key"
    custom_key  = (request.form.get("custom_key")  or "").strip()
    service     = request.form.get("service", "number")

    if service not in SERVICES:
        flash("Unknown service", "danger"); return redirect(url_for("dashboard"))

    limit_str    = (request.form.get("search_limit") or "").strip()
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
        raw_key, key_hash = custom_key, sha256(custom_key)
    else:
        raw_key, key_hash = gen_key()
    prefix = make_prefix(raw_key)

    if db_fetch_one("SELECT id FROM api_keys WHERE key_hash=?", (key_hash,)):
        flash("❌ This exact API key already exists.", "danger")
        return redirect(url_for("dashboard"))

    rc = db_execute(
        "INSERT INTO api_keys (client_name, key_name, service, prefix, key_hash, expires_at, search_limit) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (client_name, key_name, service, prefix, key_hash, expires_at, search_limit),
    )
    if rc < 0:
        flash("❌ Database error, try again", "danger")
        return redirect(url_for("dashboard"))

    svc = SERVICES[service]
    base = request.host_url.rstrip("/")
    example_url = f"{base}/api/{service}/{svc['placeholder']}?key={raw_key}"

    body = render_template_string(
        RESULT_HTML, raw_key=raw_key, client_name=client_name, key_name=key_name,
        service=service, svc=svc,
        expires=expires_at[:16] if expires_at else "♾️ Permanent",
        limit=search_limit if search_limit is not None else "♾️ Unlimited",
        example_url=example_url)
    return render(body, "Key Created", "dashboard")


@app.route("/toggle/<int:key_id>")
@login_required
def toggle_key(key_id):
    row = db_fetch_one("SELECT * FROM api_keys WHERE id=?", (key_id,))
    if not row:
        flash("Key not found", "danger"); return redirect(url_for("dashboard"))
    new_state = 0 if row["is_active"] else 1
    db_execute("UPDATE api_keys SET is_active=? WHERE id=?", (new_state, key_id))
    flash(f"Key '{row['key_name']}' {'deactivated' if new_state == 0 else 'activated'}.", "info")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/delete/<int:key_id>")
@login_required
def delete_key(key_id):
    row = db_fetch_one("SELECT key_name FROM api_keys WHERE id=?", (key_id,))
    if row:
        db_execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        flash(f"Key '{row['key_name']}' deleted.", "success")
    return redirect(request.referrer or url_for("dashboard"))


# ============================================================
#  PUBLIC API GATEWAY  —  hides upstream
# ============================================================
def _proxy(service, value):
    if service not in SERVICES:
        return jsonify({"error": "Unknown service"}), 404

    raw_key = request.args.get("key")
    if not raw_key:
        return jsonify({"error": "API key required", "usage": "?key=YOUR_KEY"}), 401

    key_hash = sha256(raw_key)
    row = db_fetch_one("SELECT * FROM api_keys WHERE key_hash=?", (key_hash,))
    if not row:
        return jsonify({"error": "Invalid API key"}), 403

    valid, msg = validate_key(row)
    if not valid:
        return jsonify({"error": msg}), 403

    allowed, remaining = check_rate_limit(key_hash)
    if not allowed:
        return jsonify({"error": "Rate limit exceeded", "limit": f"{RATE_LIMIT_PER_MIN}/min"}), 429

    svc = SERVICES[service]
    if not value or not value.strip():
        return jsonify({"error": f"{svc['param']} value required in URL"}), 400

    upstream_url    = svc["upstream"]
    upstream_params = {"key": MASTER_KEY, svc["param"]: value.strip()}

    for k, v in request.args.items():
        if k != "key" and k != svc["param"]:
            upstream_params[k] = v

    status, data = call_upstream(upstream_url, upstream_params)

    if status is None:
        err_type, err_msg = data
        code = 504 if err_type == "timeout" else 502
        return jsonify({"error": err_msg, "type": err_type}), code

    data = rewrite_json(data)

    try:
        db_execute(
            "UPDATE api_keys SET searches_used = searches_used + 1, last_used_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row["id"]),
        )
    except Exception as e:
        log.warning(f"[USAGE UPDATE] {e}")

    resp = jsonify(data)
    resp.status_code = status
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp


@app.route("/api/<service>/<path:value>", methods=["GET"])
def api_route(service, value):
    return _proxy(service, value)


@app.route("/api/<service>", methods=["GET"])
def api_route_no_value(service):
    return _proxy(service, None)


# ============================================================
#  INIT
# ============================================================
init_db()
log.info("[BOOT] App ready ✅")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)