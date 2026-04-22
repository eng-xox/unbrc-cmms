"""
UNBRC CMMS Fleet System — Python/Flask Backend
"""
from flask import Flask, request, jsonify, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
import json, os, sqlite3, secrets, socket
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cmms.db"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"

# حماية المجلدات في Render
if not UPLOAD_DIR.exists():
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

app = Flask(__name__, static_folder=str(STATIC_DIR))
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# ===== DATABASE =====
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS kv_store (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        dept TEXT,
        email TEXT,
        is_manager INTEGER DEFAULT 0,
        manager_id INTEGER,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT, name TEXT, role TEXT, dept TEXT,
        device TEXT, ip TEXT, user_agent TEXT,
        logged_at TEXT NOT NULL
    )""")
    conn.commit()

    # إنشاء المستخدمين الافتراضيين إذا كانت القاعدة فارغة
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        seed_users = [
            ("admin", "admin123", "مدير النظام", "admin", "الإدارة", "admin@unbrc.com", 1, None),
            ("maint", "maint123", "أحمد الصيانة", "maintenance", "الصيانة", "ahmed.maint@unbrc.com", 1, None),
            ("warehouse", "wh123", "خالد المستودع", "warehouse", "المستودع", "khalid.wh@unbrc.com", 1, None),
            ("purchase", "pur123", "سعد المشتريات", "procurement", "المشتريات", "saad.proc@unbrc.com", 1, None),
            ("ship", "ship123", "فهد الشحن", "shipping", "الشحن", "fahd.ship@unbrc.com", 1, None),
            ("logistics", "log123", "عمر اللوجستك", "logistics", "اللوجستك", "omar.log@unbrc.com", 1, None),
        ]
        now = datetime.utcnow().isoformat()
        for u in seed_users:
            c.execute("""INSERT INTO users (username,password_hash,name,role,dept,email,is_manager,manager_id,created_at)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (u[0], generate_password_hash(u[1]), u[2], u[3], u[4], u[5], u[6], u[7], now))
        conn.commit()
    conn.close()

# تنفيذ إنشاء قاعدة البيانات فوراً لكي يعمل مع Gunicorn في Render
init_db()

# ===== HELPERS =====
def get_device(ua: str) -> str:
    if "iPhone" in ua or "iPad" in ua: return "iOS"
    if "Android" in ua: return "Android"
    if "Windows" in ua: return "Windows"
    if "Mac" in ua: return "Mac"
    return "أخرى"

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None

def require_auth():
    if not session.get("user_id"):
        return jsonify({"error": "غير مصرح"}), 401
    return None

# ===== AUTH ROUTES =====
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "بيانات ناقصة"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        return jsonify({"error": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    
    ua = request.headers.get("User-Agent", "")
    conn.execute("""INSERT INTO sessions_log (user_id,username,name,role,dept,device,ip,user_agent,logged_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                 (user["id"], user["username"], user["name"], user["role"], user["dept"],
                  get_device(ua), request.remote_addr, ua[:200], datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "user": {"id": user["id"], "username": user["username"],
                                          "name": user["name"], "role": user["role"],
                                          "dept": user["dept"], "email": user["email"],
                                          "isManager": bool(user["is_manager"]),
                                          "managerId": user["manager_id"]}})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def me():
    user = current_user()
    if not user: return jsonify({"user": None})
    return jsonify({"user": {"id": user["id"], "username": user["username"],
                              "name": user["name"], "role": user["role"],
                              "dept": user["dept"], "email": user["email"],
                              "isManager": bool(user["is_manager"]),
                              "managerId": user["manager_id"]}})

# ===== API ROUTES =====
@app.route("/api/data", methods=["GET"])
def get_data():
    err = require_auth()
    if err: return err
    conn = get_db()
    row = conn.execute("SELECT value FROM kv_store WHERE key='cmms'").fetchone()
    conn.close()
    if row:
        return jsonify(json.loads(row["value"]))
    return jsonify({})

@app.route("/api/data", methods=["POST"])
def save_data():
    err = require_auth()
    if err: return err
    data = request.json or {}
    conn = get_db()
    conn.execute("""INSERT INTO kv_store (key,value,updated_at) VALUES ('cmms',?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                 (json.dumps(data, ensure_ascii=False), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ===== STATIC HTML FRONTEND =====
@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")

@app.route("/<path:path>")
def static_file(path):
    return send_from_directory(str(STATIC_DIR), path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
