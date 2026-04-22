"""
UNBRC CMMS Fleet System — Python/Flask Backend
Run: python app.py
Access from network: http://<your-ip>:5000
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
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

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
    """Single-table key/value JSON store — mirrors localStorage simplicity but server-side"""
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

    # Seed default users if empty
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        seed_users = [
            ("admin", "admin123", "مدير النظام", "admin", "الإدارة", "admin@unbrc.com", 1, None),
            ("maint", "maint123", "أحمد الصيانة", "maintenance", "الصيانة", "ahmed.maint@unbrc.com", 1, None),
            ("warehouse", "wh123", "خالد المستودع", "warehouse", "المستودع", "khalid.wh@unbrc.com", 1, None),
            ("purchase", "pur123", "سعد المشتريات", "procurement", "المشتريات", "saad.proc@unbrc.com", 1, None),
            ("ship", "ship123", "فهد الشحن", "shipping", "الشحن", "fahd.ship@unbrc.com", 1, None),
            ("logistics", "log123", "عمر اللوجستك", "logistics", "اللوجستك", "omar.log@unbrc.com", 1, None),
            ("maint1", "maint1", "محمد فني صيانة", "maintenance", "الصيانة", "mohammed.tech@unbrc.com", 0, 2),
            ("maint2", "maint2", "علي فني صيانة", "maintenance", "الصيانة", "ali.tech@unbrc.com", 0, 2),
            ("wh1", "wh1", "يوسف موظف مستودع", "warehouse", "المستودع", "yousef.wh@unbrc.com", 0, 3),
            ("proc1", "proc1", "ناصر موظف مشتريات", "procurement", "المشتريات", "nasser.proc@unbrc.com", 0, 4),
            ("log1", "log1", "حمد موظف لوجستك", "logistics", "اللوجستك", "hamad.log@unbrc.com", 0, 6),
        ]
        now = datetime.utcnow().isoformat()
        for u in seed_users:
            c.execute("""INSERT INTO users (username,password_hash,name,role,dept,email,is_manager,manager_id,created_at)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (u[0], generate_password_hash(u[1]), u[2], u[3], u[4], u[5], u[6], u[7], now))
        conn.commit()
    conn.close()


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
    # Log session
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

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if "@unbrc.com" not in email:
        return jsonify({"error": "يجب استخدام بريد @unbrc.com"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE LOWER(email)=?", (email,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "البريد غير مسجل"}), 404
    token = secrets.token_hex(3).upper()
    session["reset_token"] = token
    session["reset_user_id"] = user["id"]
    return jsonify({"ok": True, "token": token, "userId": user["id"]})

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.json or {}
    token = data.get("token", "").upper()
    new_pw = data.get("password", "")
    if not session.get("reset_token") or session["reset_token"] != token:
        return jsonify({"error": "رمز غير صحيح"}), 400
    if len(new_pw) < 4:
        return jsonify({"error": "كلمة المرور قصيرة"}), 400
    uid = session.get("reset_user_id")
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                 (generate_password_hash(new_pw), uid))
    conn.commit()
    conn.close()
    session.pop("reset_token", None)
    session.pop("reset_user_id", None)
    return jsonify({"ok": True})


# ===== USERS API =====
@app.route("/api/users", methods=["GET"])
def list_users():
    err = require_auth()
    if err: return err
    conn = get_db()
    rows = conn.execute("SELECT id,username,name,role,dept,email,is_manager,manager_id FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(r) for r in rows]})

@app.route("/api/users", methods=["POST"])
def create_user():
    err = require_auth()
    if err: return err
    user = current_user()
    if user["role"] != "admin":
        return jsonify({"error": "صلاحيات غير كافية"}), 403
    data = request.json or {}
    conn = get_db()
    try:
        conn.execute("""INSERT INTO users (username,password_hash,name,role,dept,email,is_manager,manager_id,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                     (data["username"], generate_password_hash(data["password"]),
                      data["name"], data["role"], data.get("dept", ""),
                      data.get("email", ""), 1 if data.get("isManager") else 0,
                      data.get("managerId"), datetime.utcnow().isoformat()))
        conn.commit()
        return jsonify({"ok": True})
    except sqlite3.IntegrityError:
        return jsonify({"error": "المستخدم موجود مسبقاً"}), 400
    finally:
        conn.close()

@app.route("/api/users/<int:uid>", methods=["DELETE"])
def delete_user(uid):
    err = require_auth()
    if err: return err
    if uid == 1:
        return jsonify({"error": "لا يمكن حذف المدير الأساسي"}), 400
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ===== KEY-VALUE STORE (mirrors localStorage for client data) =====
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


# ===== LOGIN HISTORY =====
@app.route("/api/login-history")
def login_history():
    err = require_auth()
    if err: return err
    conn = get_db()
    rows = conn.execute("SELECT * FROM sessions_log ORDER BY logged_at DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify({"history": [dict(r) for r in rows]})


# ===== FILE UPLOAD =====
@app.route("/api/upload", methods=["POST"])
def upload_file():
    err = require_auth()
    if err: return err
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    safe = secrets.token_hex(8) + "_" + Path(f.filename).name
    f.save(UPLOAD_DIR / safe)
    return jsonify({"ok": True, "filename": safe, "url": f"/uploads/{safe}"})

@app.route("/uploads/<path:fname>")
def serve_upload(fname):
    return send_from_directory(str(UPLOAD_DIR), fname)


# ===== STATIC HTML FRONTEND =====
@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")

@app.route("/<path:path>")
def static_file(path):
    return send_from_directory(str(STATIC_DIR), path)


# ===== STARTUP =====
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    init_db()
    ip = get_local_ip()
    print("=" * 60)
    print("  UNBRC CMMS Fleet System — Python Server")
    print("=" * 60)
    print(f"  📡 Local:    http://localhost:5000")
    print(f"  🌐 Network:  http://{ip}:5000")
    print("=" * 60)
    print("  Default login: admin / admin123")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
