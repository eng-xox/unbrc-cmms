"""
UNBRC CMMS Fleet System — Final Production Version
Infrastructure: Render (Web) + PostgreSQL (Database) + Cloudinary (Storage)
"""
import os, sqlite3, secrets, json
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash

# استيراد المكتبات السحابية
import cloudinary
import cloudinary.uploader

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

# إعداد المسارات المحلية (للتطوير فقط)
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cmms.db"
STATIC_DIR = BASE_DIR / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR))
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# ===== DATABASE WRAPPER (Auto-Switch: SQLite/Postgres) =====
def is_postgres():
    return bool(os.environ.get("DATABASE_URL"))

def get_db_conn():
    if is_postgres():
        return psycopg2.connect(os.environ.get("DATABASE_URL"), cursor_factory=RealDictCursor)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

def execute_query(query, params=(), commit=False, fetchone=False, fetchall=False):
    if is_postgres():
        query = query.replace("?", "%s")
    
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute(query, params)
        if commit:
            conn.commit()
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row else None
        if fetchall:
            rows = cur.fetchall()
            return [dict(r) for r in rows]
        return None
    except Exception as e:
        print(f"Database Error: {e}")
        raise e
    finally:
        conn.close()

def init_db():
    id_type = "SERIAL PRIMARY KEY" if is_postgres() else "INTEGER PRIMARY KEY AUTOINCREMENT"
    
    # 1. جدول الإعدادات العامة
    execute_query("""CREATE TABLE IF NOT EXISTS kv_store (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""", commit=True)
    
    # 2. جدول المستخدمين
    execute_query(f"""CREATE TABLE IF NOT EXISTS users (
        id {id_type},
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        dept TEXT,
        email TEXT,
        is_manager INTEGER DEFAULT 0,
        manager_id INTEGER,
        created_at TEXT NOT NULL
    )""", commit=True)
    
    # 3. جدول سجلات الدخول
    execute_query(f"""CREATE TABLE IF NOT EXISTS sessions_log (
        id {id_type},
        user_id INTEGER NOT NULL,
        username TEXT, name TEXT, role TEXT, dept TEXT,
        device TEXT, ip TEXT, user_agent TEXT,
        logged_at TEXT NOT NULL
    )""", commit=True)

    # إضافة المدير الافتراضي إذا كانت القاعدة فارغة
    count_row = execute_query("SELECT COUNT(*) as count FROM users", fetchone=True)
    if count_row and count_row["count"] == 0:
        admin_pw = generate_password_hash("admin123")
        now = datetime.utcnow().isoformat()
        execute_query("""INSERT INTO users (username,password_hash,name,role,dept,email,is_manager,created_at)
                         VALUES (?,?,?,?,?,?,?,?)""",
                      ("admin", admin_pw, "مدير النظام", "admin", "الإدارة", "admin@unbrc.com", 1, now), commit=True)

# تهيئة قاعدة البيانات عند التشغيل
init_db()

# ===== AUTH HELPERS =====
def get_device(ua: str) -> str:
    ua = ua.lower()
    if "iphone" in ua or "ipad" in ua: return "iOS"
    if "android" in ua: return "Android"
    if "windows" in ua: return "Windows"
    if "mac" in ua: return "Mac"
    return "Other"

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    return execute_query("SELECT * FROM users WHERE id=?", (uid,), fetchone=True)

def require_auth():
    if not session.get("user_id"):
        return jsonify({"error": "غير مصرح بالدخول"}), 401
    return None

# ===== AUTH & USER ROUTES =====
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    user = execute_query("SELECT * FROM users WHERE username=?", (username,), fetchone=True)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "بيانات الدخول غير صحيحة"}), 401
        
    session["user_id"] = user["id"]
    ua = request.headers.get("User-Agent", "")
    execute_query("""INSERT INTO sessions_log (user_id,username,name,role,dept,device,ip,user_agent,logged_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                 (user["id"], user["username"], user["name"], user["role"], user["dept"],
                  get_device(ua), request.remote_addr, ua[:200], datetime.utcnow().isoformat()), commit=True)
                  
    return jsonify({"ok": True, "user": {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"]}})

@app.route("/api/me")
def me():
    user = current_user()
    if not user: return jsonify({"user": None})
    return jsonify({"user": {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"]}})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

# ===== DATA PERSISTENCE (KV STORE) =====
@app.route("/api/data", methods=["GET"])
def get_data():
    err = require_auth()
    if err: return err
    row = execute_query("SELECT value FROM kv_store WHERE key='cmms_main'", fetchone=True)
    return jsonify(json.loads(row["value"]) if row else {})

@app.route("/api/data", methods=["POST"])
def save_data():
    err = require_auth()
    if err: return err
    data = request.json or {}
    execute_query("""INSERT INTO kv_store (key,value,updated_at) VALUES ('cmms_main',?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                 (json.dumps(data, ensure_ascii=False), datetime.utcnow().isoformat()), commit=True)
    return jsonify({"ok": True})

# ===== FILE UPLOAD (CLOUDINARY) =====
@app.route("/api/upload", methods=["POST"])
def upload_file():
    err = require_auth()
    if err: return err
    
    if "file" not in request.files:
        return jsonify({"error": "لا يوجد ملف"}), 400
        
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "اسم الملف فارغ"}), 400

    try:
        # الرفع مباشرة إلى سحابة Cloudinary
        # سيتم استخدام CLOUDINARY_URL المعرف في Render تلقائياً
        result = cloudinary.uploader.upload(f, folder="unbrc_fleet_system")
        
        # استرجاع الرابط الدائم الآمن
        file_url = result.get("secure_url")
        
        return jsonify({
            "ok": True, 
            "filename": f.filename, 
            "url": file_url
        })
    except Exception as e:
        print(f"Cloudinary Error: {e}")
        return jsonify({"error": "فشل الرفع للسحابة"}), 500

# ===== STATIC SERVING =====
@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory(str(STATIC_DIR), path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
