import os, sqlite3, uuid
from datetime import datetime
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "uploads")
DB = os.path.join(BASE, "trustvault.db")
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "png", "jpg", "jpeg"}
IMG_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
CATEGORIES = ["Contract", "Finance", "HR", "Legal", "Report", "Other"]

app = Flask(__name__)
app.config.update(SECRET_KEY="change-this-secret-in-production", MAX_CONTENT_LENGTH=16 * 1024 * 1024)
os.makedirs(UPLOADS, exist_ok=True)


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
        password TEXT, role TEXT, company TEXT, avatar TEXT);
    CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, title TEXT, category TEXT,
        stored TEXT, original TEXT, owner_id INTEGER, company TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS shares(id INTEGER PRIMARY KEY, doc_id INTEGER, user_id INTEGER,
        permission TEXT, UNIQUE(doc_id, user_id));
    CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, user_id INTEGER, user_name TEXT,
        action TEXT, detail TEXT, ts TEXT);
    """)
    if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users(name,email,password,role,company) VALUES(?,?,?,?,?)",
                  ("Administrator", "admin@trustvault.com", generate_password_hash("Admin@123"),
                   "admin", "TrustVault Inc"))
    c.commit(); c.close()

def log(action, detail="", user=None):
    u = user or g.get("user")
    db().execute("INSERT INTO logs(user_id,user_name,action,detail,ts) VALUES(?,?,?,?,?)",
                 (u["id"] if u else None, u["name"] if u else "anonymous", action, detail,
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db().commit()


# ---------- auth helpers ----------
@app.before_request
def load_user():
    g.user = None
    if session.get("uid"):
        g.user = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                log("ACCESS DENIED", f"{request.method} {request.path}")
                abort(403)
            return f(*a, **k)
        return w
    return deco

def get_doc(doc_id):
    d = db().execute("""SELECT d.*, u.name AS owner FROM documents d
                        JOIN users u ON u.id=d.owner_id WHERE d.id=?""", (doc_id,)).fetchone()
    if not d:
        abort(404)
    return d

def can_manage(d):  # only admin and document owner
    return g.user["role"] == "admin" or d["owner_id"] == g.user["id"]

def can_view(d):
    if can_manage(d):
        return True
    return db().execute("SELECT 1 FROM shares WHERE doc_id=? AND user_id=?",
                        (d["id"], g.user["id"])).fetchone() is not None

def visible_docs(extra="", args=()):
    q = """SELECT DISTINCT d.*, u.name AS owner FROM documents d JOIN users u ON u.id=d.owner_id
           LEFT JOIN shares s ON s.doc_id=d.id WHERE 1=1 """
    p = []
    if g.user["role"] != "admin":
        q += " AND (d.owner_id=? OR s.user_id=?)"; p += [g.user["id"], g.user["id"]]
    return db().execute(q + extra + " ORDER BY d.created DESC", p + list(args)).fetchall()

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403,
        msg="Access denied. Only the admin and the document owner can manage this."), 403

@app.errorhandler(404)
def notfound(_):
    return render_template("error.html", code=404, msg="That page or document does not exist."), 404

@app.errorhandler(413)
def toolarge(_):
    return render_template("error.html", code=413, msg="File is larger than 16 MB."), 413


# ---------- auth routes ----------
@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard" if g.user["role"] == "admin" else "my_docs"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        name, email, pw = f["name"].strip(), f["email"].strip().lower(), f["password"]
        role = f.get("role") if f.get("role") in ("owner", "viewer") else "owner"
        if not (name and email and f.get("company", "").strip()) or len(pw) < 6:
            flash("Fill all fields. Password needs at least 6 characters.", "err")
        elif db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            flash("That email is already registered. Sign in instead.", "err")
        else:
            db().execute("INSERT INTO users(name,email,password,role,company) VALUES(?,?,?,?,?)",
                         (name, email, generate_password_hash(pw), role, f["company"].strip()))
            db().commit()
            u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            log("REGISTER", f"role={role}", u)
            flash("Account created. Sign in to continue.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?",
                         (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session["uid"] = u["id"]
            log("LOGIN", "", u)
            return redirect(url_for("index"))
        log("LOGIN FAILED", request.form["email"])
        flash("Wrong email or password.", "err")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


# ---------- admin ----------
@app.route("/dashboard")
@role_required("admin")
def dashboard():
    q = lambda s: db().execute(s).fetchone()[0]
    stats = dict(docs=q("SELECT COUNT(*) FROM documents"), users=q("SELECT COUNT(*) FROM users"),
                 shared_docs=q("SELECT COUNT(DISTINCT doc_id) FROM shares"),
                 records=q("SELECT COUNT(*) FROM shares"),
                 denied=q("SELECT COUNT(*) FROM logs WHERE action='ACCESS DENIED'"),
                 failed=q("SELECT COUNT(*) FROM logs WHERE action='LOGIN FAILED'"))
    recent = db().execute("SELECT * FROM logs ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", s=stats, recent=recent)

@app.route("/users", methods=["GET", "POST"])
@role_required("admin")
def users():
    if request.method == "POST":
        uid, role = int(request.form["uid"]), request.form["role"]
        if role in ("admin", "owner", "viewer") and uid != g.user["id"]:
            db().execute("UPDATE users SET role=? WHERE id=?", (role, uid)); db().commit()
            log("ROLE CHANGE", f"user {uid} -> {role}")
            flash("Role updated.", "ok")
        return redirect(url_for("users"))
    return render_template("users.html", rows=db().execute("SELECT * FROM users ORDER BY id").fetchall())

@app.route("/logs")
@role_required("admin")
def logs():
    rows = db().execute("SELECT * FROM logs ORDER BY id DESC LIMIT 300").fetchall()
    return render_template("logs.html", rows=rows)


# ---------- documents ----------
@app.route("/documents")
@login_required
def my_docs():
    docs = visible_docs()
    perms = {s["doc_id"]: s["permission"] for s in
             db().execute("SELECT * FROM shares WHERE user_id=?", (g.user["id"],))}
    return render_template("documents.html", docs=docs, perms=perms, can_manage=can_manage)

@app.route("/search")
@login_required
def search():
    f, extra, args = request.args, "", []
    if f.get("q"):
        extra += " AND d.title LIKE ?"; args.append(f"%{f['q']}%")
    if f.get("category"):
        extra += " AND d.category=?"; args.append(f["category"])
    if f.get("owner"):
        extra += " AND u.name LIKE ?"; args.append(f"%{f['owner']}%")
    if f.get("date_from"):
        extra += " AND date(d.created)>=date(?)"; args.append(f["date_from"])
    if f.get("date_to"):
        extra += " AND date(d.created)<=date(?)"; args.append(f["date_to"])
    docs = visible_docs(extra, args) if request.args else []
    return render_template("search.html", docs=docs, f=f, cats=CATEGORIES, searched=bool(request.args),
                           can_manage=can_manage, perms={})

@app.route("/upload", methods=["GET", "POST"])
@role_required("admin", "owner")
def upload():
    others = db().execute("SELECT id,name,email,role FROM users WHERE id!=? AND (company=? OR ?='admin')",
                          (g.user["id"], g.user["company"], g.user["role"])).fetchall()
    if request.method == "POST":
        file = request.files.get("file")
        ext = file.filename.rsplit(".", 1)[-1].lower() if file and "." in file.filename else ""
        if not file or ext not in DOC_EXT:
            flash("Choose a file: " + ", ".join(sorted(DOC_EXT)), "err")
        else:
            stored = f"{uuid.uuid4().hex}.{ext}"
            file.save(os.path.join(UPLOADS, stored))
            cur = db().execute("""INSERT INTO documents(title,category,stored,original,owner_id,company,created)
                VALUES(?,?,?,?,?,?,?)""", (request.form["title"].strip() or file.filename,
                request.form["category"], stored, secure_filename(file.filename), g.user["id"],
                g.user["company"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            did = cur.lastrowid
            perm = "edit" if request.form.get("permission") == "edit" else "read"
            for uid in request.form.getlist("share_with"):
                db().execute("INSERT OR REPLACE INTO shares(doc_id,user_id,permission) VALUES(?,?,?)",
                             (did, int(uid), perm))
            db().commit()
            log("UPLOAD", f"doc #{did} {request.form['title']}")
            flash("Document uploaded.", "ok")
            return redirect(url_for("my_docs"))
    return render_template("upload.html", cats=CATEGORIES, others=others)

@app.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    d = get_doc(doc_id)
    if not can_view(d):
        log("ACCESS DENIED", f"download doc #{doc_id}"); abort(403)
    log("DOWNLOAD", f"doc #{doc_id} {d['title']}")
    return send_from_directory(UPLOADS, d["stored"], as_attachment=True, download_name=d["original"])

@app.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete(doc_id):
    d = get_doc(doc_id)
    if not can_manage(d):
        log("ACCESS DENIED", f"delete doc #{doc_id}"); abort(403)
    db().execute("DELETE FROM shares WHERE doc_id=?", (doc_id,))
    db().execute("DELETE FROM documents WHERE id=?", (doc_id,)); db().commit()
    try: os.remove(os.path.join(UPLOADS, d["stored"]))
    except OSError: pass
    log("DELETE", f"doc #{doc_id} {d['title']}")
    flash("Document deleted.", "ok")
    return redirect(url_for("my_docs"))

@app.route("/access/<int:doc_id>", methods=["GET", "POST"])
@login_required
def access(doc_id):
    d = get_doc(doc_id)
    if not can_manage(d):
        log("ACCESS DENIED", f"manage access doc #{doc_id}"); abort(403)
    if request.method == "POST":
        act, uid = request.form["action"], int(request.form["uid"])
        if act == "grant":
            perm = "edit" if request.form.get("permission") == "edit" else "read"
            db().execute("INSERT OR REPLACE INTO shares(doc_id,user_id,permission) VALUES(?,?,?)",
                         (doc_id, uid, perm))
            log("GRANT", f"doc #{doc_id} user {uid} ({perm})"); flash("Access granted.", "ok")
        else:
            db().execute("DELETE FROM shares WHERE doc_id=? AND user_id=?", (doc_id, uid))
            log("REVOKE", f"doc #{doc_id} user {uid}"); flash("Access revoked.", "ok")
        db().commit()
        return redirect(url_for("access", doc_id=doc_id))
    shared = db().execute("""SELECT u.id,u.name,u.email,s.permission FROM shares s
                             JOIN users u ON u.id=s.user_id WHERE s.doc_id=?""", (doc_id,)).fetchall()
    ids = [s["id"] for s in shared] + [d["owner_id"]]
    cands = [u for u in db().execute("SELECT id,name,email FROM users WHERE company=? OR ?='admin'",
             (d["company"], g.user["role"])) if u["id"] not in ids]
    return render_template("access.html", d=d, shared=shared, cands=cands)


# ---------- profile ----------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form["name"].strip() or g.user["name"]
        db().execute("UPDATE users SET name=? WHERE id=?", (name, g.user["id"]))
        pw = request.form.get("password", "")
        if pw:
            if len(pw) < 6:
                flash("Password needs at least 6 characters.", "err"); return redirect(url_for("profile"))
            db().execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(pw), g.user["id"]))
        img = request.files.get("avatar")
        if img and img.filename:
            ext = img.filename.rsplit(".", 1)[-1].lower()
            if ext in IMG_EXT:
                fn = f"avatar_{g.user['id']}_{uuid.uuid4().hex[:6]}.{ext}"
                img.save(os.path.join(BASE, "static", fn))
                db().execute("UPDATE users SET avatar=? WHERE id=?", (fn, g.user["id"]))
        db().commit(); log("PROFILE UPDATE"); flash("Profile saved.", "ok")
        return redirect(url_for("profile"))
    return render_template("profile.html")
