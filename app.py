"""
app.py - SFMS Web Application (Flask)
Full web interface for the Secure File Management System
"""

import os
import sys
import json
import shutil
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_from_directory)

# Add parent path so we can reuse our existing modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import UserRegistry
from encryption import encrypt_file, decrypt_file, is_encrypted
from access_control import check_access, register_file_owner, get_file_owner
from threat_detection import (
    record_failed_login, record_successful_login,
    is_locked_out, check_login_time, get_threat_summary, scan_file
)

# ── Config ────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
USERS_DB   = os.path.join(BASE_DIR, "users.json")
STORAGE    = os.path.join(BASE_DIR, "storage")
UPLOAD_TMP = os.path.join(BASE_DIR, "tmp_uploads")

os.makedirs(STORAGE, exist_ok=True)
os.makedirs(UPLOAD_TMP, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload

registry = UserRegistry(USERS_DB)

# Bootstrap admin on first run
if not registry.user_exists("admin"):
    import secrets, string
    default_pw = "Admin@1234"
    ok, secret = registry.register("admin", default_pw, role="admin")
    if ok:
        print(f"\n{'='*50}")
        print("  DEFAULT ADMIN ACCOUNT CREATED")
        print(f"  Username : admin")
        print(f"  Password : {default_pw}")
        print(f"  2FA Secret: {secret}")
        print(f"  Add this secret to Authy/Google Authenticator")
        print(f"{'='*50}\n")


# ── Auth Decorators ───────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Helper ────────────────────────────────────────────────

def safe_path(filename):
    return os.path.join(STORAGE, os.path.basename(filename))

def get_files():
    files = []
    for name in os.listdir(STORAGE):
        path = os.path.join(STORAGE, name)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append({
                "name": name,
                "size": _fmt_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%d %b %Y, %H:%M"),
                "owner": get_file_owner(name) or "unknown",
                "encrypted": is_encrypted(path),
            })
    return sorted(files, key=lambda x: x["name"])

def _fmt_size(b):
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"


# ── Routes ────────────────────────────────────────────────

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        step = request.form.get("step", "password")
        username = request.form.get("username", "").strip()

        # Step 1: Password
        if step == "password":
            password = request.form.get("password", "")
            locked, remaining = is_locked_out(username)
            if locked:
                flash(f"Account locked. Try again in {remaining} seconds.", "error")
                return render_template("login.html", step="password")

            ok, msg = registry.authenticate(username, password)
            if not ok:
                should_lock = record_failed_login(username)
                if should_lock:
                    registry.lock_user(username)
                    flash("Account locked due to too many failed attempts.", "error")
                else:
                    flash("Invalid username or password.", "error")
                return render_template("login.html", step="password")

            # Password OK → go to 2FA step
            session["pending_user"] = username
            return render_template("login.html", step="totp", username=username)

        # Step 2: TOTP
        elif step == "totp":
            pending = session.get("pending_user")
            if not pending or pending != username:
                return redirect(url_for("login"))

            code = request.form.get("totp_code", "").strip()
            if not registry.verify_2fa(username, code):
                record_failed_login(username)
                flash("Invalid 2FA code. Try again.", "error")
                return render_template("login.html", step="totp", username=username)

            # Full success
            record_successful_login(username)
            registry.update_last_login(username)
            session.pop("pending_user", None)
            session["username"] = username
            session["role"] = registry.get_role(username)
            session["enc_password"] = request.form.get("enc_password", "defaultEncKey123")
            check_login_time(username)
            return redirect(url_for("dashboard"))

    return render_template("login.html", step="password")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        ok, result = registry.register(username, password, role="user")
        if not ok:
            flash(result, "error")
            return render_template("register.html")

        flash(f"Account created! Your 2FA secret: {result} — Add it to Authy now!", "success")
        return render_template("register_success.html", secret=result, username=username)

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    files = get_files()
    summary = get_threat_summary()
    return render_template("dashboard.html",
        username=session["username"],
        role=session["role"],
        files=files,
        threat_summary=summary,
        total_files=len(files),
        encrypted_count=sum(1 for f in files if f["encrypted"]),
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    username = session["username"]
    role = session["role"]
    allowed, msg = check_access(username, role, "write")
    if not allowed:
        flash("Access denied: you don't have permission to upload files.", "error")
        return redirect(url_for("dashboard"))

    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    filename = os.path.basename(file.filename)
    warnings = scan_file(filename)
    dest = safe_path(filename)
    file.save(dest)
    register_file_owner(filename, username)

    if warnings:
        flash(f"File uploaded with warnings: {'; '.join(warnings)}", "warning")
    else:
        flash(f"'{filename}' uploaded successfully!", "success")
    return redirect(url_for("dashboard"))


@app.route("/create", methods=["POST"])
@login_required
def create_file_route():
    username = session["username"]
    role = session["role"]
    allowed, _ = check_access(username, role, "write")
    if not allowed:
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    filename = os.path.basename(request.form.get("filename", "").strip())
    content  = request.form.get("content", "")
    if not filename:
        flash("Filename cannot be empty.", "error")
        return redirect(url_for("dashboard"))

    path = safe_path(filename)
    with open(path, "w") as f:
        f.write(content)
    register_file_owner(filename, username)
    flash(f"File '{filename}' created!", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete/<filename>", methods=["POST"])
@login_required
def delete_file(filename):
    username = session["username"]
    role = session["role"]
    allowed, msg = check_access(username, role, "delete", filename)
    if not allowed:
        flash("Access denied: cannot delete this file.", "error")
        return redirect(url_for("dashboard"))

    path = safe_path(filename)
    if os.path.exists(path):
        os.remove(path)
        flash(f"'{filename}' deleted.", "success")
    else:
        flash("File not found.", "error")
    return redirect(url_for("dashboard"))


@app.route("/encrypt/<filename>", methods=["POST"])
@login_required
def encrypt_file_route(filename):
    username = session["username"]
    role = session["role"]
    allowed, _ = check_access(username, role, "encrypt", filename)
    if not allowed:
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    path = safe_path(filename)
    if is_encrypted(path):
        flash(f"'{filename}' is already encrypted.", "warning")
        return redirect(url_for("dashboard"))

    tmp = path + ".enc_tmp"
    try:
        encrypt_file(path, tmp, session.get("enc_password", "defaultKey"))
        os.replace(tmp, path)
        flash(f"'{filename}' encrypted successfully! 🔒", "success")
    except Exception as e:
        flash(f"Encryption failed: {e}", "error")
    return redirect(url_for("dashboard"))


@app.route("/decrypt/<filename>", methods=["POST"])
@login_required
def decrypt_file_route(filename):
    username = session["username"]
    role = session["role"]
    allowed, _ = check_access(username, role, "decrypt", filename)
    if not allowed:
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    path = safe_path(filename)
    if not is_encrypted(path):
        flash(f"'{filename}' is not encrypted.", "warning")
        return redirect(url_for("dashboard"))

    tmp = path + ".dec_tmp"
    try:
        decrypt_file(path, tmp, session.get("enc_password", "defaultKey"))
        os.replace(tmp, path)
        flash(f"'{filename}' decrypted successfully! 🔓", "success")
    except ValueError:
        if os.path.exists(tmp): os.remove(tmp)
        flash("Decryption failed: wrong encryption password.", "error")
    return redirect(url_for("dashboard"))


@app.route("/read/<filename>")
@login_required
def read_file(filename):
    username = session["username"]
    role = session["role"]
    allowed, _ = check_access(username, role, "read", filename)
    if not allowed:
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    path = safe_path(filename)
    if not os.path.exists(path):
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))

    if is_encrypted(path):
        flash(f"'{filename}' is encrypted. Decrypt it first to read.", "warning")
        return redirect(url_for("dashboard"))

    with open(path, "r", errors="replace") as f:
        content = f.read()
    return render_template("read_file.html", filename=filename, content=content,
                           username=session["username"], role=session["role"])


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = registry.list_users()
    return render_template("admin_users.html", users=users,
                           username=session["username"], role=session["role"])


@app.route("/admin/lock/<target>", methods=["POST"])
@login_required
@admin_required
def lock_user(target):
    registry.lock_user(target)
    flash(f"User '{target}' locked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/unlock/<target>", methods=["POST"])
@login_required
@admin_required
def unlock_user(target):
    registry.unlock_user(target)
    flash(f"User '{target}' unlocked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    logs = []
    log_path = "security_alerts.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except: pass
    logs.reverse()
    return render_template("admin_logs.html", logs=logs[:100],
                           username=session["username"], role=session["role"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
