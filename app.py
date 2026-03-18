from flask import Flask, render_template, render_template_string, request, redirect, session
import bcrypt
import sqlite3
import time
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = "change-this-to-a-long-random-secret-key"

# 🔐 Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read cookie
    SESSION_COOKIE_SECURE=False,    # True only when using HTTPS
    SESSION_COOKIE_SAMESITE=None   # CSRF protection temporarily changed to none from "lax"
)

# ---------- CSP HEADER ----------
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response


DATABASE_FILE = "database/auth.db"

MAX_ATTEMPTS = 2
LOCK_DURATION_SECONDS = 120


def connect_db():
    return sqlite3.connect(DATABASE_FILE)


def setup_database():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        failed_attempts INTEGER,
        lock_until INTEGER
    )
    """)

    conn.commit()
    conn.close()

def is_admin_user(username):
    # Simple demo rule: username "admin" is admin
    return username == "admin"


# ---------- HOME ----------
@app.route("/")
def home():
    return render_template("home.html", user=session.get("user"))


# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

        conn = connect_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (username, password_hash, failed_attempts, lock_until)
                VALUES (?, ?, 0, 0)
            """, (username, hashed))
            conn.commit()
            msg = "User registered!"
        except sqlite3.IntegrityError:
            msg = "Username already exists!"

        conn.close()
        return msg + "<br><a href='/login'>Go to login</a>"

    return """
    <h2>Register</h2>
    <form method="post">
        Username: <input name="username"><br><br>
        Password: <input name="password" type="password"><br><br>
        <button type="submit">Register</button>
    </form>
    """


# ---------- LOGIN (SECURE) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password_hash, failed_attempts, lock_until FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()

        if not result:
            return "User not found!"

        stored_hash, attempts, lock_until = result
        current_time = int(time.time())

        if lock_until > current_time:
            remaining = lock_until - current_time
            return f"Account locked. Try again in {remaining} seconds."

        if bcrypt.checkpw(password, stored_hash.encode()):
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE username = ?",
                (username,)
            )
            conn.commit()
            conn.close()

            session["user"] = username
            return redirect("/")
        else:
            attempts += 1

            if attempts >= MAX_ATTEMPTS:
                lock_until = current_time + LOCK_DURATION_SECONDS
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
                    (attempts, lock_until, username)
                )
                conn.commit()
                conn.close()
                return "Too many failed attempts. Account locked."

            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (attempts, username)
            )
            conn.commit()
            conn.close()
            return "Wrong password."

    return render_template("login.html")


# ---------- VULNERABLE LOGIN (FIXED DEMO) ----------
@app.route("/login_vuln", methods=["GET", "POST"])
def login_vuln():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = connect_db()
        cursor = conn.cursor()

        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
        print("DEBUG QUERY:", query)

        try:
            cursor.execute(query)
            result = cursor.fetchone()
        except Exception as e:
            conn.close()
            return f"SQL Error: {e}"

        conn.close()

        if result:
            session["user"] = "hacked_user"
            return "<h2>Login successful (VULNERABLE)</h2>"
        else:
            return "Invalid credentials"

    return """
    <h2>Vulnerable Login (SQL Injection Demo)</h2>
    <form method="post">
        Username: <input name="username"><br><br>
        Password: <input name="password" type="password"><br><br>
        <button type="submit">Login</button>
    """


# ---------- PROFILE (XSS SAFE) ----------
@app.route("/profile_safe", methods=["GET", "POST"])
def profile_safe():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        bio = request.form["bio"]
        session["bio"] = bio

    bio_display = session.get("bio", "")

    template = """
    <h2>Profile Page (Safe)</h2>
    <p>Welcome, {{ user }}</p>

    <form method="post">
        Enter your bio:<br><br>
        <textarea name="bio" rows="4" cols="40"></textarea><br><br>
        <button type="submit">Save Bio</button>
    </form>

    <h3>Your Bio:</h3>
    {{ bio }}
    <br><br>
    <a href="/">Home</a>
    """

    return render_template_string(template, user=session["user"], bio=bio_display)


# ---------- SEARCH (REFLECTED XSS - VULNERABLE) ----------
@app.route("/search")
def search():
    query = request.args.get("q", "")

    return f"""
    <h2>Search Page</h2>
    <form>
        Search: <input name="q">
        <button type="submit">Search</button>
    </form>

    <h3>Results for: {query}</h3>
    """


# ---------- SEARCH (REFLECTED XSS - SAFE) ----------
@app.route("/search_safe")
def search_safe():
    query = request.args.get("q", "")

    template = """
    <h2>Search Page (Safe)</h2>
    <form>
        Search: <input name="q">
        <button type="submit">Search</button>
    </form>

    <h3>Results for: {{ query }}</h3>
    """

    return render_template_string(template, query=query)


# ---------- ATTACKER COOKIE COLLECTOR ----------
@app.route("/steal")
def steal():
    cookie = request.args.get("c")
    print("🚨 Stolen cookie:", cookie)
    return "Cookie received"


# ---------- PROFILE (XSS DEMO - VULNERABLE) ----------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        bio = request.form["bio"]
        session["bio"] = bio

    bio_display = session.get("bio", "")

    return f"""
    <h2>Profile Page (Vulnerable)</h2>
    <p>Welcome, {session['user']}</p>

    <form method="post">
        Enter your bio:<br><br>
        <textarea name="bio" rows="4" cols="40"></textarea><br><br>
        <button type="submit">Save Bio</button>
    </form>

    <h3>Your Bio:</h3>
    {bio_display}
    <br><br>
    <a href="/">Home</a>
    """


# ---------- TRANSFER (CSRF PROTECTED) ----------
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user" not in session:
        return redirect("/login")

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    if request.method == "POST":
        form_token = request.form.get("csrf_token")

        if not form_token or form_token != session["csrf_token"]:
            return "<h3>CSRF validation failed!</h3>"

        amount = request.form.get("amount")
        to_user = request.form.get("to")

        return f"<h3>Transferred ${amount} to {to_user}</h3><a href='/'>Home</a>"

    return f"""
    <h2>Transfer Money</h2>
    <form method="post">
        <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
        To User: <input name="to"><br><br>
        Amount: <input name="amount"><br><br>
        <button type="submit">Send</button>
    </form>
    """

# ---------- ADMIN PANEL (BROKEN ACCESS CONTROL - VULNERABLE) ----------
@app.route("/admin_vuln")
def admin_vuln():
    if "user" not in session:
        return redirect("/login")

    # ❌ MISSING authorization check
    return f"""
    <h2>Admin Panel (Vulnerable)</h2>
    <p>Welcome, {session['user']}</p>
    <p>🔥 Sensitive admin data visible!</p>
    <a href="/">Home</a>
    """

# ---------- ADMIN PANEL (SECURE) ----------
@app.route("/admin_safe")
def admin_safe():
    if "user" not in session:
        return redirect("/login")

    if not is_admin_user(session["user"]):
        return "<h3>Access denied: Admins only</h3>"

    return f"""
    <h2>Admin Panel (Secure)</h2>
    <p>Welcome, {session['user']}</p>
    <p>✅ Authorized admin access</p>
    <a href="/">Home</a>
    """


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    setup_database()
    app.run(debug=True)
