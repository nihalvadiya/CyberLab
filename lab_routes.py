"""
Deliberately vulnerable training endpoints.

This blueprint is only registered when ``CYBERLAB_LAB_MODE=1``. Every route here
is broken on purpose and paired with the hardened implementation in ``app.py``:

    /lab/login-sqli    SQL injection        <->  /login
    /lab/profile-xss   stored XSS           <->  /profile
    /lab/search-xss    reflected XSS        <->  /search
    /lab/admin-open    broken access ctrl   <->  /admin
    /lab/steal         cookie exfil sink    (demonstrates HttpOnly)

Do not register this blueprint on a host anyone else can reach.
"""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

import config
import db

lab = Blueprint("lab", __name__)


@lab.route("/")
def index():
    return render_template("lab_index.html")


# --------------------------------------------------- SQL injection (VULNERABLE)
@lab.route("/login-sqli", methods=["GET", "POST"])
def login_sqli():
    """
    Compare with :func:`app.login`, which binds parameters instead.

    Try ``' OR '1'='1' --`` as the username.
    """
    result = None
    error = None
    query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE ON PURPOSE: user input concatenated straight into SQL.
        query = (
            "SELECT username FROM users "
            f"WHERE username = '{username}' AND password_hash = '{password}'"
        )
        conn = sqlite3.connect(config.DATABASE_FILE)
        try:
            row = conn.execute(query).fetchone()
            result = row[0] if row else None
        except sqlite3.Error as exc:
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "lab_sqli.html", result=result, error=error, query=query
    )


# ----------------------------------------------------- stored XSS (VULNERABLE)
@lab.route("/profile-xss", methods=["GET", "POST"])
def profile_xss():
    """
    Renders a stored bio without escaping. Compare with :func:`app.profile`,
    where Jinja autoescaping neutralises the same payload.
    """
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        db.set_bio(user, (request.form.get("bio") or "")[: config.MAX_BIO_LEN])
        return redirect(url_for("lab.profile_xss"))

    row = db.get_user(user)
    bio = row["bio"] if row else ""
    # VULNERABLE ON PURPOSE: |safe disables escaping for attacker-controlled text.
    return render_template("lab_xss_stored.html", user=user, bio=bio)


# -------------------------------------------------- reflected XSS (VULNERABLE)
@lab.route("/search-xss")
def search_xss():
    """Reflects the query string verbatim. Compare with :func:`app.search`."""
    query = request.args.get("q", "")
    return render_template("lab_xss_reflected.html", query=query)


# --------------------------------------------- broken access control (VULNERABLE)
@lab.route("/admin-open")
def admin_open():
    """
    Checks authentication but never authorisation, so any signed-in user reads
    admin data. Compare with :func:`app.admin`.
    """
    if not session.get("user"):
        return redirect(url_for("login"))
    # MISSING ON PURPOSE: no `if not session["is_admin"]: abort(403)`.
    return render_template("lab_admin_open.html", users=db.list_users())


# ------------------------------------------------------- cookie exfil endpoint
@lab.route("/steal")
def steal():
    """
    Sink for the session-hijacking exercise.

    With HttpOnly set (as it is), ``document.cookie`` cannot read the session
    cookie, so this endpoint should only ever receive an empty value — which is
    the point of the lesson.
    """
    cookie = request.args.get("c", "")[:512]
    current_app.logger.warning("[lab] exfil endpoint received: %r", cookie)
    return render_template("lab_steal.html", cookie=cookie)
