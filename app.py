"""
CyberLab — a Flask web application security lab.

Run without ``CYBERLAB_LAB_MODE`` and only the hardened application exists: the
deliberately vulnerable training endpoints are never registered, so they return
404 rather than relying on a runtime check somewhere inside the handler.

Set ``CYBERLAB_LAB_MODE=1`` to mount the vulnerable endpoints under ``/lab``.
That mode is for an isolated machine, never a public host.
"""

from __future__ import annotations

import os
import time

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

import config
import db
from security import (
    ValidationError,
    client_ip,
    csrf_token,
    enforce_csrf,
    format_cents,
    login_limiter,
    parse_amount_to_cents,
    rotate_csrf_token,
    validate_password,
    validate_username,
)

# Deliberately identical for every failure reason. Distinct messages for "no such
# user", "wrong password" and "locked" let an attacker enumerate valid accounts.
GENERIC_LOGIN_ERROR = (
    "Invalid username or password, or the account is temporarily locked."
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = config.load_secret_key()

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=config.FORCE_HTTPS,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="cyberlab_session",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=False,
    )

    if config.TRUSTED_PROXY_COUNT > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=config.TRUSTED_PROXY_COUNT,
            x_proto=config.TRUSTED_PROXY_COUNT,
            x_host=config.TRUSTED_PROXY_COUNT,
        )

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["lab_mode"] = config.LAB_MODE
    app.jinja_env.filters["money"] = format_cents

    db.setup_database()

    _register_hooks(app)
    _register_routes(app)
    _register_error_handlers(app)

    if config.LAB_MODE:
        from lab_routes import lab

        app.register_blueprint(lab, url_prefix="/lab")

    return app


# --------------------------------------------------------------------- hooks


def _register_hooks(app: Flask) -> None:
    @app.before_request
    def _csrf() -> None:
        enforce_csrf()

    @app.after_request
    def _security_headers(response):
        # No 'unsafe-inline' anywhere: all styles live in static/style.css, so an
        # injected <style> or style="" payload cannot execute.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "object-src 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), interest-cohort=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if config.FORCE_HTTPS:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


def _current_user() -> str | None:
    return session.get("user")


def _require_login() -> str:
    user = _current_user()
    if not user:
        abort(401)
    return user


# -------------------------------------------------------------------- routes


def _register_routes(app: Flask) -> None:
    @app.route("/")
    def home():
        return render_template("home.html", user=_current_user())

    # ------------------------------------------------------------- register
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        if not login_limiter.check(f"register:{client_ip()}"):
            abort(429)

        try:
            username = validate_username(request.form.get("username", ""))
            password = validate_password(request.form.get("password", ""))
        except ValidationError as exc:
            flash(str(exc), "error")
            return render_template("register.html"), 400

        if not db.create_user(username, password):
            # Same wording and status as success would be ideal, but a registration
            # form has to tell the user the name is taken to be usable at all.
            flash("That username is not available.", "error")
            return render_template("register.html"), 409

        flash("Account created. You can sign in now.", "success")
        return redirect(url_for("login"))

    # ---------------------------------------------------------------- login
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        ip = client_ip()
        if not login_limiter.check(f"login:{ip}"):
            flash(
                f"Too many attempts. Try again in {login_limiter.retry_after(f'login:{ip}')} seconds.",
                "error",
            )
            return render_template("login.html"), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        row = db.get_user(username) if username else None
        now = int(time.time())

        # Runs even when the row is missing, so the response time is the same
        # either way and cannot be used to probe for valid usernames.
        password_ok = db.verify_password(
            password, row["password_hash"] if row is not None else None
        )

        if row is None or (row["lock_until"] and row["lock_until"] > now):
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html"), 401

        if not password_ok:
            db.register_login_failure(username, db.effective_attempts(row, now))
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html"), 401

        db.register_login_success(username)

        # Drop everything the pre-authentication session held, so a token an
        # attacker planted in the victim's browser cannot survive into the
        # authenticated session (session fixation).
        session.clear()
        session["user"] = username
        session["is_admin"] = bool(row["is_admin"])
        session.permanent = True
        rotate_csrf_token()
        return redirect(url_for("home"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        rotate_csrf_token()
        flash("Signed out.", "success")
        return redirect(url_for("home"))

    # -------------------------------------------------------------- profile
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        user = _require_login()

        if request.method == "POST":
            bio = (request.form.get("bio") or "").strip()
            if len(bio) > config.MAX_BIO_LEN:
                flash(
                    f"Bio must be at most {config.MAX_BIO_LEN} characters.", "error"
                )
            else:
                # Stored in the database, not the session: Flask session cookies
                # cap out around 4KB, so a long bio in the session would silently
                # produce an oversized cookie the browser drops.
                db.set_bio(user, bio)
                flash("Bio saved.", "success")
            return redirect(url_for("profile"))

        row = db.get_user(user)
        if row is None:
            session.clear()
            return redirect(url_for("login"))
        return render_template("profile.html", user=user, bio=row["bio"])

    # ------------------------------------------------------------- transfer
    @app.route("/transfer", methods=["GET", "POST"])
    def transfer():
        user = _require_login()

        if request.method == "POST":
            try:
                recipient = validate_username(request.form.get("to", ""))
                amount_cents = parse_amount_to_cents(request.form.get("amount", ""))
                db.transfer_funds(user, recipient, amount_cents)
            except ValidationError as exc:
                flash(str(exc), "error")
            except db.UnknownRecipient:
                flash("No account with that username.", "error")
            except db.InsufficientFunds:
                flash("Insufficient funds for that transfer.", "error")
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash(
                    f"Sent ${format_cents(amount_cents)} to {recipient}.", "success"
                )
            return redirect(url_for("transfer"))

        row = db.get_user(user)
        if row is None:
            session.clear()
            return redirect(url_for("login"))
        return render_template(
            "transfer.html",
            user=user,
            balance_cents=row["balance_cents"],
            transfers=db.recent_transfers(user),
        )

    # ---------------------------------------------------------------- admin
    @app.route("/admin")
    def admin():
        _require_login()
        # Authentication is not authorisation: being signed in is checked above,
        # having the admin role is checked here.
        if not session.get("is_admin"):
            abort(403)
        return render_template("admin.html", users=db.list_users())

    # --------------------------------------------------------------- search
    @app.route("/search")
    def search():
        query = request.args.get("q", "")[:200]
        return render_template("search.html", query=query)

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "lab_mode": config.LAB_MODE}


# ------------------------------------------------------------ error handlers


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        if exc.code == 401:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))
        return (
            render_template("error.html", code=exc.code, message=exc.description),
            exc.code or 500,
        )

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        # Log the detail, show the user nothing: stack traces and driver messages
        # in a response body are free reconnaissance.
        app.logger.exception("Unhandled error on %s", request.path, exc_info=exc)
        return (
            render_template(
                "error.html",
                code=500,
                message="Something went wrong. The error has been logged.",
            ),
            500,
        )


app = create_app()


if __name__ == "__main__":
    # debug=True would expose the Werkzeug console, which is remote code
    # execution for anyone who can reach it. Opt in explicitly and locally only.
    app.run(
        host=os.environ.get("CYBERLAB_HOST", "127.0.0.1"),
        port=config.env_int("CYBERLAB_PORT", 5000),
        debug=config.env_bool("CYBERLAB_DEBUG", default=False),
    )
