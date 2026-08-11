"""
End-to-end checks for the hardened application.

Run with:  python test_app.py     (no pytest required)
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

# Configure before importing the app: config reads the environment at import time.
_TMP = tempfile.mkdtemp(prefix="cyberlab-test-")
os.environ["CYBERLAB_DATABASE"] = os.path.join(_TMP, "test.db")
os.environ["CYBERLAB_SECRET_KEY"] = "t" * 64
os.environ["CYBERLAB_FORCE_HTTPS"] = "0"
os.environ["CYBERLAB_LAB_MODE"] = "0"
os.environ["CYBERLAB_MAX_ATTEMPTS"] = "3"
os.environ["CYBERLAB_LOCK_SECONDS"] = "60"
os.environ["CYBERLAB_LOGIN_RATE_MAX"] = "100"
os.environ["CYBERLAB_STARTING_BALANCE_CENTS"] = "100000"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db  # noqa: E402
from app import app  # noqa: E402
from security import parse_amount_to_cents, ValidationError  # noqa: E402

PASSWORD = "correct-horse-battery"
_TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _token(client, path: str) -> str:
    body = client.get(path).get_data(as_text=True)
    match = _TOKEN_RE.search(body)
    assert match, f"no CSRF token in {path}"
    return match.group(1)


def _register(client, username: str, password: str = PASSWORD):
    return client.post(
        "/register",
        data={
            "username": username,
            "password": password,
            "csrf_token": _token(client, "/register"),
        },
        follow_redirects=True,
    )


def _login(client, username: str, password: str = PASSWORD):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _token(client, "/login"),
        },
        follow_redirects=True,
    )


def test_csrf_required():
    with app.test_client() as c:
        assert c.post("/login", data={"username": "x", "password": "y"}).status_code == 400
        assert c.post("/transfer", data={"to": "x", "amount": "1"}).status_code == 400


def test_register_validation():
    with app.test_client() as c:
        # Too short a password is rejected, not stored.
        assert _register(c, "shortpw_user", "abc").status_code == 400
        # Over bcrypt's 72-byte ceiling: rejected rather than truncated or 500.
        assert _register(c, "longpw_user", "a" * 200).status_code == 400
        # Illegal username characters.
        assert _register(c, "bad user!", PASSWORD).status_code == 400
        assert db.get_user("shortpw_user") is None
        assert db.get_user("bad user!") is None


def test_register_and_login():
    with app.test_client() as c:
        assert _register(c, "alice").status_code == 200
        assert db.get_user("alice") is not None
        # Password is hashed, never stored in the clear.
        assert PASSWORD not in db.get_user("alice")["password_hash"]

        body = _login(c, "alice").get_data(as_text=True)
        assert "Welcome, alice" in body

        # Duplicate registration does not leak or overwrite.
        assert _register(app.test_client(), "alice").status_code == 409


def test_login_failure_is_not_enumerable():
    with app.test_client() as c:
        _register(c, "bob")

    unknown = _login(app.test_client(), "no_such_user_here")
    wrong = _login(app.test_client(), "bob", "wrong-password-x")
    assert unknown.status_code == wrong.status_code == 401

    # Identical apart from the per-session CSRF token, so the response cannot
    # be used to tell a valid username from an invalid one.
    scrub = lambda r: _TOKEN_RE.sub("", r.get_data(as_text=True))  # noqa: E731
    assert scrub(unknown) == scrub(wrong)


def test_lockout_and_expiry_reset():
    with app.test_client() as c:
        _register(c, "carol")

    for _ in range(3):  # CYBERLAB_MAX_ATTEMPTS
        _login(app.test_client(), "carol", "wrong-password-x")

    row = db.get_user("carol")
    assert row["lock_until"] > 0, "account should be locked"

    # Correct password is refused while locked.
    assert "Welcome, carol" not in _login(app.test_client(), "carol").get_data(as_text=True)

    # Simulate the lock expiring: the attempt counter must reset, otherwise a
    # single mistyped password would immediately re-lock the account.
    with db.transaction(write=True) as conn:
        conn.execute("UPDATE users SET lock_until = 1 WHERE username = 'carol'")
    row = db.get_user("carol")
    assert db.effective_attempts(row, 10_000) == 0

    assert "Welcome, carol" in _login(app.test_client(), "carol").get_data(as_text=True)
    assert db.get_user("carol")["lock_until"] == 0


def test_authorization_is_separate_from_authentication():
    with app.test_client() as c:
        # Anonymous users are redirected to sign in, not shown the page.
        assert "Please sign in" in c.get("/admin", follow_redirects=True).get_data(as_text=True)
        _register(c, "dave")
        _login(c, "dave")
        # Signed in but not an admin: 403, not 200.
        assert c.get("/admin").status_code == 403

    with app.test_client() as c:
        _register(c, "root_admin")
        with db.transaction(write=True) as conn:
            conn.execute("UPDATE users SET is_admin = 1 WHERE username = 'root_admin'")
        _login(c, "root_admin")
        assert c.get("/admin").status_code == 200


def test_xss_payload_is_escaped():
    payload = "<script>alert(1)</script>"
    with app.test_client() as c:
        _register(c, "eve")
        _login(c, "eve")
        c.post(
            "/profile",
            data={"bio": payload, "csrf_token": _token(c, "/profile")},
            follow_redirects=True,
        )
        body = c.get("/profile").get_data(as_text=True)
        assert payload not in body, "raw script tag reached the response"
        assert "&lt;script&gt;" in body

        reflected = c.get("/search?q=" + payload).get_data(as_text=True)
        assert payload not in reflected


def test_sql_injection_is_inert_on_hardened_login():
    with app.test_client() as c:
        _register(c, "frank")
    body = _login(app.test_client(), "' OR '1'='1' --", "anything").get_data(as_text=True)
    assert "Welcome" not in body
    # The table survived; the payload was bound as a literal, not executed.
    assert db.get_user("frank") is not None


def test_transfer_moves_money_and_is_atomic():
    # Registered through separate, non-overlapping clients: nesting two
    # `with app.test_client()` blocks unwinds Flask's context stack out of order.
    with app.test_client() as c:
        _register(c, "payee")

    with app.test_client() as sender:
        _register(sender, "payer")
        _login(sender, "payer")

        start_payer = db.get_user("payer")["balance_cents"]
        start_payee = db.get_user("payee")["balance_cents"]

        sender.post(
            "/transfer",
            data={"to": "payee", "amount": "25.50", "csrf_token": _token(sender, "/transfer")},
            follow_redirects=True,
        )
        assert db.get_user("payer")["balance_cents"] == start_payer - 2550
        assert db.get_user("payee")["balance_cents"] == start_payee + 2550

        # Overdraft is refused and leaves both balances untouched.
        before = db.get_user("payer")["balance_cents"]
        body = sender.post(
            "/transfer",
            data={"to": "payee", "amount": "999999", "csrf_token": _token(sender, "/transfer")},
            follow_redirects=True,
        ).get_data(as_text=True)
        assert "Insufficient funds" in body
        assert db.get_user("payer")["balance_cents"] == before

        # Unknown recipient and self-transfer are both rejected.
        for recipient, expected in (("ghost_account", "No account"), ("payer", "yourself")):
            body = sender.post(
                "/transfer",
                data={"to": recipient, "amount": "1.00", "csrf_token": _token(sender, "/transfer")},
                follow_redirects=True,
            ).get_data(as_text=True)
            assert expected in body
        assert db.get_user("payer")["balance_cents"] == before


def test_amount_parsing_rejects_junk():
    assert parse_amount_to_cents("25.50") == 2550
    assert parse_amount_to_cents("1,000") == 100_000
    for bad in ("", "-5", "0", "abc", "1.2.3", "1e9", "0.001", " 5; DROP TABLE users"):
        try:
            parse_amount_to_cents(bad)
        except ValidationError:
            continue
        raise AssertionError(f"accepted invalid amount {bad!r}")


def test_session_is_cleared_on_login_and_logout():
    with app.test_client() as c:
        _register(c, "grace")
        pre_login_token = _token(c, "/login")
        _login(c, "grace")
        # Session fixation: the token from before authentication must not survive.
        assert _token(c, "/profile") != pre_login_token

        c.post("/logout", data={"csrf_token": _token(c, "/profile")}, follow_redirects=True)
        assert "Please sign in" in c.get("/profile", follow_redirects=True).get_data(as_text=True)


def test_vulnerable_routes_absent_outside_lab_mode():
    with app.test_client() as c:
        for path in ("/lab/", "/lab/login-sqli", "/lab/search-xss", "/lab/steal"):
            assert c.get(path).status_code == 404, f"{path} must not exist in production mode"


def test_security_headers_present():
    with app.test_client() as c:
        headers = c.get("/").headers
        csp = headers["Content-Security-Policy"]
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert "frame-ancestors 'none'" in csp
        for name in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
                     "Permissions-Policy"):
            assert name in headers, f"missing {name}"

        cookie = c.post(
            "/login",
            data={"username": "nobody", "password": "x", "csrf_token": _token(c, "/login")},
        ).headers.get("Set-Cookie", "")
        if cookie:
            assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures += 1
            print(f"FAIL  {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {test.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
