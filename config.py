"""
Runtime configuration, read from the environment.

Two modes:

* **Default (deployable):** only hardened endpoints are registered. Secure cookies,
  HSTS and a strict CSP are on. Safe to expose on a public host.
* **Lab mode** (``CYBERLAB_LAB_MODE=1``): additionally registers the deliberately
  vulnerable endpoints used for OWASP training. Never enable this on a public host.
"""

from __future__ import annotations

import os
import secrets
import sys

_TRUTHY = frozenset(("1", "true", "yes", "on"))

# Repo root, so the database path does not depend on the current working directory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


def env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {value}")
    return value


LAB_MODE = env_bool("CYBERLAB_LAB_MODE", default=False)

DATABASE_FILE = os.environ.get(
    "CYBERLAB_DATABASE", os.path.join(BASE_DIR, "database", "auth.db")
)

# Account lockout. The defaults are deliberately gentle for a teaching lab; raise
# MAX_ATTEMPTS for anything resembling real use.
MAX_ATTEMPTS = env_int("CYBERLAB_MAX_ATTEMPTS", 5)
LOCK_DURATION_SECONDS = env_int("CYBERLAB_LOCK_SECONDS", 300)

# Per-IP throttle on authentication endpoints.
LOGIN_RATE_MAX = env_int("CYBERLAB_LOGIN_RATE_MAX", 10)
LOGIN_RATE_WINDOW = env_int("CYBERLAB_LOGIN_RATE_WINDOW", 60)

# Credential policy. 72 bytes is a hard bcrypt limit: longer inputs raise in
# bcrypt >= 4, and silently truncated in older versions (so two different long
# passwords would authenticate against the same hash).
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LEN = env_int("CYBERLAB_MIN_PASSWORD_LEN", 12)

MAX_BIO_LEN = 2000
STARTING_BALANCE_CENTS = env_int("CYBERLAB_STARTING_BALANCE_CENTS", 100_000)

# Usernames granted admin at startup, e.g. CYBERLAB_ADMIN_USERS="admin,nihal".
ADMIN_USERS = tuple(
    u.strip() for u in os.environ.get("CYBERLAB_ADMIN_USERS", "").split(",") if u.strip()
)

# Serve over HTTPS only. Defaults on outside lab mode; turning it on makes the
# session cookie Secure, so plain-http logins will stop working.
FORCE_HTTPS = env_bool("CYBERLAB_FORCE_HTTPS", default=not LAB_MODE)

# Number of trusted reverse proxies in front of the app. Leave at 0 unless you
# actually run behind one — otherwise clients can spoof X-Forwarded-For and
# evade the per-IP login throttle.
TRUSTED_PROXY_COUNT = env_int("CYBERLAB_TRUSTED_PROXIES", 0, minimum=0)


def load_secret_key() -> str:
    """
    Return the session signing key.

    Outside lab mode a real key is mandatory: an ephemeral key would differ per
    worker process, so sessions would break at random under any multi-worker
    WSGI server, and a hardcoded one would let anyone forge session cookies.
    """
    key = os.environ.get("CYBERLAB_SECRET_KEY", "").strip()
    if key:
        if len(key) < 32:
            raise RuntimeError("CYBERLAB_SECRET_KEY must be at least 32 characters.")
        return key

    if LAB_MODE:
        print(
            "[cyberlab] CYBERLAB_SECRET_KEY unset; using an ephemeral key. "
            "Sessions reset on restart and this is single-process only.",
            file=sys.stderr,
        )
        return secrets.token_hex(32)

    raise RuntimeError(
        "CYBERLAB_SECRET_KEY is not set.\n"
        "Generate one with:  python -c \"import secrets;print(secrets.token_hex(32))\"\n"
        "Then export it before starting the app."
    )
