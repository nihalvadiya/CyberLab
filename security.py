"""Input validation, CSRF tokens, and the per-IP authentication throttle."""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import defaultdict, deque
from decimal import Decimal, InvalidOperation

from flask import abort, request, session

from config import (
    LOGIN_RATE_MAX,
    LOGIN_RATE_WINDOW,
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_LEN,
    TRUSTED_PROXY_COUNT,
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")

_CSRF_SESSION_KEY = "_csrf_token"
_UNSAFE_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


# ---------------------------------------------------------------- credentials


def validate_username(raw: str) -> str:
    username = (raw or "").strip()
    if not USERNAME_RE.match(username):
        raise ValidationError(
            "Username must be 3-32 characters, start with a letter or digit, and "
            "contain only letters, digits, underscore, dot or hyphen."
        )
    return username


def validate_password(raw: str) -> str:
    password = raw or ""
    if len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LEN} characters."
        )
    # bcrypt hashes at most 72 bytes. Rejecting longer input beats truncating it:
    # truncation would make every password sharing the first 72 bytes equivalent.
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValidationError(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes "
            "(non-ASCII characters count as more than one byte)."
        )
    return password


def parse_amount_to_cents(raw: str) -> int:
    """
    Parse a user-entered money amount into integer cents.

    Money is never held as a float: 0.1 + 0.2 != 0.3 in binary floating point,
    and rounding drift in a balance is a real defect.
    """
    text = (raw or "").strip().replace(",", "")
    if not text:
        raise ValidationError("Enter an amount.")
    if not re.fullmatch(r"\d{1,12}(\.\d{1,2})?", text):
        raise ValidationError(
            "Amount must be a positive number with at most two decimal places."
        )
    try:
        cents = int((Decimal(text) * 100).to_integral_value())
    except (InvalidOperation, ValueError) as exc:
        raise ValidationError("Amount is not a valid number.") from exc
    if cents <= 0:
        raise ValidationError("Amount must be greater than zero.")
    return cents


def format_cents(cents: int) -> str:
    return f"{Decimal(cents) / 100:,.2f}"


# ---------------------------------------------------------------------- CSRF


def csrf_token() -> str:
    """Return this session's CSRF token, minting one on first use."""
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def rotate_csrf_token() -> None:
    """Issue a fresh token; called on login and logout alongside session reset."""
    session[_CSRF_SESSION_KEY] = secrets.token_urlsafe(32)


def enforce_csrf() -> None:
    """
    Reject any state-changing request without a matching token.

    Registered as a ``before_request`` hook so every current and future POST
    handler is covered, rather than each one remembering to check.
    """
    if request.method not in _UNSAFE_METHODS:
        return
    expected = session.get(_CSRF_SESSION_KEY)
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400, description="CSRF validation failed.")


# ------------------------------------------------------------- rate limiting


class SlidingWindowLimiter:
    """
    Allow at most ``max_events`` per ``window_sec`` for each key.

    ponytail: in-process memory, so each worker keeps its own counters and the
    effective limit scales with worker count. Move to Redis if you run more than
    one process and need an exact global limit.
    """

    def __init__(self, max_events: int, window_sec: int) -> None:
        self._max = max_events
        self._window = window_sec
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """Record an attempt; return False once the key is over its limit."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            # Drop keys that have gone quiet so the dict cannot grow without bound.
            if len(self._events) > 10_000:
                for stale in [k for k, v in self._events.items() if not v]:
                    del self._events[stale]
            return True

    def retry_after(self, key: str) -> int:
        with self._lock:
            bucket = self._events.get(key)
            if not bucket:
                return 0
            return max(0, int(self._window - (time.monotonic() - bucket[0])) + 1)


login_limiter = SlidingWindowLimiter(LOGIN_RATE_MAX, LOGIN_RATE_WINDOW)


def client_ip() -> str:
    """
    Best-effort client address.

    X-Forwarded-For is only consulted when TRUSTED_PROXY_COUNT says a proxy
    actually sets it; otherwise any client could spoof the header and reset its
    own throttle bucket on every request.
    """
    if TRUSTED_PROXY_COUNT > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if len(parts) >= TRUSTED_PROXY_COUNT:
                return parts[-TRUSTED_PROXY_COUNT]
    return request.remote_addr or "unknown"
