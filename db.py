"""
SQLite data layer.

Every connection is opened and closed through :func:`transaction`, so no code
path can leak a handle on an early return or an exception. All statements are
parameterised.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

import bcrypt

from config import (
    ADMIN_USERS,
    DATABASE_FILE,
    LOCK_DURATION_SECONDS,
    MAX_ATTEMPTS,
    STARTING_BALANCE_CENTS,
)


class InsufficientFunds(Exception):
    """Raised when a transfer would overdraw the sender."""


class UnknownRecipient(Exception):
    """Raised when a transfer names an account that does not exist."""


# Compared against when a username does not exist, so a login attempt for an
# unknown user costs the same wall-clock time as one for a known user and
# cannot be distinguished by timing.
_DUMMY_HASH = bcrypt.hashpw(b"cyberlab-timing-equalizer", bcrypt.gensalt())


@contextmanager
def transaction(write: bool = False) -> Iterator[sqlite3.Connection]:
    """
    Yield a connection, committing on clean exit and rolling back on error.

    ``write=True`` opens with BEGIN IMMEDIATE so concurrent writers serialise at
    the start of the transaction rather than failing at commit time.
    """
    conn = sqlite3.connect(DATABASE_FILE, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def setup_database() -> None:
    """Create the schema if absent and migrate databases made by older versions."""
    parent = os.path.dirname(DATABASE_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with transaction(write=True) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until      INTEGER NOT NULL DEFAULT 0,
                is_admin        INTEGER NOT NULL DEFAULT 0,
                bio             TEXT    NOT NULL DEFAULT '',
                balance_cents   INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Columns added after the first release; ALTER is a no-op on fresh databases.
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        for column, ddl in (
            ("is_admin", "INTEGER NOT NULL DEFAULT 0"),
            ("bio", "TEXT NOT NULL DEFAULT ''"),
            ("balance_cents", f"INTEGER NOT NULL DEFAULT {STARTING_BALANCE_CENTS}"),
        ):
            if column not in existing:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column} {ddl}")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transfers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id    INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                created_at   INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_id)"
        )

        for username in ADMIN_USERS:
            conn.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))


def get_user(username: str) -> sqlite3.Row | None:
    with transaction() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def create_user(username: str, password: str) -> bool:
    """Register a user. Returns False if the username is already taken."""
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with transaction(write=True) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, failed_attempts,
                                   lock_until, is_admin, bio, balance_cents)
                VALUES (?, ?, 0, 0, 0, '', ?)
                """,
                (username, password_hash, STARTING_BALANCE_CENTS),
            )
    except sqlite3.IntegrityError:
        return False
    return True


def verify_password(password: str, stored_hash: str | None) -> bool:
    """
    Check a password against a stored hash in constant-ish time.

    When ``stored_hash`` is None (unknown user) a dummy comparison still runs, so
    the response time does not reveal whether the account exists.
    """
    encoded = password.encode()
    if stored_hash is None:
        bcrypt.checkpw(encoded, _DUMMY_HASH)
        return False
    try:
        return bcrypt.checkpw(encoded, stored_hash.encode())
    except ValueError:
        # Corrupt or non-bcrypt hash in the row; treat as a failed login.
        return False


def register_login_success(username: str) -> None:
    with transaction(write=True) as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE username = ?",
            (username,),
        )


def register_login_failure(username: str, current_attempts: int) -> bool:
    """
    Record a failed login. Returns True if the account is now locked.

    ``current_attempts`` must already account for an expired lock having reset
    the counter, which :func:`effective_attempts` handles.
    """
    attempts = current_attempts + 1
    now = int(time.time())
    lock_until = now + LOCK_DURATION_SECONDS if attempts >= MAX_ATTEMPTS else 0
    with transaction(write=True) as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
            (0 if lock_until else attempts, lock_until, username),
        )
    return bool(lock_until)


def effective_attempts(row: sqlite3.Row, now: int) -> int:
    """
    Failed-attempt count with an expired lockout treated as a clean slate.

    Without this, an account whose lock has just expired still carries a
    saturated counter, so the next single mistyped password re-locks it
    immediately.
    """
    if row["lock_until"] and row["lock_until"] <= now:
        return 0
    return row["failed_attempts"]


def set_bio(username: str, bio: str) -> None:
    with transaction(write=True) as conn:
        conn.execute("UPDATE users SET bio = ? WHERE username = ?", (bio, username))


def transfer_funds(sender: str, recipient: str, amount_cents: int) -> None:
    """
    Move money between two accounts atomically.

    Raises :class:`UnknownRecipient` or :class:`InsufficientFunds`; on either the
    surrounding transaction rolls back, so no partial debit is possible.
    """
    if amount_cents <= 0:
        raise ValueError("amount_cents must be positive")

    now = int(time.time())
    with transaction(write=True) as conn:
        sender_row = conn.execute(
            "SELECT id, balance_cents FROM users WHERE username = ?", (sender,)
        ).fetchone()
        if sender_row is None:
            raise UnknownRecipient(sender)

        recipient_row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (recipient,)
        ).fetchone()
        if recipient_row is None:
            raise UnknownRecipient(recipient)
        if recipient_row["id"] == sender_row["id"]:
            raise ValueError("Cannot transfer to yourself.")

        # The WHERE guard makes the balance check and the debit a single atomic
        # step, so a concurrent transfer cannot slip between them.
        cursor = conn.execute(
            "UPDATE users SET balance_cents = balance_cents - ? "
            "WHERE id = ? AND balance_cents >= ?",
            (amount_cents, sender_row["id"], amount_cents),
        )
        if cursor.rowcount != 1:
            raise InsufficientFunds(sender)

        conn.execute(
            "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
            (amount_cents, recipient_row["id"]),
        )
        conn.execute(
            "INSERT INTO transfers (sender_id, recipient_id, amount_cents, created_at) "
            "VALUES (?, ?, ?, ?)",
            (sender_row["id"], recipient_row["id"], amount_cents, now),
        )


def recent_transfers(username: str, limit: int = 10) -> list[sqlite3.Row]:
    with transaction() as conn:
        return conn.execute(
            """
            SELECT t.amount_cents,
                   t.created_at,
                   s.username AS sender,
                   r.username AS recipient
            FROM transfers t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            WHERE s.username = ? OR r.username = ?
            ORDER BY t.id DESC
            LIMIT ?
            """,
            (username, username, limit),
        ).fetchall()


def list_users() -> list[sqlite3.Row]:
    with transaction() as conn:
        return conn.execute(
            "SELECT username, is_admin, balance_cents, failed_attempts, lock_until "
            "FROM users ORDER BY username"
        ).fetchall()
