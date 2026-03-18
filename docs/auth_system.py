import bcrypt
import sqlite3
import time
from datetime import datetime

DATABASE_FILE = "auth.db"

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


def register():
    username = input("Enter username: ")
    password = input("Enter password: ").encode()

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt).decode()

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
        INSERT INTO users (username, password_hash, failed_attempts, lock_until)
        VALUES (?, ?, 0, 0)
        """, (username, hashed))

        conn.commit()
        print("User registered successfully!\n")

    except sqlite3.IntegrityError:
        print("Username already exists!\n")

    conn.close()


def login():
    username = input("Enter username: ")
    password = input("Enter password: ").encode()

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, failed_attempts, lock_until FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("User not found!\n")
        conn.close()
        return

    stored_hash, attempts, lock_until = result
    current_time = int(time.time())

    print("Current time:", datetime.fromtimestamp(current_time))

    # Check if locked
    if lock_until > current_time:
        remaining = lock_until - current_time
        unlock_time = datetime.fromtimestamp(lock_until)

        print("\nAccount is locked!")
        print(f"Try again in {remaining} seconds.")
        print(f"Locked until: {unlock_time}\n")

        conn.close()
        return

    # Auto unlock
    if lock_until != 0 and lock_until <= current_time:
        attempts = 0
        lock_until = 0

    if bcrypt.checkpw(password, stored_hash.encode()):
        print("Login successful!\n")
        cursor.execute("""
        UPDATE users
        SET failed_attempts = 0, lock_until = 0
        WHERE username = ?
        """, (username,))
    else:
        attempts += 1

        if attempts >= MAX_ATTEMPTS:
            lock_until = current_time + LOCK_DURATION_SECONDS
            unlock_time = datetime.fromtimestamp(lock_until)

            print("\nToo many failed attempts.")
            print(f"Account locked until: {unlock_time}\n")

            cursor.execute("""
            UPDATE users
            SET failed_attempts = ?, lock_until = ?
            WHERE username = ?
            """, (attempts, lock_until, username))
        else:
            print("Wrong password!\n")
            cursor.execute("""
            UPDATE users
            SET failed_attempts = ?
            WHERE username = ?
            """, (attempts, username))

    conn.commit()
    conn.close()


# 🚨 INTENTIONALLY VULNERABLE LOGIN (FOR SQL INJECTION DEMO)
def login_vulnerable():
    username = input("Enter username: ")
    password = input("Enter password: ").encode()

    conn = connect_db()
    cursor = conn.cursor()

    # ❌ VULNERABLE QUERY (string interpolation)
    query = f"SELECT password_hash FROM users WHERE username = '{username}'"
    print("DEBUG QUERY:", query)

    cursor.execute(query)
    result = cursor.fetchone()

    if not result:
        print("User not found!\n")
        conn.close()
        return

    stored_hash = result[0]

    if bcrypt.checkpw(password, stored_hash.encode()):
        print("Login successful!\n")
    else:
        print("Wrong password!\n")

    conn.close()


def reset_database():
    confirm = input("Delete entire database? (yes/no): ")
    if confirm.lower() == "yes":
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        conn.commit()
        conn.close()
        setup_database()
        print("Database reset complete.\n")
    else:
        print("Reset cancelled.\n")


def main():
    setup_database()

    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        print("4. Reset Database")
        print("5. Vulnerable Login (SQLi Demo)")

        choice = input("Choose option: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        elif choice == "4":
            reset_database()
        elif choice == "5":
            login_vulnerable()
        else:
            print("Invalid option\n")


if __name__ == "__main__":
    main()
