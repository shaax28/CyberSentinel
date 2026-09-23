import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "cybersentinel.db"


def create_database():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            scan_time TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    password_hash = generate_password_hash(
        "CyberSentinel@123"
    )

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password)
        VALUES (?, ?)
    """, ("admin", password_hash))

    cursor.execute("""
        UPDATE users
        SET password = ?
        WHERE username = ?
    """, (password_hash, "admin"))

    conn.commit()
    conn.close()


if __name__ == "__main__":

    create_database()

    print("[+] CyberSentinel database ready.")
    print("[+] Admin password updated with secure hashing.")