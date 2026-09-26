import os
import sqlite3
from datetime import datetime
from flask import g, has_app_context

import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On Vercel / serverless platforms, BASE_DIR is read-only; use /tmp for runtime logs
if os.environ.get('VERCEL') or not os.access(BASE_DIR, os.W_OK):
    DB_DIR = os.path.join(tempfile.gettempdir(), 'password_evaluation_db')
else:
    DB_DIR = os.path.join(BASE_DIR, 'database')

LOCAL_PASSWORDS_DB = os.path.join(BASE_DIR, 'database', 'passwords.db')
PASSWORDS_DB_PATH = LOCAL_PASSWORDS_DB if os.path.exists(LOCAL_PASSWORDS_DB) else os.path.join(DB_DIR, 'passwords.db')
LOGS_DB_PATH = os.path.join(DB_DIR, 'logs.db')

def init_db_storage():
    """Ensure database directory and logs.db schema exist without crashing on read-only systems."""
    try:
        if not os.path.exists(DB_DIR):
            os.makedirs(DB_DIR, exist_ok=True)

        conn = sqlite3.connect(LOGS_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                dict_match INTEGER NOT NULL,
                entropy REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Init Notice (Read-only environment or /tmp access): {e}")

init_db_storage()

def get_passwords_db():
    if has_app_context():
        if 'passwords_db' not in g:
            g.passwords_db = sqlite3.connect(PASSWORDS_DB_PATH)
            g.passwords_db.row_factory = sqlite3.Row
        return g.passwords_db
    conn = sqlite3.connect(PASSWORDS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def check_password_in_corpus(password):
    """
    Sub-millisecond indexed lookup in database/passwords.db.
    """
    if not os.path.exists(PASSWORDS_DB_PATH):
        return False

    pw_lower = password.strip().lower()
    if not pw_lower:
        return False

    try:
        db = get_passwords_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM passwords WHERE password = ? LIMIT 1", (pw_lower,))
        found = cursor.fetchone() is not None
        if not has_app_context():
            db.close()
        return found
    except Exception as e:
        print(f"Database Lookup Exception: {e}")
        return False

def log_evaluation_anonymous(score, verdict, dict_match, entropy_val):
    """
    Logs evaluation telemetry anonymously into database/logs.db.
    NEVER logs plain-text user passwords for zero-trust privacy compliance.
    """
    try:
        conn = sqlite3.connect(LOGS_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO evaluation_logs (timestamp, score, verdict, dict_match, entropy)
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            score,
            verdict,
            1 if dict_match else 0,
            entropy_val
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit Log Error: {e}")
