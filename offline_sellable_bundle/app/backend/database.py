import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pentest.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        tool TEXT NOT NULL,
        status TEXT CHECK(status IN
            ('pending','running','completed','failed','reported')
        ) DEFAULT 'pending',
        results TEXT,
        report TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.commit()
    db.close()

def create_scan(user_id, target, tool):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (user_id, target, tool, status) VALUES (?, ?, ?, 'running')",
        (user_id, target, tool)
    )
    scan_id = cur.lastrowid
    db.commit()
    db.close()
    return scan_id

def update_scan(scan_id, status, results=None):
    db = get_db()
    cur = db.cursor()

    if results:
        cur.execute(
            "UPDATE scans SET status=?, results=? WHERE id=?",
            (status, results, scan_id)
        )
    else:
        cur.execute(
            "UPDATE scans SET status=? WHERE id=?",
            (status, scan_id)
        )

    db.commit()
    db.close()

def list_user_scans(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, target, tool, status, created_at FROM scans WHERE user_id=? ORDER BY id DESC",
        (user_id,)
    )
    rows = cur.fetchall()
    db.close()
    return [dict(r) for r in rows]
