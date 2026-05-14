import sqlite3
from pathlib import Path


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

DB_FILE = OUTPUT_DIR / "recon.db"


def init_db():

    conn = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_report(module, content):

    conn = sqlite3.connect(DB_FILE)

    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO reports (module, content) VALUES (?, ?)",
        (module, content)
    )

    conn.commit()
    conn.close()