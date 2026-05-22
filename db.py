import os
import sqlite3
import datetime
from contextlib import closing
from typing import List, Dict, Any

def _get_db_path() -> str:
    """Helper function to retrieve the database path from environment variable or fallback."""
    return os.environ.get('DB_PATH', './phish_siem.db')

def init_db() -> None:
    """Creates the 'emails' table if it doesn't already exist."""
    db_path = _get_db_path()
    # Create the directory for the database if it doesn't exist
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
        
    with closing(sqlite3.connect(db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                subject TEXT,
                body TEXT,
                verdict TEXT,
                confidence REAL,
                reason TEXT,
                received_at TEXT,
                analyzed_at TEXT
            )
        ''')
        conn.commit()

def insert_email(
    sender: str,
    subject: str,
    body: str,
    verdict: str,
    confidence: float,
    reason: str,
    received_at: str
) -> None:
    """Inserts a single email record into the database, setting analyzed_at to the current UTC time."""
    db_path = _get_db_path()
    analyzed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    with closing(sqlite3.connect(db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO emails (sender, subject, body, verdict, confidence, reason, received_at, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (sender, subject, body, verdict, confidence, reason, received_at, analyzed_at))
        conn.commit()

def get_all_emails() -> List[Dict[str, Any]]:
    """Returns all rows from the emails table ordered by analyzed_at descending.
    
    Each row is represented as a dictionary.
    """
    db_path = _get_db_path()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM emails ORDER BY analyzed_at DESC')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
