import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

from .config import ensure_data_dir


def get_db_path() -> Path:
    return ensure_data_dir() / "events.db"


def _conn():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                details TEXT,
                severity TEXT DEFAULT 'high',
                authorization_ref TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                authorization_ref TEXT,
                details TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cooldown (
                key TEXT PRIMARY KEY,
                last_alerted TEXT NOT NULL
            )
        """)
        conn.commit()


def log_event(event_type: str, source_ip: str = "",
              details: dict = None, severity: str = "high",
              authorization_ref: str = "") -> None:
    init_db()
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO events (timestamp, event_type, source_ip, details, severity, authorization_ref) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat() + "Z",
                event_type,
                source_ip,
                json.dumps(details or {}),
                severity,
                authorization_ref,
            ),
        )
        conn.commit()


def log_auth(action: str, authorization_ref: str = "", details: str = "") -> None:
    init_db()
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO auth_log (timestamp, action, authorization_ref, details) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat() + "Z", action, authorization_ref, details),
        )
        conn.commit()


def is_in_cooldown(key: str, seconds: int) -> bool:
    init_db()
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT last_alerted FROM cooldown WHERE key = ?", (key,))
        row = cur.fetchone()
        if not row:
            return False
        last = datetime.fromisoformat(row["last_alerted"].replace("Z", ""))
        return (datetime.utcnow() - last).total_seconds() < seconds


def set_cooldown(key: str) -> None:
    init_db()
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO cooldown (key, last_alerted) VALUES (?, ?)",
            (key, datetime.utcnow().isoformat() + "Z"),
        )
        conn.commit()


def get_recent_events(hours: int = 24) -> List[Dict[str, Any]]:
    init_db()
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_all_events(limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
