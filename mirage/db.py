"""Mirage event database — init once, indexed, retention-aware, secrets redacted."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir, load_config
from .redaction import redact_details

_init_lock = threading.Lock()
_initialized = False


def get_db_path() -> Path:
    cfg = load_config()
    return ensure_data_dir(cfg) / "events.db"


def _conn():
    path = get_db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    global _initialized
    with _init_lock:
        if _initialized:
            return
        path = get_db_path()
        with _conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    details TEXT,
                    severity TEXT DEFAULT 'high',
                    authorization_ref TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    authorization_ref TEXT,
                    details TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS cooldown (
                    key TEXT PRIMARY KEY,
                    last_alerted TEXT NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity)")
            conn.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _initialized = True


def log_event(
    event_type: str,
    source_ip: str = "",
    details: dict = None,
    severity: str = "high",
    authorization_ref: str = "",
) -> None:
    init_db()
    safe = redact_details(details or {})
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO events (timestamp, event_type, source_ip, details, severity, authorization_ref) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat() + "Z",
                event_type,
                source_ip,
                json.dumps(safe),
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
            (datetime.utcnow().isoformat() + "Z", action, authorization_ref, details[:500]),
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


def purge_old_events(days: Optional[int] = None) -> int:
    """Delete events older than retention. Returns rows removed."""
    init_db()
    if days is None:
        days = int(load_config().get("event_retention_days") or 90)
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        n = cur.rowcount
        conn.commit()
        return n
