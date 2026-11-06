"""Session correlation and event identity (Stage 4 items 15–16)."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

_lock = threading.Lock()
# (source_ip, service) -> (session_id, last_seen)
_sessions: Dict[Tuple[str, str], Tuple[str, float]] = {}
SESSION_GAP_SEC = 600.0  # new session if quiet for 10 minutes


def new_event_id() -> str:
    return str(uuid.uuid4())


def session_id_for(source_ip: str, service: str = "") -> str:
    """Return stable session id for source+service within SESSION_GAP_SEC."""
    key = ((source_ip or "unknown").strip(), (service or "default").strip().lower())
    now = time.time()
    with _lock:
        prev = _sessions.get(key)
        if prev and (now - prev[1]) < SESSION_GAP_SEC:
            sid, _ = prev
            _sessions[key] = (sid, now)
            return sid
        sid = str(uuid.uuid4())
        _sessions[key] = (sid, now)
        return sid


def enrich_event_fields(
    event_type: str,
    source_ip: str = "",
    details: Optional[dict] = None,
) -> Dict[str, Any]:
    """Add event_uid, session_id, decoy_id into a copy of details."""
    d = dict(details or {})
    service = (d.get("service") or event_type or "unknown").lower()
    d.setdefault("event_uid", new_event_id())
    d.setdefault("session_id", session_id_for(source_ip, service))
    d.setdefault("decoy_id", d.get("decoy_id") or d.get("canary") or service)
    d.setdefault("integrity", {"schema": "mirage-event-v2"})
    return d


def active_sessions() -> List[Dict[str, Any]]:
    now = time.time()
    out = []
    with _lock:
        for (ip, svc), (sid, last) in _sessions.items():
            if now - last < SESSION_GAP_SEC:
                out.append({"source_ip": ip, "service": svc, "session_id": sid, "age_sec": int(now - last)})
    return out
