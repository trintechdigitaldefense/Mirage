"""Alert acknowledgement and false-positive marking (Stage 4 item 17)."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir

_lock = threading.Lock()


def _path() -> Path:
    return ensure_data_dir() / "acks.json"


def _load() -> Dict[str, Any]:
    p = _path()
    if not p.exists():
        return {"acks": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"acks": {}}


def _save(data: Dict[str, Any]) -> None:
    p = _path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def acknowledge(
    event_id: str,
    *,
    operator: str = "operator",
    reason: str = "",
    false_positive: bool = False,
) -> Dict[str, Any]:
    with _lock:
        data = _load()
        rec = {
            "event_id": str(event_id),
            "operator": operator,
            "reason": reason[:500],
            "false_positive": bool(false_positive),
            "acked_at": datetime.utcnow().isoformat() + "Z",
        }
        data.setdefault("acks", {})[str(event_id)] = rec
        _save(data)
        return rec


def get_ack(event_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        return (_load().get("acks") or {}).get(str(event_id))


def list_acks(limit: int = 50) -> List[Dict[str, Any]]:
    with _lock:
        rows = list((_load().get("acks") or {}).values())
    rows.sort(key=lambda r: r.get("acked_at") or "", reverse=True)
    return rows[:limit]
