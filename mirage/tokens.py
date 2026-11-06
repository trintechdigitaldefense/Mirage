"""Honeytoken lifecycle — Stage 3 item 7.

Tracks every planted token: id, type, path, deployed_at, hits, last_hit, status.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir

_lock = threading.Lock()


def _path() -> Path:
    return ensure_data_dir() / "tokens.json"


def _load() -> Dict[str, Any]:
    p = _path()
    if not p.exists():
        return {"tokens": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"tokens": {}}


def _save(data: Dict[str, Any]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def register_token(
    token_id: str,
    token_type: str,
    path: str = "",
    label: str = "",
    extra: Optional[dict] = None,
) -> Dict[str, Any]:
    with _lock:
        data = _load()
        tokens = data.setdefault("tokens", {})
        rec = {
            "id": token_id,
            "type": token_type,
            "path": path,
            "label": label,
            "status": "deployed",
            "deployed_at": datetime.utcnow().isoformat() + "Z",
            "hits": 0,
            "last_hit": None,
            "last_source_ip": None,
        }
        if extra:
            rec["extra"] = extra
        tokens[token_id] = rec
        _save(data)
        return rec


def record_hit(token_id: str, source_ip: str = "", path: str = "") -> Optional[Dict[str, Any]]:
    if not token_id or token_id == "unknown":
        return None
    with _lock:
        data = _load()
        tokens = data.setdefault("tokens", {})
        rec = tokens.get(token_id)
        if not rec:
            rec = {
                "id": token_id,
                "type": "unknown",
                "path": path,
                "label": "",
                "status": "hit_untracked",
                "deployed_at": None,
                "hits": 0,
            }
            tokens[token_id] = rec
        rec["hits"] = int(rec.get("hits") or 0) + 1
        rec["last_hit"] = datetime.utcnow().isoformat() + "Z"
        rec["last_source_ip"] = source_ip or rec.get("last_source_ip")
        rec["status"] = "hit"
        _save(data)
        return rec


def list_tokens() -> List[Dict[str, Any]]:
    with _lock:
        data = _load()
        return list((data.get("tokens") or {}).values())


def lifecycle_summary() -> Dict[str, Any]:
    rows = list_tokens()
    by_status: Dict[str, int] = {}
    for r in rows:
        s = r.get("status") or "unknown"
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "total": len(rows),
        "by_status": by_status,
        "hit": by_status.get("hit", 0) + by_status.get("hit_untracked", 0),
        "deployed_only": by_status.get("deployed", 0),
    }
