"""Deception health & uptime SLA view — Feature 17.

Client-visible proof the grid is alive: decoy uptime hints, last interaction,
coverage score. Designed to feed Sentinel portal fields; also usable standalone.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from .config import ensure_data_dir, load_config
from .coverage import compute_coverage
from .db import get_recent_events, get_all_events
from .mesh import register_site, mesh_summary
from . import guardrails


def _heartbeat_path() -> Path:
    return ensure_data_dir() / "heartbeat.json"


def write_heartbeat(extra: Dict[str, Any] = None) -> Dict[str, Any]:
    cfg = load_config()
    events_24h = get_recent_events(hours=24)
    last = get_all_events(limit=1)
    cov = compute_coverage(cfg)
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "version": "2.2.0",
        "organization": cfg.get("organization_name") or "",
        "site_id": cfg.get("site_id") or "",
        "authorization_ref": cfg.get("authorization_ref") or "",
        "events_24h": len(events_24h),
        "last_event_at": last[0]["timestamp"] if last else None,
        "coverage_score": cov["score"],
        "ssh_jail": bool(cfg.get("ssh_jail_enabled", True)),
        "smb": bool(cfg.get("smb_enabled", True)),
        "beacon": bool(cfg.get("beacon_enabled", True)),
        "cloud_decoy": bool(cfg.get("cloud_decoy_enabled", True)),
        "guardrails": guardrails.status(),
    }
    if extra:
        payload.update(extra)
    _heartbeat_path().write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def read_heartbeat() -> Optional[Dict[str, Any]]:
    path = _heartbeat_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def health_report() -> str:
    hb = write_heartbeat()
    # Refresh mesh registration as part of health check
    try:
        register_site({"health_ts": hb["ts"]})
    except Exception:
        pass
    mesh = mesh_summary()

    lines = [
        "Mirage Deception Health",
        "=" * 50,
        f"Timestamp      : {hb['ts']}",
        f"Organization   : {hb.get('organization') or '(not set)'}",
        f"Site ID        : {hb.get('site_id') or '(n/a)'}",
        f"Coverage score : {hb.get('coverage_score')}%",
        f"Events (24h)   : {hb.get('events_24h')}",
        f"Last event     : {hb.get('last_event_at') or 'none'}",
        "",
        "Controls",
        f"  SSH jail     : {'ON' if hb.get('ssh_jail') else 'OFF'}",
        f"  SMB decoys   : {'ON' if hb.get('smb') else 'OFF'}",
        f"  Beacons      : {'ON' if hb.get('beacon') else 'OFF'}",
        f"  Cloud decoy  : {'ON' if hb.get('cloud_decoy') else 'OFF'}",
        "",
        f"Mesh sites     : {mesh.get('site_count', 0)}",
        f"Mesh events24h : {mesh.get('total_events_24h', 0)}",
    ]
    gb = hb.get("guardrails") or {}
    cb = gb.get("circuit_breaker") or {}
    if cb.get("tripped"):
        lines.append(f"Circuit breaker: TRIPPED — {cb.get('reason')}")
    else:
        lines.append("Circuit breaker: OK")
    lines += [
        "",
        "Heartbeat written for Sentinel/portal consumption:",
        f"  {_heartbeat_path()}",
        "",
        "Your defenses are on duty — checkable fact, not a hope.",
    ]
    return "\n".join(lines)
