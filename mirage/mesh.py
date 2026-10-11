"""Multi-site deception mesh — Feature 04.

One operator view across every client deployment: which sites have active
decoys, interaction counts, quietest and noisiest traps. Franchises and
multi-branch clients get a single group report covering all locations.

Sites self-register into a local registry JSON (or a shared path). A
central TrinTech-side aggregator can collect these nightly summaries.
"""

from __future__ import annotations

import json
import socket
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir, load_config
from .db import get_recent_events
from .coverage import compute_coverage


def _registry_path() -> Path:
    return ensure_data_dir() / "mesh_registry.json"


def _load_registry() -> Dict[str, Any]:
    path = _registry_path()
    if not path.exists():
        return {"sites": {}, "updated": None}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"sites": {}, "updated": None}


def _save_registry(reg: Dict[str, Any]) -> None:
    reg["updated"] = datetime.utcnow().isoformat() + "Z"
    path = _registry_path()
    path.write_text(json.dumps(reg, indent=2), encoding="utf-8")


def _site_id(cfg: Dict[str, Any]) -> str:
    existing = cfg.get("site_id")
    if existing:
        return existing
    # Stable-ish id from org + hostname
    host = socket.gethostname()
    org = cfg.get("organization_name") or "site"
    raw = f"{org}:{host}".lower()
    return "site-" + uuid.uuid5(uuid.NAMESPACE_DNS, raw).hex[:12]


def register_site(extra: Dict[str, Any] = None) -> Dict[str, Any]:
    """Register / refresh this host in the mesh registry."""
    cfg = load_config()
    sid = _site_id(cfg)
    # Persist site_id back into config if new
    if not cfg.get("site_id"):
        cfg["site_id"] = sid
        from .config import save_config
        save_config(cfg)

    events_24h = get_recent_events(hours=24)
    cov = compute_coverage(cfg)

    record = {
        "site_id": sid,
        "organization": cfg.get("organization_name") or "",
        "hostname": socket.gethostname(),
        "listen_address": cfg.get("listen_address"),
        "sector": cfg.get("sector") or "general",
        "authorization_ref": cfg.get("authorization_ref") or "",
        "last_seen": datetime.utcnow().isoformat() + "Z",
        "events_24h": len(events_24h),
        "coverage_score": cov["score"],
        "ssh_jail": bool(cfg.get("ssh_jail_enabled", True)),
        "smb": bool(cfg.get("smb_enabled", True)),
        "beacon": bool(cfg.get("beacon_enabled", True)),
        "ports": cfg.get("ports") or {},
    }
    if extra:
        record.update(extra)

    reg = _load_registry()
    reg.setdefault("sites", {})[sid] = record
    _save_registry(reg)
    return record


def list_sites() -> List[Dict[str, Any]]:
    reg = _load_registry()
    sites = list((reg.get("sites") or {}).values())
    sites.sort(key=lambda s: s.get("last_seen") or "", reverse=True)
    return sites


def mesh_summary() -> Dict[str, Any]:
    sites = list_sites()
    if not sites:
        return {
            "site_count": 0,
            "total_events_24h": 0,
            "sites": [],
            "noisiest": None,
            "quietest": None,
        }

    total_events = sum(int(s.get("events_24h") or 0) for s in sites)
    by_noise = sorted(sites, key=lambda s: int(s.get("events_24h") or 0), reverse=True)

    return {
        "site_count": len(sites),
        "total_events_24h": total_events,
        "sites": sites,
        "noisiest": by_noise[0] if by_noise else None,
        "quietest": by_noise[-1] if by_noise else None,
        "registry_updated": _load_registry().get("updated"),
    }


def render_mesh_text() -> str:
    summary = mesh_summary()
    lines = [
        "Mirage Multi-Site Mesh",
        "=" * 50,
        f"Sites registered : {summary['site_count']}",
        f"Events (24h)     : {summary['total_events_24h']}",
        f"Registry updated : {summary.get('registry_updated') or 'n/a'}",
        "",
    ]
    if not summary["sites"]:
        lines.append("No sites registered yet. Run 'mirage deploy' or 'mirage mesh register'.")
        return "\n".join(lines)

    lines.append(f"{'Site ID':<18} {'Org':<20} {'Host':<16} {'24h':>5} {'Cov':>4}")
    lines.append("-" * 70)
    for s in summary["sites"]:
        lines.append(
            f"{s.get('site_id',''):<18} "
            f"{(s.get('organization') or '')[:20]:<20} "
            f"{(s.get('hostname') or '')[:16]:<16} "
            f"{int(s.get('events_24h') or 0):>5} "
            f"{int(s.get('coverage_score') or 0):>3}%"
        )

    if summary.get("noisiest"):
        n = summary["noisiest"]
        lines += [
            "",
            f"Noisiest : {n.get('site_id')} ({n.get('events_24h')} events)",
            f"Quietest : {summary['quietest'].get('site_id')} "
            f"({summary['quietest'].get('events_24h')} events)",
        ]
    return "\n".join(lines)


def group_report_text() -> str:
    """Client-facing group report across all registered sites."""
    summary = mesh_summary()
    cfg = load_config()
    org = cfg.get("organization_name") or "Client Group"
    lines = [
        f"# Multi-Site Deception Summary — {org}",
        f"**Prepared by:** TrinTech Digital Defense",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        f"**Sites covered:** {summary['site_count']}",
        "",
        "---",
        "",
        "## Overview",
        f"Total deception events across all sites in the last 24 hours: "
        f"**{summary['total_events_24h']}**.",
        "",
    ]
    if not summary["sites"]:
        lines.append("No branch sites have registered yet.")
        return "\n".join(lines)

    lines.append("## Per-site status")
    lines.append("")
    for s in summary["sites"]:
        lines.append(
            f"- **{s.get('organization') or s.get('site_id')}** "
            f"(`{s.get('hostname')}`) — "
            f"{s.get('events_24h', 0)} events, coverage {s.get('coverage_score', 0)}%"
        )
    lines += [
        "",
        "---",
        "",
        "*Mirage multi-site mesh · TrinTech Digital Defense*",
    ]
    return "\n".join(lines)
