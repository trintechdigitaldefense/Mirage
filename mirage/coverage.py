"""Coverage heatmap — Feature 09.

Shows which ports, decoy types and roles are deployed vs remaining gaps.
Turns deployment quality into something visible at renewal time.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .config import load_config


# Recommended baseline for Caribbean SMB deployments
RECOMMENDED = {
    "services": {
        "ssh": {"port_key": "ssh", "label": "SSH / SSH jail", "priority": "critical"},
        "http": {"port_key": "http", "label": "HTTP admin decoy", "priority": "high"},
        "https": {"port_key": "https", "label": "HTTPS admin decoy", "priority": "medium"},
        "mysql": {"port_key": "mysql", "label": "MySQL decoy", "priority": "high"},
        "ftp": {"port_key": "ftp", "label": "FTP decoy", "priority": "medium"},
        "rdp": {"port_key": "rdp", "label": "RDP decoy", "priority": "high"},
    },
    "features": {
        "ssh_jail": {"cfg": "ssh_jail_enabled", "label": "SSH credential jail", "priority": "critical"},
        "smb": {"cfg": "smb_enabled", "label": "Decoy SMB shares", "priority": "high"},
        "beacon": {"cfg": "beacon_enabled", "label": "Beaconing honey tokens", "priority": "high"},
        "canaries": {"cfg": None, "label": "Canary / decoy files", "priority": "critical", "always": True},
        "trails": {"cfg": None, "label": "Breadcrumb trails", "priority": "medium", "always": True},
        "guardrails": {"cfg": "guardrails_enabled", "label": "Anti-abuse guardrails", "priority": "critical"},
    },
}


def compute_coverage(cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    cfg = cfg or load_config()
    ports = cfg.get("ports") or {}

    service_rows = []
    for key, meta in RECOMMENDED["services"].items():
        deployed = key in ports and ports.get(key)
        service_rows.append({
            "id": key,
            "label": meta["label"],
            "priority": meta["priority"],
            "deployed": bool(deployed),
            "port": ports.get(key) if deployed else None,
        })

    feature_rows = []
    for key, meta in RECOMMENDED["features"].items():
        if meta.get("always"):
            deployed = True
        else:
            deployed = bool(cfg.get(meta["cfg"], True if meta["cfg"] else False))
        feature_rows.append({
            "id": key,
            "label": meta["label"],
            "priority": meta["priority"],
            "deployed": deployed,
        })

    gaps = [r for r in service_rows + feature_rows if not r["deployed"]]
    # Sort gaps by priority
    prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda r: prio_order.get(r["priority"], 9))

    total = len(service_rows) + len(feature_rows)
    covered = sum(1 for r in service_rows + feature_rows if r["deployed"])
    score = int(round(100 * covered / total)) if total else 0

    suggestions = []
    for g in gaps:
        if g["id"] in RECOMMENDED["services"]:
            suggestions.append(
                f"Enable {g['label']} — add to ports in config or ensure key '{g['id']}' is present."
            )
        else:
            cfg_key = RECOMMENDED["features"].get(g["id"], {}).get("cfg")
            if cfg_key:
                suggestions.append(f"Set {cfg_key}=true to enable {g['label']}.")
            else:
                suggestions.append(f"Deploy {g['label']}.")

    return {
        "organization": cfg.get("organization_name") or "",
        "score": score,
        "covered": covered,
        "total": total,
        "services": service_rows,
        "features": feature_rows,
        "gaps": gaps,
        "suggestions": suggestions,
        "smb_port": cfg.get("smb_port"),
        "smb_shares": cfg.get("smb_shares") or [],
        "listen_address": cfg.get("listen_address"),
    }


def render_coverage_text(cov: Dict[str, Any] = None) -> str:
    cov = cov or compute_coverage()
    lines = [
        "Mirage Coverage Heatmap",
        "=" * 50,
        f"Organization : {cov.get('organization') or '(not set)'}",
        f"Coverage     : {cov['score']}%  ({cov['covered']}/{cov['total']} controls)",
        f"Listen       : {cov.get('listen_address')}",
        "",
        "Services",
        "-" * 50,
    ]
    for s in cov["services"]:
        mark = "[x]" if s["deployed"] else "[ ]"
        port = f":{s['port']}" if s.get("port") else ""
        lines.append(f"  {mark} {s['label']:<28} {s['priority']:<8} {port}")

    lines += ["", "Features", "-" * 50]
    for f in cov["features"]:
        mark = "[x]" if f["deployed"] else "[ ]"
        lines.append(f"  {mark} {f['label']:<28} {f['priority']}")

    if cov.get("smb_shares"):
        lines += ["", f"SMB shares : {', '.join(cov['smb_shares'])} (port {cov.get('smb_port')})"]

    if cov["gaps"]:
        lines += ["", "Blind spots / suggested decoys", "-" * 50]
        for i, s in enumerate(cov["suggestions"], 1):
            lines.append(f"  {i}. {s}")
    else:
        lines += ["", "No critical blind spots detected for the standard baseline."]

    lines += ["", "Honest coverage builds trust and expands contracts."]
    return "\n".join(lines)
