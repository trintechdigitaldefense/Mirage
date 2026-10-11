"""Breadcrumb trails — Feature 05.

Decoys point to each other. An attacker who takes the bait keeps taking
it — every hop is logged and the trail reveals their full playbook.

Each cross-reference carries an embedded trail token so Mirage knows
which hop the attacker came from.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mirage.trails")


def _trail_token(from_node: str, to_node: str) -> str:
    raw = f"{from_node}:{to_node}:{secrets.token_hex(4)}"
    return "TR" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


# Default topology: a short realistic chain attackers like to follow
DEFAULT_TOPOLOGY = [
    {
        "id": "share_finance",
        "label": "Finance share pointer",
        "relpath": "shares/README_Finance.txt",
        "points_to": ["nas_backup", "admin_creds"],
        "body": (
            "Finance network share mapping\n"
            "=============================\n"
            "Primary: \\\\fileserver\\Finance\n"
            "Backup archive: \\\\nas-backup\\Archives\\2024\n"
            "Credential store for scheduled jobs: see admin/passwords.txt\n"
            "Contact IT if the drive mapping fails.\n"
        ),
    },
    {
        "id": "nas_backup",
        "label": "NAS backup config",
        "relpath": "config/nas_backup.conf",
        "points_to": ["backup_server", "admin_creds"],
        "body": (
            "# NAS backup job definition\n"
            "host=nas-backup.internal\n"
            "share=Archives\n"
            "user=backup_svc\n"
            "# Full backup target documented in config/backup_server.txt\n"
            "schedule=02:00 daily\n"
        ),
    },
    {
        "id": "backup_server",
        "label": "Backup server notes",
        "relpath": "config/backup_server.txt",
        "points_to": ["admin_creds"],
        "body": (
            "Backup target host\n"
            "==================\n"
            "Hostname: backup-01.internal\n"
            "Service account credentials: admin/passwords.txt (backup user)\n"
            "Retention: 30 days\n"
            "Do not modify without change ticket.\n"
        ),
    },
    {
        "id": "admin_creds",
        "label": "Admin credential pointer",
        "relpath": "admin/passwords.txt",
        "points_to": [],
        "body": None,  # will be filled by canary factory / left as endpoint
    },
]


def build_trail_documents(
    org: str = "Company",
    topology: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Materialise a breadcrumb topology into decoy file definitions.

    Each document that points to another embeds a unique trail token.
    When the target is later touched, the token (if found in context)
    or the path graph lets us reconstruct the hop chain.
    """
    topo = topology or DEFAULT_TOPOLOGY
    nodes = {n["id"]: n for n in topo}
    docs: List[Dict[str, Any]] = []
    edges: List[Dict[str, str]] = []

    for node in topo:
        body = node.get("body")
        if body is None:
            # Endpoint node — skip generating content here; canary factory owns it
            continue

        # Inject trail tokens for each outbound link
        trail_lines = ["", "# Internal references (do not redistribute)"]
        for target_id in node.get("points_to", []):
            target = nodes.get(target_id)
            if not target:
                continue
            token = _trail_token(node["id"], target_id)
            edges.append({
                "from": node["id"],
                "to": target_id,
                "token": token,
                "from_path": node["relpath"],
                "to_path": target["relpath"],
            })
            trail_lines.append(
                f"# ref:{target_id} token:{token} path:{target['relpath']}"
            )

        content = body.rstrip() + "\n" + "\n".join(trail_lines) + "\n"
        # Light org branding
        content = content.replace("fileserver", f"{org.lower().replace(' ', '')}-files")
        content = content.replace("nas-backup", f"{org.lower().replace(' ', '')}-nas")

        docs.append({
            "name": f"trail_{node['id']}",
            "relpath": node["relpath"],
            "content": content,
            "trail_node": node["id"],
            "points_to": node.get("points_to", []),
        })

    # Persist edge map alongside (for status / reporting)
    meta = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "org": org,
        "edges": edges,
        "nodes": [{"id": n["id"], "path": n["relpath"]} for n in topo],
    }

    return docs, meta


def load_trail_meta(base_dir: Path) -> Dict[str, Any]:
    path = base_dir / ".mirage_trails.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_trail_meta(base_dir: Path, meta: Dict[str, Any]) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    path = base_dir / ".mirage_trails.json"
    path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def resolve_hop(meta: Dict[str, Any], touched_path: str, token: str = "") -> Dict[str, Any]:
    """Given a touched path or token, return hop context for the event."""
    edges = meta.get("edges") or []
    nodes = meta.get("nodes") or []

    # Match by token first
    if token:
        for e in edges:
            if e.get("token") == token:
                return {
                    "hop_from": e["from"],
                    "hop_to": e["to"],
                    "token": token,
                    "from_path": e.get("from_path"),
                    "to_path": e.get("to_path"),
                }

    # Match by path
    for n in nodes:
        if n.get("path") and (touched_path.endswith(n["path"]) or n["path"] in touched_path):
            inbound = [e for e in edges if e["to"] == n["id"]]
            outbound = [e for e in edges if e["from"] == n["id"]]
            return {
                "node": n["id"],
                "path": n["path"],
                "inbound_from": [e["from"] for e in inbound],
                "outbound_to": [e["to"] for e in outbound],
            }

    return {}
