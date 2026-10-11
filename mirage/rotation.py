"""Decoy realism rotation — Feature 11.

Decoys that never change become fingerprintable. Monthly (or on-demand)
rotation of service banners, hostnames, and cosmetic attributes keeps the
grid believable. Tokens and logging stay continuous; only cosmetics move.
"""

from __future__ import annotations

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .config import ensure_data_dir, load_config, save_config

SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n",
    b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-1ubuntu3\r\n",
    b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4\r\n",
]

HTTP_SERVERS = [
    "Apache/2.4.52 (Ubuntu)",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "Microsoft-IIS/10.0",
]

HOSTNAMES = [
    "prod-app-01", "app-server-02", "web-internal-01",
    "files-01", "backup-host", "db-util-01",
]

FTP_BANNERS = [
    b"220 Welcome to FTP Server (vsFTPd 3.0.5)\r\n",
    b"220 (vsFTPd 3.0.3)\r\n",
    b"220 Microsoft FTP Service\r\n",
]


def _history_path() -> Path:
    return ensure_data_dir() / "rotation_history.json"


def _load_history() -> List[Dict[str, Any]]:
    path = _history_path()
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_history(entries: List[Dict[str, Any]]) -> None:
    # Keep last 24 rotations
    _history_path().write_text(
        json.dumps(entries[-24:], indent=2),
        encoding="utf-8",
    )


def current_cosmetics() -> Dict[str, Any]:
    cfg = load_config()
    return cfg.get("cosmetics") or {
        "ssh_banner_idx": 0,
        "http_server_idx": 0,
        "ftp_banner_idx": 0,
        "hostname_idx": 0,
        "last_rotated": None,
    }


def rotate(force: bool = False) -> Dict[str, Any]:
    """Re-roll cosmetic attributes and persist to config + history."""
    cfg = load_config()
    cos = current_cosmetics()

    new_cos = {
        "ssh_banner_idx": random.randrange(len(SSH_BANNERS)),
        "http_server_idx": random.randrange(len(HTTP_SERVERS)),
        "ftp_banner_idx": random.randrange(len(FTP_BANNERS)),
        "hostname_idx": random.randrange(len(HOSTNAMES)),
        "last_rotated": datetime.utcnow().isoformat() + "Z",
        "forced": force,
    }

    cfg["cosmetics"] = new_cos
    save_config(cfg)

    entry = {
        "at": new_cos["last_rotated"],
        "previous": cos,
        "current": new_cos,
        "ssh_banner": SSH_BANNERS[new_cos["ssh_banner_idx"]].decode("utf-8", errors="replace").strip(),
        "http_server": HTTP_SERVERS[new_cos["http_server_idx"]],
        "hostname": HOSTNAMES[new_cos["hostname_idx"]],
    }
    hist = _load_history()
    hist.append(entry)
    _save_history(hist)
    return entry


def get_ssh_banner() -> bytes:
    cos = current_cosmetics()
    idx = int(cos.get("ssh_banner_idx") or 0) % len(SSH_BANNERS)
    return SSH_BANNERS[idx]


def get_http_server() -> str:
    cos = current_cosmetics()
    idx = int(cos.get("http_server_idx") or 0) % len(HTTP_SERVERS)
    return HTTP_SERVERS[idx]


def get_ftp_banner() -> bytes:
    cos = current_cosmetics()
    idx = int(cos.get("ftp_banner_idx") or 0) % len(FTP_BANNERS)
    return FTP_BANNERS[idx]


def get_hostname() -> str:
    cos = current_cosmetics()
    idx = int(cos.get("hostname_idx") or 0) % len(HOSTNAMES)
    return HOSTNAMES[idx]


def render_rotation_status() -> str:
    cos = current_cosmetics()
    hist = _load_history()
    lines = [
        "Mirage Realism Rotation",
        "=" * 50,
        f"Last rotated : {cos.get('last_rotated') or 'never'}",
        f"SSH banner   : {get_ssh_banner().decode('utf-8', errors='replace').strip()}",
        f"HTTP Server  : {get_http_server()}",
        f"FTP banner   : {get_ftp_banner().decode('utf-8', errors='replace').strip()}",
        f"Hostname     : {get_hostname()}",
        f"History entries: {len(hist)}",
        "",
        "Run: mirage rotate   to re-roll cosmetics now.",
        "Tokens and event logging are not affected by rotation.",
    ]
    return "\n".join(lines)
