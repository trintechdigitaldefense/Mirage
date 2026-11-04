"""Dynamic banner mutator — Feature 11 + v2.3 OS/service spoofing.

Rotate synthetic service banners (IIS, Cisco IOS, Apache, legacy Windows SMB)
on timer or per connection to confuse Nmap/Masscan/Shodan fingerprints.
"""

from __future__ import annotations

import json
import random
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .config import ensure_data_dir, load_config, save_config

SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n",
    b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-1ubuntu3\r\n",
    b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4\r\n",
    b"SSH-2.0-Cisco-1.25\r\n",
    b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n",
    b"SSH-2.0-dropbear_2020.81\r\n",
]

HTTP_SERVERS = [
    "Apache/2.4.52 (Ubuntu)",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "Microsoft-IIS/10.0",
    "Microsoft-IIS/8.5",
    "Apache/2.4.29 (Win64)",
    "nginx/1.14.2",
    "cloudflare",
]

HOSTNAMES = [
    "prod-app-01", "app-server-02", "web-internal-01",
    "files-01", "backup-host", "db-util-01",
    "WIN-SRV2012R2", "CISCO-CORE-01", "EXCH-MBX-02",
]

FTP_BANNERS = [
    b"220 Welcome to FTP Server (vsFTPd 3.0.5)\r\n",
    b"220 (vsFTPd 3.0.3)\r\n",
    b"220 Microsoft FTP Service\r\n",
    b"220 ProFTPD 1.3.5e Server ready.\r\n",
]

SMB_DIALECTS = [
    "Windows Server 2012 R2 Standard 9600",
    "Windows Server 2016 Standard 14393",
    "Windows 10 Enterprise 19041",
    "Samba 4.15.13-Ubuntu",
]

MYSQL_VERSIONS = ["8.0.36", "5.7.42", "8.0.28-0ubuntu0.20.04.3"]
REDIS_VERSIONS = ["7.0.12", "6.2.6", "5.0.14"]
POSTGRES_VERSIONS = ["14.9", "13.12", "12.16"]

_per_conn_lock = threading.Lock()


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
    _history_path().write_text(json.dumps(entries[-24:], indent=2), encoding="utf-8")


def current_cosmetics() -> Dict[str, Any]:
    cfg = load_config()
    return cfg.get("cosmetics") or {
        "ssh_banner_idx": 0,
        "http_server_idx": 0,
        "ftp_banner_idx": 0,
        "hostname_idx": 0,
        "smb_idx": 0,
        "last_rotated": None,
        "per_connection": False,
    }


def rotate(force: bool = False) -> Dict[str, Any]:
    cfg = load_config()
    cos = current_cosmetics()
    new_cos = {
        "ssh_banner_idx": random.randrange(len(SSH_BANNERS)),
        "http_server_idx": random.randrange(len(HTTP_SERVERS)),
        "ftp_banner_idx": random.randrange(len(FTP_BANNERS)),
        "hostname_idx": random.randrange(len(HOSTNAMES)),
        "smb_idx": random.randrange(len(SMB_DIALECTS)),
        "last_rotated": datetime.utcnow().isoformat() + "Z",
        "forced": force,
        "per_connection": bool(cos.get("per_connection") or cfg.get("banner_per_connection", False)),
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
        "smb_dialect": SMB_DIALECTS[new_cos["smb_idx"]],
    }
    hist = _load_history()
    hist.append(entry)
    _save_history(hist)
    return entry


def get_ssh_banner() -> bytes:
    cos = current_cosmetics()
    if cos.get("per_connection") or load_config().get("banner_per_connection"):
        return random.choice(SSH_BANNERS)
    idx = int(cos.get("ssh_banner_idx") or 0) % len(SSH_BANNERS)
    return SSH_BANNERS[idx]


def get_http_server() -> str:
    cos = current_cosmetics()
    if cos.get("per_connection") or load_config().get("banner_per_connection"):
        return random.choice(HTTP_SERVERS)
    idx = int(cos.get("http_server_idx") or 0) % len(HTTP_SERVERS)
    return HTTP_SERVERS[idx]


def get_ftp_banner() -> bytes:
    cos = current_cosmetics()
    if cos.get("per_connection") or load_config().get("banner_per_connection"):
        return random.choice(FTP_BANNERS)
    idx = int(cos.get("ftp_banner_idx") or 0) % len(FTP_BANNERS)
    return FTP_BANNERS[idx]


def get_hostname() -> str:
    cos = current_cosmetics()
    idx = int(cos.get("hostname_idx") or 0) % len(HOSTNAMES)
    return HOSTNAMES[idx]


def get_smb_dialect() -> str:
    cos = current_cosmetics()
    idx = int(cos.get("smb_idx") or 0) % len(SMB_DIALECTS)
    return SMB_DIALECTS[idx]


def get_mysql_version() -> str:
    return random.choice(MYSQL_VERSIONS)


def get_redis_version() -> str:
    return random.choice(REDIS_VERSIONS)


def get_postgres_version() -> str:
    return random.choice(POSTGRES_VERSIONS)


def render_rotation_status() -> str:
    cos = current_cosmetics()
    hist = _load_history()
    lines = [
        "Mirage Dynamic Banner Mutator",
        "=" * 50,
        f"Last rotated     : {cos.get('last_rotated') or 'never'}",
        f"Per-connection   : {bool(cos.get('per_connection') or load_config().get('banner_per_connection'))}",
        f"SSH banner       : {get_ssh_banner().decode('utf-8', errors='replace').strip()}",
        f"HTTP Server      : {get_http_server()}",
        f"FTP banner       : {get_ftp_banner().decode('utf-8', errors='replace').strip()}",
        f"SMB dialect      : {get_smb_dialect()}",
        f"Hostname         : {get_hostname()}",
        f"History entries  : {len(hist)}",
        "",
        "Run: mirage rotate   to re-roll cosmetics now.",
        "Set banner_per_connection=true in config for per-scan mutation.",
    ]
    return "\n".join(lines)
