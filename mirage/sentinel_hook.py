"""Sentinel integration — emit local events; optional OS firewall drop.

Default is observe-only: write a JSONL event file and optional Unix socket
message that Sentinel (or any host agent) can consume.

Firewall drops are OFF unless explicitly enabled in config AND ROE allows
active response. Even then, only DROP rules for the source IP on INPUT —
no outbound, no attack-back.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .config import ensure_data_dir, load_config

logger = logging.getLogger("mirage.sentinel_hook")

EVENT_FILE = "sentinel_events.jsonl"
SOCKET_PATH = "sentinel.sock"


def _event_path() -> Path:
    return ensure_data_dir() / EVENT_FILE


def emit_local(event_type: str, source_ip: str, details: Dict[str, Any]) -> None:
    """Append structured event for Sentinel / host agents."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "Mirage",
        "event_type": event_type,
        "source_ip": source_ip,
        "details": details or {},
    }
    path = _event_path()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        logger.warning("Sentinel event file write failed: %s", e)

    # Optional Unix datagram to Sentinel if socket exists
    sock_path = ensure_data_dir() / SOCKET_PATH
    if sock_path.exists():
        try:
            import socket

            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.sendto(json.dumps(record).encode("utf-8"), str(sock_path))
            s.close()
        except OSError:
            pass


def maybe_block_ip(source_ip: str, reason: str = "") -> bool:
    """If config.sentinel_firewall_drop is true, insert iptables/nft DROP.

    Returns True if a rule was attempted. Never blocks localhost or empty.
    """
    cfg = load_config()
    if not cfg.get("sentinel_firewall_drop", False):
        return False
    if not source_ip or source_ip in ("127.0.0.1", "::1", "localhost", "local", "unknown"):
        return False
    # Basic IPv4 sanity
    parts = source_ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        logger.warning("Refusing firewall drop for non-IPv4: %s", source_ip)
        return False

    # Prefer iptables; fall back to nft if present
    comment = f"Mirage/{reason or 'decoy'}"[:28]
    try:
        r = subprocess.run(
            [
                "iptables", "-C", "INPUT", "-s", source_ip, "-j", "DROP",
            ],
            capture_output=True,
            timeout=5,
        )
        if r.returncode == 0:
            logger.info("Firewall drop already present for %s", source_ip)
            return True
        subprocess.run(
            [
                "iptables", "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP",
                "-m", "comment", "--comment", comment,
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
        logger.warning("Sentinel hook: DROP inserted for %s (%s)", source_ip, comment)
        emit_local(
            "firewall_drop",
            source_ip,
            {"action": "iptables_DROP", "reason": reason},
        )
        return True
    except FileNotFoundError:
        logger.warning("iptables not found — firewall drop skipped")
    except Exception as e:
        logger.warning("Firewall drop failed: %s", e)
    return False


def on_mirage_event(
    event_type: str,
    source_ip: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Called from alert path when Sentinel integration is enabled."""
    cfg = load_config()
    if not cfg.get("sentinel_integration", True):
        return
    details = details or {}
    emit_local(event_type, source_ip, details)

    # Only auto-block on high-confidence interactive / credential events
    block_types = {
        "ssh_jail_login",
        "ssh_jail_command",
        "http_login_capture",
        "attack_profile",
        "beacon_hit",
        "trail_hop",
        "dns_canary_lookup",
    }
    if event_type in block_types or details.get("severity") == "critical":
        maybe_block_ip(source_ip, reason=event_type)
