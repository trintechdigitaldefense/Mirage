"""Alerting for Mirage deception events."""

import json
import logging
from typing import Dict, Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

import requests

from .config import load_config
from .db import log_event, is_in_cooldown, set_cooldown

logger = logging.getLogger("mirage.alerts")


def emit(event_type: str, source_ip: str = "",
         details: Dict[str, Any] = None, severity: str = "high") -> None:
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref", "")
    details = details or {}

    # Cooldown key
    key = f"{event_type}:{source_ip}:{details.get('service', details.get('canary', ''))}"
    cooldown = int(cfg.get("alert_cooldown_seconds", 300))
    if is_in_cooldown(key, cooldown):
        return

    log_event(event_type, source_ip, details, severity, auth_ref)
    set_cooldown(key)

    # Human message
    if "canary" in event_type:
        msg = f"Canary '{details.get('canary')}' was {event_type.split('_')[-1]}"
    else:
        svc = details.get("service", "unknown")
        msg = f"Attacker interaction with fake {svc.upper()} service from {source_ip or 'unknown'}"

    # Console
    if cfg.get("enable_console_alerts", True):
        if RICH:
            console.print(Panel(
                f"[bold red]{msg}[/bold red]\n"
                f"Type: {event_type}\n"
                f"Source: {source_ip or 'n/a'}\n"
                f"Details: {json.dumps(details)[:120]}",
                title="MIRAGE ALERT",
                border_style="red",
            ))
        else:
            print(f"\n!!! MIRAGE ALERT: {msg}")
            print(f"    Type: {event_type} | Source: {source_ip}")

    # Webhook
    webhook = cfg.get("webhook_url")
    if webhook:
        try:
            payload = {
                "source": "Mirage",
                "version": "2.0.0",
                "event_type": event_type,
                "source_ip": source_ip,
                "message": msg,
                "details": details,
                "authorization_ref": auth_ref,
            }
            requests.post(webhook, json=payload, timeout=8)
        except Exception as e:
            logger.warning("Webhook failed: %s", e)
