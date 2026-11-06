"""Alerting for Mirage deception events — secrets redacted before any output."""

import json
import logging
from typing import Any, Dict

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
from .redaction import redact_details
from . import guardrails

logger = logging.getLogger("mirage.alerts")


def emit(event_type: str, source_ip: str = "",
         details: Dict[str, Any] = None, severity: str = "high") -> None:
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref", "")
    raw = details or {}
    # Central redaction — nothing downstream sees plaintext secrets
    safe = redact_details(raw)

    if cfg.get("guardrails_enabled", True):
        allowed, reason = guardrails.check_source(source_ip or "unknown")
        if not allowed:
            logger.warning("Guardrail blocked alert %s from %s: %s", event_type, source_ip, reason)
            if "circuit" in reason.lower() or reason.startswith("Circuit"):
                log_event(
                    "guardrail_circuit_open",
                    source_ip,
                    {"reason": reason, "blocked_event": event_type},
                    severity="critical",
                    authorization_ref=auth_ref,
                )
            return

    key = f"{event_type}:{source_ip}:{safe.get('service', safe.get('canary', safe.get('path', '')))}"
    cooldown = int(cfg.get("alert_cooldown_seconds", 300))
    if is_in_cooldown(key, cooldown):
        return

    log_event(event_type, source_ip, safe, severity, auth_ref)
    set_cooldown(key)

    mitre_payload = None
    if cfg.get("mitre_siem_stream", True):
        try:
            from .mitre_mapper import stream_siem

            mitre_payload = stream_siem(event_type, source_ip, safe)
        except Exception as e:
            logger.debug("MITRE stream skip: %s", e)

    if cfg.get("profiler_enabled", True) and event_type != "attack_profile":
        try:
            from . import profiler

            def _profile_emit(et, sip, det):
                emit(et, sip, det, severity=det.get("severity", "high"))

            profiler.record(event_type, source_ip, safe, on_profile=_profile_emit)
        except Exception as e:
            logger.debug("Profiler skip: %s", e)

    if cfg.get("sentinel_integration", True):
        try:
            from .sentinel_hook import on_mirage_event

            on_mirage_event(event_type, source_ip, safe)
        except Exception as e:
            logger.debug("Sentinel hook skip: %s", e)

    if "canary" in event_type:
        msg = f"Canary '{safe.get('canary')}' was {event_type.split('_')[-1]}"
    elif event_type == "dns_canary_lookup":
        msg = f"DNS canary lookup '{safe.get('qname')}' from {source_ip}"
    elif event_type == "tarpit_hold":
        msg = f"Scanner held in tarpit on port {safe.get('port')} from {source_ip}"
    elif event_type == "web_api_hit":
        msg = f"Web API decoy {safe.get('method')} {safe.get('path')} from {source_ip}"
    elif event_type == "attack_profile":
        msg = f"Profile {safe.get('profile')}: {safe.get('summary', '')}"
    elif event_type == "http_login_capture":
        msg = f"Credentials submitted to decoy admin portal from {source_ip} (secrets redacted)"
    elif event_type.startswith("telnet_jail"):
        if event_type == "telnet_jail_command":
            msg = f"Telnet jail command from {source_ip}: {safe.get('command', '')!r}"
        elif event_type == "telnet_jail_login":
            msg = f"Telnet jail login as {safe.get('username', '?')} from {source_ip}"
        else:
            msg = f"Telnet jail ({event_type}) from {source_ip or 'unknown'}"
    elif event_type.startswith("ssh_jail"):
        if event_type == "ssh_jail_command":
            msg = f"SSH jail command from {source_ip}: {safe.get('command', '')!r}"
        elif event_type == "ssh_jail_login":
            msg = f"SSH jail login as {safe.get('username', '?')} from {source_ip} (password redacted)"
        else:
            msg = f"SSH jail event ({event_type}) from {source_ip or 'unknown'}"
    else:
        svc = safe.get("service", "unknown")
        msg = f"Attacker interaction with fake {str(svc).upper()} service from {source_ip or 'unknown'}"

    if cfg.get("enable_console_alerts", True):
        extra = ""
        if mitre_payload and mitre_payload.get("technique_ids"):
            extra = f"\nMITRE: {', '.join(mitre_payload['technique_ids'])}"
        detail_preview = json.dumps(safe)[:120]
        if RICH:
            console.print(Panel(
                f"[bold red]{msg}[/bold red]\n"
                f"Type: {event_type}\n"
                f"Source: {source_ip or 'n/a'}\n"
                f"Details: {detail_preview}{extra}",
                title="MIRAGE ALERT",
                border_style="red",
            ))
        else:
            print(f"\n!!! MIRAGE ALERT: {msg}")
            print(f"    Type: {event_type} | Source: {source_ip}{extra}")

    webhook = cfg.get("webhook_url")
    if webhook:
        try:
            payload = {
                "source": "Mirage",
                "version": "2.5.0",
                "event_type": event_type,
                "source_ip": source_ip,
                "message": msg,
                "details": safe,
                "authorization_ref": auth_ref,
                "mitre": mitre_payload,
            }
            requests.post(webhook, json=payload, timeout=8)
        except Exception as e:
            logger.warning("Webhook failed: %s", e)
