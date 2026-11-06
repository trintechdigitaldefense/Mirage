"""Alert emission with redaction, durable event logging and notification cooldowns."""

from __future__ import annotations

import json
import logging
from typing import Optional

from .config import load_config
from .db import log_event, is_in_cooldown, set_cooldown
from .redaction import redact_details
from .sessions import enrich_event_fields
from .tokens import record_hit
from . import guardrails

logger = logging.getLogger("mirage.alerts")


def emit(
    event_type: str,
    source_ip: str = "",
    details: Optional[dict] = None,
    severity: str = "high",
) -> None:
    """Persist every event; cooldowns affect notifications, never the audit stream."""
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref") or ""

    enriched = enrich_event_fields(event_type, source_ip, details or {})

    # Record beacon lifecycle independently of notification delivery.
    if event_type == "beacon_hit":
        token_id = (enriched.get("token_id") or "").strip()
        if token_id:
            record_hit(
                token_id,
                source_ip=source_ip,
                path=enriched.get("path") or "",
            )

    # A tripped breaker suppresses operator notifications, not event evidence.
    breaker_open = False
    if cfg.get("guardrails_enabled", True):
        try:
            allowed, reason = guardrails.check_source(source_ip or "unknown")
            breaker_open = not allowed and reason == "circuit_open"
        except Exception:
            logger.exception("Guardrail alert check failed")

    safe = redact_details(enriched)

    # Persist before any best-effort external notification.
    log_event(
        event_type=event_type,
        source_ip=source_ip,
        details=safe,
        severity=severity,
        authorization_ref=auth_ref,
    )

    cooldown_key = f"{event_type}:{source_ip}"
    cooldown_seconds = int(
        cfg.get("alert_cooldown_seconds", cfg.get("alert_cooldown_sec", 30)) or 0
    )
    cooldown_active = False
    if cooldown_seconds > 0:
        cooldown_active = is_in_cooldown(cooldown_key, cooldown_seconds)
        if not cooldown_active:
            set_cooldown(cooldown_key)

    notifications_allowed = not cooldown_active and not breaker_open
    if cooldown_active:
        logger.debug("Operator notification cooldown active: %s", cooldown_key)
    if breaker_open:
        logger.warning("Operator notification suppressed — circuit open (%s)", source_ip)

    channel = (cfg.get("alert_channel") or "console").lower()
    line = f"[MIRAGE] {event_type} src={source_ip or 'n/a'} sev={severity}"

    if notifications_allowed and channel in ("console", "both"):
        print(line)

    if (
        notifications_allowed
        and channel in ("webhook", "both")
        and cfg.get("webhook_url")
    ):
        _post_webhook(cfg["webhook_url"], event_type, source_ip, safe, severity)

    # SIEM is an audit/integration stream: it receives every redacted event.
    if cfg.get("mitre_siem_stream", True):
        _append_siem(event_type, source_ip, safe, severity)


def _post_webhook(url: str, event_type: str, source_ip: str, details: dict, severity: str):
    try:
        import urllib.request

        body = json.dumps(
            {
                "event_type": event_type,
                "source_ip": source_ip,
                "severity": severity,
                "details": details,
                "note": "Mirage passive deception — secrets redacted",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            response.read()
    except Exception as exc:
        logger.warning("Webhook failed (non-fatal): %s", exc)


def _append_siem(event_type: str, source_ip: str, details: dict, severity: str):
    try:
        from .config import ensure_data_dir

        path = ensure_data_dir() / "siem_events.jsonl"
        row = {
            "event_type": event_type,
            "source_ip": source_ip,
            "severity": severity,
            "details": details,
        }
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, default=str) + "\n")
    except Exception as exc:
        logger.warning("SIEM append failed (non-fatal): %s", exc)
