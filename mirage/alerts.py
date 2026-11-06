"""Alert emission — redacted, enriched with session/event ids, token lifecycle."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from .config import load_config
from .db import log_event, is_in_cooldown, set_cooldown
from .redaction import redact_details, contains_secret
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
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref") or ""

    # Session + schema enrichment before redaction
    details = enrich_event_fields(event_type, source_ip, details or {})

    # Honeytoken lifecycle
    if event_type == "beacon_hit":
        tid = (details.get("token_id") or "").strip()
        if tid:
            record_hit(tid, source_ip=source_ip, path=details.get("path") or "")

    # Guardrail rate check for logging path
    if cfg.get("guardrails_enabled", True):
        ok, reason = guardrails.check_source(source_ip or "unknown")
        if not ok and reason == "circuit_open":
            logger.warning("Alert suppressed — circuit open (%s)", source_ip)
            return

    safe = redact_details(details)
    # Cooldown per event_type+source
    cd_key = f"{event_type}:{source_ip}"
    cd_sec = int(cfg.get("alert_cooldown_sec") or 30)
    if cd_sec > 0 and is_in_cooldown(cd_key, cd_sec):
        logger.debug("Cooldown in cooldown: %s", cd_key)
    else:
        if cd_sec > 0:
            set_cooldown(cd_key)

    log_event(
        event_type=event_type,
        source_ip=source_ip,
        details=safe,
        severity=severity,
        authorization_ref=auth_ref,
    )

    # Console
    channel = (cfg.get("alert_channel") or "console").lower()
    line = f"[MIRAGE] {event_type} src={source_ip or 'n/a'} sev={severity}"
    if channel in ("console", "both"):
        print(line)

    # Webhook — never send unredacted secrets
    if channel in ("webhook", "both") and cfg.get("webhook_url"):
        _post_webhook(cfg["webhook_url"], event_type, source_ip, safe, severity)

    # SIEM stream
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
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning("Webhook failed (non-fatal): %s", e)


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
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except Exception as e:
        logger.debug("SIEM append failed: %s", e)
