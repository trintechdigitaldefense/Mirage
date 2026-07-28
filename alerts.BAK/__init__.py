"""Mirage alerts — multiple output channels."""

import json
import logging
import smtplib
import subprocess
import time
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("mirage.alerts")

ALERT_LOG = Path("/tmp/mirage_alerts.json")


def _ensure_log():
    if not ALERT_LOG.exists():
        ALERT_LOG.write_text("[]\n")


def _read_alerts() -> list:
    _ensure_log()
    try:
        return json.loads(ALERT_LOG.read_text())
    except (json.JSONDecodeError, ValueError):
        return []


def _write_alerts(alerts: list):
    ALERT_LOG.write_text(json.dumps(alerts, indent=2))


def log_event(event_type: str, data: dict):
    """Log an alert to the persistent JSON log."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": event_type,
        "data": data,
    }
    alerts = _read_alerts()
    alerts.append(entry)
    _write_alerts(alerts)
    logger.warning("Alert logged: %s %s", event_type, data)

    # Also write to stdout in a parseable format
    msg = json.dumps(entry)
    print(f"[MIRAGE_ALERT] {msg}")

    return entry


def get_recent(count: int = 10) -> list:
    """Return the most recent alerts."""
    alerts = _read_alerts()
    return alerts[-count:]


def get_all() -> list:
    return _read_alerts()


def clear():
    _write_alerts([])
    logger.info("All alerts cleared")


# ─── Send Alert via WhatsApp (via WhatsApp Web link) ──────────────

def send_whatsapp_alert(alert_msg: str, phone_number: str = ""):
    """Send alert by opening a WhatsApp link (works on desktop/phone)."""
    import urllib.parse
    if phone_number:
        url = f"https://wa.me/{phone_number}?text={urllib.parse.quote(alert_msg)}"
    else:
        url = f"https://web.whatsapp.com/send?text={urllib.parse.quote(alert_msg)}"
    logger.info("WhatsApp alert URL: %s", url)
    return url


# ─── Send Alert via Email ─────────────────────────────────────────

def send_email_alert(
    alert_msg: str,
    smtp_server: str = "",
    smtp_port: int = 587,
    sender: str = "",
    password: str = "",
    recipient: str = "",
):
    """Send email alert via SMTP."""
    if not all([smtp_server, sender, password, recipient]):
        logger.warning("Email alert skipped — missing credentials")
        return False
    try:
        msg = MIMEText(alert_msg)
        msg["Subject"] = "[MIRAGE] Deception Alert"
        msg["From"] = sender
        msg["To"] = recipient
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
        logger.info("Email alert sent to %s", recipient)
        return True
    except Exception as e:
        logger.error("Email alert failed: %s", e)
        return False


# ─── Command-line helper ──────────────────────────────────────────

def print_recent():
    alerts = get_recent()
    if not alerts:
        print("No alerts yet.")
        return
    for a in alerts:
        print(f"[{a['timestamp']}] {a['type']}: {json.dumps(a['data'])}")
