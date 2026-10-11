"""Beaconing honey tokens — Feature 07.

Deployable AWS-style keys, Azure tokens and API secrets that phone home
when used ANYWHERE (including outside the client network).

Tokens embed a unique ID. Hits on the configured beacon endpoint (or
webhook) fire an alert with source IP, geography hint, and timestamp.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import string
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("mirage.beacons")


def _token_id(prefix: str = "MIR") -> str:
    raw = secrets.token_hex(8)
    return f"{prefix}-{raw[:8].upper()}-{raw[8:].upper()}"


def _aws_style_key() -> str:
    # Looks like AKIA... but is clearly a decoy when inspected closely
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return f"AKIA{body}"


def _aws_style_secret() -> str:
    return secrets.token_urlsafe(30)


def generate_tokens(
    org: str = "Company",
    count: int = 3,
    beacon_base: str = "",
) -> List[Dict[str, Any]]:
    """Create a set of beaconing honey tokens.

    Each token carries a unique id. If beacon_base is set, the token
    content includes a tracking URL that fires when fetched.
    """
    org_slug = "".join(c if c.isalnum() else "_" for c in org)[:20]
    tokens: List[Dict[str, Any]] = []

    for i in range(count):
        tid = _token_id()
        access = _aws_style_key()
        secret = _aws_style_secret()
        beacon_url = ""
        if beacon_base:
            beacon_url = f"{beacon_base.rstrip('/')}/b/{tid}"

        tokens.append({
            "id": tid,
            "type": "aws_access_key",
            "access_key": access,
            "secret_key": secret,
            "beacon_url": beacon_url,
            "label": f"{org_slug}_cloud_key_{i+1}",
            "created": datetime.utcnow().isoformat() + "Z",
        })

        # Azure-style
        tid2 = _token_id("AZ")
        tokens.append({
            "id": tid2,
            "type": "azure_client_secret",
            "client_id": str(secrets.token_hex(16)),
            "client_secret": secrets.token_urlsafe(32),
            "tenant": "decoy-tenant.onmicrosoft.com",
            "beacon_url": f"{beacon_base.rstrip('/')}/b/{tid2}" if beacon_base else "",
            "label": f"{org_slug}_azure_{i+1}",
            "created": datetime.utcnow().isoformat() + "Z",
        })

    return tokens


def tokens_to_env_file(tokens: List[Dict[str, Any]], org: str = "Company") -> str:
    """Render tokens as a realistic-looking secrets file."""
    lines = [
        f"# {org} — Cloud & API credentials (CONFIDENTIAL)",
        f"# Generated for internal automation — do not commit",
        f"# Last rotated: {datetime.utcnow().strftime('%Y-%m-%d')}",
        "",
    ]
    for t in tokens:
        if t["type"] == "aws_access_key":
            lines.append(f"# {t['label']} ({t['id']})")
            lines.append(f"AWS_ACCESS_KEY_ID={t['access_key']}")
            lines.append(f"AWS_SECRET_ACCESS_KEY={t['secret_key']}")
            if t.get("beacon_url"):
                lines.append(f"# healthcheck: {t['beacon_url']}")
            lines.append("")
        elif t["type"] == "azure_client_secret":
            lines.append(f"# {t['label']} ({t['id']})")
            lines.append(f"AZURE_CLIENT_ID={t['client_id']}")
            lines.append(f"AZURE_CLIENT_SECRET={t['client_secret']}")
            lines.append(f"AZURE_TENANT_ID={t['tenant']}")
            if t.get("beacon_url"):
                lines.append(f"# healthcheck: {t['beacon_url']}")
            lines.append("")
    lines.append("# Honey tokens — any external use or fetch of healthcheck URL alerts")
    return "\n".join(lines) + "\n"


def tokens_to_json(tokens: List[Dict[str, Any]]) -> str:
    return json.dumps(tokens, indent=2)


class BeaconListener:
    """Lightweight local HTTP endpoint that records token phone-homes.

    Binds only to the configured address. Pure observation — no data is
    forwarded and no real credentials are validated.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        on_beacon: Optional[Callable] = None,
        known_ids: Optional[set] = None,
    ):
        self.host = host
        self.port = port
        self.on_beacon = on_beacon
        self.known_ids = known_ids or set()
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logger.debug("beacon: " + fmt, *args)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def do_HEAD(self):
                self._handle()

            def _handle(self):
                parsed = urlparse(self.path)
                parts = [p for p in parsed.path.split("/") if p]
                token_id = None
                if len(parts) >= 2 and parts[0] == "b":
                    token_id = parts[1]
                elif "id" in parse_qs(parsed.query):
                    token_id = parse_qs(parsed.query)["id"][0]

                source = self.client_address[0]
                ua = self.headers.get("User-Agent", "")
                logger.info("Beacon hit from %s path=%s id=%s", source, self.path, token_id)

                if outer.on_beacon:
                    outer.on_beacon(
                        event_type="beacon_hit",
                        source_ip=source,
                        details={
                            "token_id": token_id or "unknown",
                            "path": self.path,
                            "user_agent": ua[:120],
                            "method": self.command,
                            "known": token_id in outer.known_ids if token_id else False,
                        },
                    )

                # Always 204 — never leak whether the token was real
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

        return Handler

    def start(self):
        if self._running:
            return
        try:
            self._httpd = HTTPServer((self.host, self.port), self._make_handler())
            self._httpd.timeout = 1.0
            self._running = True

            def serve():
                while self._running:
                    self._httpd.handle_request()

            self._thread = threading.Thread(target=serve, daemon=True)
            self._thread.start()
            logger.info("Beacon listener on %s:%d", self.host, self.port)
        except OSError as e:
            logger.error("Cannot bind beacon listener on %s:%d: %s", self.host, self.port, e)
            self._running = False

    def stop(self):
        self._running = False
        if self._httpd:
            try:
                self._httpd.server_close()
            except Exception:
                pass
        logger.info("Beacon listener stopped")

    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "known_tokens": len(self.known_ids),
        }
