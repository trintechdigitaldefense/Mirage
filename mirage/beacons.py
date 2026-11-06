"""Beaconing honey tokens — Stage 2 guardrails on HTTP beacon path."""

from __future__ import annotations

import json
import logging
import secrets
import string
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from . import guardrails

logger = logging.getLogger("mirage.beacons")


def _token_id(prefix: str = "MIR") -> str:
    raw = secrets.token_hex(8)
    return f"{prefix}-{raw[:8].upper()}-{raw[8:].upper()}"


def _aws_style_key() -> str:
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return f"AKIA{body}"


def _aws_style_secret() -> str:
    return secrets.token_urlsafe(30)


def generate_tokens(org: str = "Company", count: int = 3, beacon_base: str = "") -> List[Dict[str, Any]]:
    org_slug = "".join(c if c.isalnum() else "_" for c in org)[:20]
    tokens: List[Dict[str, Any]] = []
    for i in range(count):
        tid = _token_id()
        access = _aws_style_key()
        secret = _aws_style_secret()
        beacon_url = f"{beacon_base.rstrip('/')}/b/{tid}" if beacon_base else ""
        tokens.append({
            "id": tid,
            "type": "aws_access_key",
            "access_key": access,
            "secret_key": secret,
            "beacon_url": beacon_url,
            "label": f"{org_slug}_cloud_key_{i+1}",
            "created": datetime.utcnow().isoformat() + "Z",
        })
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
    def __init__(
        self,
        host: str = "127.0.0.1",
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
                if guardrails.listeners_paused():
                    self.send_response(503)
                    self.end_headers()
                    return
                source = self.client_address[0]
                allowed, reason = guardrails.accept_allowed("beacon", source)
                if not allowed:
                    self.send_response(429)
                    self.end_headers()
                    return
                try:
                    parsed = urlparse(self.path)
                    parts = [p for p in parsed.path.split("/") if p]
                    token_id = None
                    if len(parts) >= 2 and parts[0] == "b":
                        token_id = parts[1]
                    elif "id" in parse_qs(parsed.query):
                        token_id = parse_qs(parsed.query)["id"][0]
                    ua = self.headers.get("User-Agent", "")
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
                                "service": "beacon",
                            },
                        )
                    self.send_response(204)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                finally:
                    guardrails.session_release("beacon", source)

        return Handler

    def start(self) -> bool:
        if self._running:
            return True
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
            return True
        except OSError as e:
            logger.error("Cannot bind beacon on %s:%d: %s", self.host, self.port, e)
            self._running = False
            return False

    def stop(self):
        self._running = False
        if self._httpd:
            try:
                self._httpd.server_close()
            except Exception:
                pass

    def status(self) -> Dict[str, Any]:
        return {
            "name": "beacon",
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "known_tokens": len(self.known_ids),
        }
