"""Minimal authenticated operator dashboard (Stage 5 MVP).

Binds to 127.0.0.1 only. Token auth via MIRAGE_DASH_TOKEN or config dashboard_token.
Not a full SPA — read-only HTML status for local operators.
"""

from __future__ import annotations

import html
import logging
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .config import load_config, ensure_data_dir
from .db import get_all_events
from .health import health_report
from .registry import REGISTRY
from .tokens import lifecycle_summary
from . import guardrails

logger = logging.getLogger("mirage.dashboard")


def _token() -> str:
    cfg = load_config()
    t = cfg.get("dashboard_token") or os.environ.get("MIRAGE_DASH_TOKEN") or ""
    if not t:
        path = ensure_data_dir() / "dashboard_token.txt"
        if path.exists():
            t = path.read_text(encoding="utf-8").strip()
        else:
            t = secrets.token_urlsafe(24)
            path.write_text(t + "\n", encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    return t


class Dashboard:
    def __init__(self, port: int = 8787, listen_addr: str = "127.0.0.1"):
        self.port = port
        self.listen_addr = listen_addr
        self._httpd: Optional[HTTPServer] = None
        self._running = False

    def _page(self) -> bytes:
        events = get_all_events(limit=15)
        rows = "".join(
            f"<tr><td>{html.escape(str(e.get('timestamp','')))}</td>"
            f"<td>{html.escape(str(e.get('event_type','')))}</td>"
            f"<td>{html.escape(str(e.get('source_ip','')))}</td></tr>"
            for e in events
        )
        reg = "".join(
            f"<li>{html.escape(r.get('state','?'))} {html.escape(r.get('name',''))} :{r.get('port')}</li>"
            for r in (REGISTRY.status_list() or [])
        )
        tok = lifecycle_summary()
        body = f"""<!DOCTYPE html><html><head><title>Mirage Operator</title>
<style>body{{font-family:system-ui;margin:1.5rem;background:#0b1220;color:#e8eefc}}
 table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #334;padding:6px}}
 a{{color:#8cf}}</style></head><body>
<h1>Mirage Operator (local)</h1>
<p>Authenticated view · bind {html.escape(self.listen_addr)}:{self.port}</p>
<h2>Health</h2><pre>{html.escape(health_report())}</pre>
<h2>Registry</h2><ul>{reg or '<li>none (deploy not in this process)</li>'}</ul>
<h2>Tokens</h2><pre>{html.escape(str(tok))}</pre>
<h2>Recent events</h2>
<table><tr><th>Time</th><th>Type</th><th>Source</th></tr>{rows or '<tr><td colspan=3>none</td></tr>'}</table>
<p><small>Stage 5 MVP — no unauthenticated write APIs. CSRF N/A (GET-only).</small></p>
</body></html>"""
        return body.encode("utf-8")

    def _handler(self):
        outer = self
        expected = _token()

        class H(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logger.debug("dash: " + fmt, *args)

            def do_GET(self):
                if guardrails.listeners_paused():
                    self.send_response(503)
                    self.end_headers()
                    return
                auth = self.headers.get("Authorization") or ""
                q = parse_qs(urlparse(self.path).query)
                token = ""
                if auth.lower().startswith("bearer "):
                    token = auth.split(" ", 1)[1].strip()
                elif q.get("token"):
                    token = q["token"][0]
                if not token or not secrets.compare_digest(token, expected):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", "Bearer")
                    self.end_headers()
                    self.wfile.write(b"unauthorized")
                    return
                body = outer._page()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.send_response(405)
                self.end_headers()

        return H

    def start(self) -> bool:
        if self._running:
            return True
        if self.listen_addr not in ("127.0.0.1", "localhost", "::1"):
            logger.error("Dashboard refuses non-loopback bind")
            return False
        try:
            self._httpd = HTTPServer((self.listen_addr, self.port), self._handler())
            self._httpd.timeout = 1.0
            self._running = True

            def serve():
                while self._running:
                    self._httpd.handle_request()

            threading.Thread(target=serve, daemon=True).start()
            logger.info("Dashboard on http://%s:%d (Bearer token required)", self.listen_addr, self.port)
            return True
        except OSError as e:
            logger.error("Dashboard bind failed: %s", e)
            return False

    def stop(self):
        self._running = False
        if self._httpd:
            try:
                self._httpd.server_close()
            except Exception:
                pass
