"""Cloud decoys — Feature 15.

Fake 'misconfigured' cloud storage that looks like an exposed bucket.
Implemented as a lightweight HTTP listing endpoint on a dedicated port.
Any GET/list fires an alert. Pure TrinTech-controlled surface — does not
touch the client's real cloud.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("mirage.cloud_decoy")


def _listing_html(org: str, objects: List[str]) -> bytes:
    rows = "".join(f"<tr><td>{o}</td><td>2024-11-02</td><td>application/octet-stream</td></tr>" for o in objects)
    body = (
        f"<!DOCTYPE html><html><head><title>{org} backups</title></head>"
        f"<body><h1>Bucket: {org.lower().replace(' ', '-')}-backups</h1>"
        f"<p><em>Listing public (misconfigured decoy)</em></p>"
        f"<table border=1 cellpadding=4><tr><th>Key</th><th>LastModified</th><th>Type</th></tr>"
        f"{rows}</table>"
        f"<!-- DECOY CLOUD STORAGE -->"
        f"</body></html>"
    )
    return body.encode("utf-8")


class CloudDecoy:
    def __init__(
        self,
        org: str = "Company",
        port: int = 9000,
        listen_addr: str = "0.0.0.0",
        on_event: Optional[Callable] = None,
        objects: Optional[List[str]] = None,
    ):
        self.org = org or "Company"
        self.port = port
        self.listen_addr = listen_addr
        self.on_event = on_event
        self.objects = objects or [
            "backups_2024.zip",
            "payroll.csv",
            "customer_export.csv",
            "vpn_configs.tar.gz",
            "db_dump.sql.gz",
        ]
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logger.debug("cloud decoy: " + fmt, *args)

            def do_GET(self):
                self._hit("GET")

            def do_HEAD(self):
                self._hit("HEAD")

            def do_LIST(self):  # nonstandard, still log
                self._hit("LIST")

            def _hit(self, method: str):
                source = self.client_address[0]
                path = urlparse(self.path).path
                if outer.on_event:
                    outer.on_event(
                        event_type="cloud_decoy_access",
                        source_ip=source,
                        details={
                            "service": "cloud_decoy",
                            "method": method,
                            "path": path,
                            "user_agent": self.headers.get("User-Agent", "")[:120],
                            "bucket": f"{outer.org.lower().replace(' ', '-')}-backups",
                        },
                    )
                body = _listing_html(outer.org, outer.objects)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", "AmazonS3")
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(body)

        return Handler

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._httpd = HTTPServer((self.listen_addr, self.port), self._handler())
            self._httpd.timeout = 1.0
            self._running = True

            def serve():
                while self._running:
                    self._httpd.handle_request()

            self._thread = threading.Thread(target=serve, daemon=True)
            self._thread.start()
            logger.info("Cloud decoy bucket on %s:%d", self.listen_addr, self.port)
            return True
        except OSError as e:
            logger.error("Cloud decoy bind failed: %s", e)
            self._running = False
            return False

    def stop(self):
        self._running = False
        if self._httpd:
            try:
                self._httpd.server_close()
            except Exception:
                pass
        logger.info("Cloud decoy stopped")

    def status(self) -> Dict[str, Any]:
        return {
            "name": "cloud_decoy",
            "port": self.port,
            "running": self._running,
            "objects": self.objects,
        }
