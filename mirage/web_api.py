"""Decoy Web Application API & Endpoint Generator.

Low-interaction HTTP routes that mimic vulnerable management interfaces.
Scanners (Nuclei, Nikto, crawlers) hitting these paths generate high-confidence alerts.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote

logger = logging.getLogger("mirage.web_api")

# path prefix -> (status, content-type, body)
ROUTES: List[Tuple[str, int, str, bytes]] = [
    ("/api/v1/auth", 401, "application/json",
     b'{"error":"unauthorized","message":"Invalid credentials"}\n'),
    ("/api/v1/login", 401, "application/json",
     b'{"status":"fail","token":null}\n'),
    ("/api/v1/users", 403, "application/json",
     b'{"error":"forbidden"}\n'),
    ("/.env", 200, "text/plain",
     b"APP_KEY=base64:DECOY_KEY_DO_NOT_USE\nDB_PASSWORD=Pr0d_S3cure_2026!\n"
     b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/DECOY\n"),
    ("/wp-login.php", 200, "text/html",
     b"<html><body><h1>WordPress Login</h1>"
     b"<form method='post'><input name='log'><input name='pwd' type='password'>"
     b"<input type='submit' value='Log In'></form></body></html>"),
    ("/wp-admin/", 302, "text/html", b"Redirect"),
    ("/admin/config.json", 200, "application/json",
     b'{"db_host":"10.0.0.15","db_user":"admin","db_pass":"Pr0d_S3cure_2026!"}\n'),
    ("/admin/", 200, "text/html",
     b"<html><body><h1>Admin Console</h1><form method='post' action='/api/v1/auth'>"
     b"<input name='username'><input name='password' type='password'>"
     b"<button>Login</button></form></body></html>"),
    ("/phpmyadmin/", 401, "text/html", b"Unauthorized"),
    ("/actuator/env", 200, "application/json",
     b'{"activeProfiles":["prod"],"propertySources":[{"name":"decoy"}]}\n'),
    ("/server-status", 403, "text/plain", b"Forbidden\n"),
    ("/console/", 200, "text/html", b"<html><body>Management Console</body></html>"),
    ("/manager/html", 401, "text/plain", b"Unauthorized"),
    ("/robots.txt", 200, "text/plain",
     b"User-agent: *\nDisallow: /admin/\nDisallow: /.env\nDisallow: /api/\n"),
]


def _match_route(path: str) -> Optional[Tuple[int, str, bytes]]:
    path = path.split("?")[0].rstrip("/") or "/"
    # exact then prefix
    for route, status, ctype, body in ROUTES:
        r = route.rstrip("/") or "/"
        if path == r or path.startswith(r + "/") or path == route:
            return status, ctype, body
    # path traversal / sensitive probes
    low = path.lower()
    if any(x in low for x in ("../", ".git", "wp-config", "web.config", "id_rsa", "backup.sql")):
        return 403, "text/plain", b"Forbidden\n"
    return None


def _parse_request(data: bytes) -> Tuple[str, str, str]:
    try:
        text = data.decode("utf-8", errors="replace")
        line = text.split("\r\n", 1)[0]
        parts = line.split()
        method = parts[0] if parts else "GET"
        path = unquote(parts[1]) if len(parts) > 1 else "/"
        return method, path, text
    except Exception:
        return "GET", "/", ""


class WebAPIDecoy:
    def __init__(
        self,
        port: int = 8081,
        listen_addr: str = "0.0.0.0",
        on_event: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        self.on_event = on_event
        self._sock: Optional[socket.socket] = None
        self._running = False

    def _emit(self, source_ip: str, method: str, path: str, status: int, extra: dict = None):
        if not self.on_event:
            return
        details = {
            "service": "web_api",
            "method": method,
            "path": path,
            "status": status,
            "port": self.port,
        }
        if extra:
            details.update(extra)
        try:
            self.on_event(
                event_type="web_api_hit",
                source_ip=source_ip,
                details=details,
            )
        except Exception:
            pass

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        try:
            conn.settimeout(5.0)
            data = conn.recv(8192)
            if not data:
                return
            method, path, raw = _parse_request(data)
            matched = _match_route(path)
            if matched:
                status, ctype, body = matched
            else:
                # default decoy portal
                status, ctype, body = 200, "text/html", (
                    b"<!DOCTYPE html><html><body><h1>Internal Services</h1>"
                    b"<p>API documentation restricted.</p></body></html>"
                )
            extra = {}
            if method == "POST" and ("login" in path.lower() or "auth" in path.lower() or "wp-login" in path.lower()):
                # capture submitted creds fragment
                body_part = raw.split("\r\n\r\n", 1)[-1][:120] if "\r\n\r\n" in raw else ""
                extra["post_preview"] = body_part
                extra["credential_probe"] = True
                if status == 200:
                    status = 401
                    body = b'{"error":"invalid_credentials"}\n'
                    ctype = "application/json"

            self._emit(source_ip, method, path, status, extra)

            if status == 302:
                hdr = (
                    f"HTTP/1.1 302 Found\r\nLocation: /wp-login.php\r\n"
                    f"Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode()
                conn.sendall(hdr)
            else:
                resp = (
                    f"HTTP/1.1 {status} X\r\n"
                    f"Server: nginx/1.18.0\r\n"
                    f"Content-Type: {ctype}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body
                conn.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def start(self) -> bool:
        if self._running:
            return True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_addr, self.port))
        except OSError as e:
            logger.error("Web API decoy bind failed on %d: %s", self.port, e)
            return False
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            try:
                self._sock.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        logger.info("Web API decoy on %s:%d (%d routes)", self.listen_addr, self.port, len(ROUTES))
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> dict:
        return {"name": "web_api", "port": self.port, "running": self._running, "routes": len(ROUTES)}
