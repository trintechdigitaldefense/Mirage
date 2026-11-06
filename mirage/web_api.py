"""Decoy Web Application API — no plaintext credential storage (v2.5)."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable, List, Optional, Tuple
from urllib.parse import unquote

from . import guardrails
from .redaction import fingerprint

logger = logging.getLogger("mirage.web_api")

ROUTES: List[Tuple[str, int, str, bytes]] = [
    ("/api/v1/auth", 401, "application/json",
     b'{"error":"unauthorized","message":"Invalid credentials"}\n'),
    ("/api/v1/login", 401, "application/json",
     b'{"status":"fail","token":null}\n'),
    ("/api/v1/users", 403, "application/json", b'{"error":"forbidden"}\n'),
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
    for route, status, ctype, body in ROUTES:
        r = route.rstrip("/") or "/"
        if path == r or path.startswith(r + "/") or path == route:
            return status, ctype, body
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


def _credential_meta(body: str) -> dict:
    """Username + fingerprint only — never store password values."""
    meta = {"credential_probe": True, "password_present": False}
    for part in body.replace("&", " ").split():
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip().lower()
        if k in ("user", "username", "login", "log", "email") and v:
            meta["username"] = v[:80]
        if k in ("pass", "password", "passwd", "pwd") and v:
            meta["password_present"] = True
            meta["password_length"] = len(v)
            meta["password_fingerprint"] = fingerprint(v)
    return meta


class WebAPIDecoy:
    def __init__(self, port: int = 8081, listen_addr: str = "127.0.0.1", on_event: Optional[Callable] = None):
        self.port = port
        self.listen_addr = listen_addr
        self.on_event = on_event
        self._sock: Optional[socket.socket] = None
        self._running = False

    def _emit(self, source_ip: str, method: str, path: str, status: int, extra: dict = None):
        if not self.on_event:
            return
        details = {"service": "web_api", "method": method, "path": path, "status": status, "port": self.port}
        if extra:
            details.update(extra)
        try:
            self.on_event(event_type="web_api_hit", source_ip=source_ip, details=details)
        except Exception:
            pass

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        allowed, reason = guardrails.accept_allowed("web_api", source_ip)
        if not allowed:
            try:
                conn.close()
            except OSError:
                pass
            return
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
                status, ctype, body = 200, "text/html", (
                    b"<!DOCTYPE html><html><body><h1>Internal Services</h1>"
                    b"<p>API documentation restricted.</p></body></html>"
                )
            extra = {}
            if method == "POST" and any(x in path.lower() for x in ("login", "auth", "wp-login")):
                body_part = raw.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in raw else ""
                extra.update(_credential_meta(body_part[:500]))
                if status == 200:
                    status = 401
                    body = b'{"error":"invalid_credentials"}\n'
                    ctype = "application/json"
            self._emit(source_ip, method, path, status, extra)
            if status == 302:
                conn.sendall(
                    b"HTTP/1.1 302 Found\r\nLocation: /wp-login.php\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            else:
                resp = (
                    f"HTTP/1.1 {status} X\r\nServer: nginx/1.18.0\r\nContent-Type: {ctype}\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body
                conn.sendall(resp)
        except OSError:
            pass
        finally:
            guardrails.session_release("web_api", source_ip)
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
            logger.error("Web API bind failed on %d: %s", self.port, e)
            return False
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                if guardrails.listeners_paused():
                    time.sleep(0.5)
                    continue
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
        logger.info("Web API decoy on %s:%d", self.listen_addr, self.port)
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
