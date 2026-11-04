"""Realistic fake network services for Mirage deception platform (v2.3)."""

from __future__ import annotations

import logging
import random
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mirage.services")

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
HTTP_SERVER = "Apache/2.4.52 (Ubuntu)"
FTP_BANNER = b"220 Welcome to FTP Server (vsFTPd 3.0.5)\r\n"
MYSQL_GREETING = (
    b"\x4a\x00\x00\x00\x0a8.0.36\x00\x0f\x00\x00\x00"
    b"abcdefgh\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00abcdefghijklmnop\x00"
)
RDP_BANNER = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x02\x00\x00\x00"
REDIS_PONG = b"+PONG\r\n"
REDIS_ERR = b"-ERR invalid password\r\n"
POSTGRES_AUTH = (
    # Startup failure / password required style bytes (simplified)
    b"R\x00\x00\x00\x08\x00\x00\x00\x03"  # AuthenticationCleartextPassword-ish
)
ELASTIC_BANNER = (
    b'{"name":"decoy-node-01","cluster_name":"elasticsearch",'
    b'"version":{"number":"7.17.9","build_flavor":"default"},'
    b'"tagline":"You Know, for Search"}\n'
)


def _http_response(server: str = HTTP_SERVER, body: Optional[bytes] = None) -> bytes:
    if body is None:
        body = (
            b"<!DOCTYPE html><html><head><title>Admin Portal</title></head>"
            b"<body><h1>Internal Admin Portal</h1>"
            b"<p>Authorized personnel only. Login required.</p>"
            b"<form method='POST' action='/login'>"
            b"<input name='username' placeholder='Username'>"
            b"<input name='password' type='password' placeholder='Password'>"
            b"<button type='submit'>Login</button></form></body></html>"
        )
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Server: {server}\r\n".encode()
        + b"Content-Type: text/html\r\n"
        + b"Connection: close\r\n\r\n"
        + body
    )


def _http_error_500(server: str) -> bytes:
    return (
        b"HTTP/1.1 500 Internal Server Error\r\n"
        + f"Server: {server}\r\n".encode()
        + b"Content-Type: text/html\r\nConnection: close\r\n\r\n"
        + b"<html><body><h1>Invalid Gateway</h1><p>Server Error 500</p></body></html>"
    )


def _load_cosmetics():
    global SSH_BANNER, HTTP_SERVER, FTP_BANNER
    try:
        from .rotation import get_ssh_banner, get_http_server, get_ftp_banner

        SSH_BANNER = get_ssh_banner()
        HTTP_SERVER = get_http_server()
        FTP_BANNER = get_ftp_banner()
    except Exception:
        pass


def _parse_http_credentials(data: bytes) -> Dict[str, str]:
    text = data.decode("utf-8", errors="replace")
    out: Dict[str, str] = {}
    if "username=" in text or "user=" in text or "password=" in text or "pass=" in text:
        # crude form parse
        body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else text
        for part in body.replace("&", " ").split():
            if "=" in part:
                k, _, v = part.partition("=")
                k = k.strip().lower()
                if k in ("user", "username", "login", "email"):
                    out["username"] = v[:80]
                if k in ("pass", "password", "passwd"):
                    out["password"] = v[:80]
    return out


class FakeService:
    def __init__(
        self,
        name: str,
        port: int,
        banner: bytes,
        listen_addr: str = "0.0.0.0",
        on_connect: Optional[Callable] = None,
        mode: str = "banner",  # banner | http_admin | redis | postgres | elastic
    ):
        self.name = name
        self.port = port
        self.banner = banner
        self.listen_addr = listen_addr
        self.on_connect = on_connect
        self.mode = mode
        self._sock = None
        self._thread = None
        self._running = False

    def _emit(self, event_type: str, source_ip: str, details: dict):
        if self.on_connect:
            try:
                self.on_connect(event_type=event_type, source_ip=source_ip, details=details)
            except Exception:
                pass

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        # Refresh banner per connection if mutator says so
        _load_cosmetics()
        self._emit(
            f"decoy_{self.name}_connect",
            source_ip,
            {"service": self.name, "port": self.port, "source_port": addr[1]},
        )
        try:
            conn.settimeout(8.0)
            if self.mode == "http_admin":
                self._handle_http(conn, source_ip)
            elif self.mode == "redis":
                self._handle_redis(conn, source_ip)
            elif self.mode == "postgres":
                self._handle_postgres(conn, source_ip)
            elif self.mode == "elastic":
                self._handle_elastic(conn, source_ip)
            else:
                try:
                    from .rotation import get_ssh_banner, get_ftp_banner, get_http_server

                    if self.name == "ssh":
                        conn.sendall(get_ssh_banner())
                    elif self.name == "ftp":
                        conn.sendall(get_ftp_banner())
                    elif self.name in ("http", "https"):
                        conn.sendall(_http_response(get_http_server()))
                    else:
                        conn.sendall(self.banner)
                except Exception:
                    conn.sendall(self.banner)
                try:
                    data = conn.recv(2048)
                    if data:
                        self._emit(
                            f"decoy_{self.name}_data",
                            source_ip,
                            {
                                "service": self.name,
                                "port": self.port,
                                "bytes_received": len(data),
                                "preview": data[:80].decode("utf-8", errors="replace"),
                            },
                        )
                except (socket.timeout, OSError):
                    pass
                time.sleep(random.uniform(0.3, 1.5))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_http(self, conn: socket.socket, source_ip: str):
        from .rotation import get_http_server

        server = get_http_server()
        try:
            data = conn.recv(4096)
        except (socket.timeout, OSError):
            data = b""
        creds = _parse_http_credentials(data) if data else {}
        if data:
            self._emit(
                "decoy_http_data",
                source_ip,
                {
                    "service": "http",
                    "port": self.port,
                    "bytes_received": len(data),
                    "preview": data[:100].decode("utf-8", errors="replace"),
                },
            )
        if creds:
            self._emit(
                "http_login_capture",
                source_ip,
                {
                    "service": "http_admin",
                    "port": self.port,
                    "username": creds.get("username", ""),
                    "password": creds.get("password", ""),
                    "note": "submitted to decoy admin portal",
                },
            )
            conn.sendall(_http_error_500(server))
        else:
            conn.sendall(_http_response(server))

    def _handle_redis(self, conn: socket.socket, source_ip: str):
        try:
            from .rotation import get_redis_version

            ver = get_redis_version()
        except Exception:
            ver = "7.0.12"
        # Minimal: respond to anything with AUTH error / PONG
        try:
            data = conn.recv(1024)
        except (socket.timeout, OSError):
            data = b""
        preview = data[:60].decode("utf-8", errors="replace") if data else ""
        self._emit(
            "decoy_redis_data",
            source_ip,
            {"service": "redis", "port": self.port, "preview": preview, "version": ver},
        )
        if data and b"AUTH" in data.upper():
            conn.sendall(REDIS_ERR)
            self._emit(
                "http_login_capture" if False else "decoy_redis_auth",
                source_ip,
                {"service": "redis", "port": self.port, "preview": preview},
            )
        else:
            try:
                conn.sendall(f"$32\r\nredis_version:{ver}\r\n".encode() if False else REDIS_PONG)
            except OSError:
                pass

    def _handle_postgres(self, conn: socket.socket, source_ip: str):
        try:
            data = conn.recv(1024)
        except (socket.timeout, OSError):
            data = b""
        self._emit(
            "decoy_postgres_data",
            source_ip,
            {
                "service": "postgres",
                "port": self.port,
                "bytes_received": len(data) if data else 0,
                "preview": (data[:40].hex() if data else ""),
            },
        )
        try:
            conn.sendall(POSTGRES_AUTH)
        except OSError:
            pass

    def _handle_elastic(self, conn: socket.socket, source_ip: str):
        try:
            data = conn.recv(2048)
        except (socket.timeout, OSError):
            data = b""
        self._emit(
            "decoy_elastic_data",
            source_ip,
            {
                "service": "elastic",
                "port": self.port,
                "bytes_received": len(data) if data else 0,
            },
        )
        try:
            body = ELASTIC_BANNER
            resp = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            conn.sendall(resp)
        except OSError:
            pass

    def start(self):
        if self._running:
            return
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_addr, self.port))
        except OSError as e:
            logger.error("Cannot bind %s on port %d: %s", self.name, self.port, e)
            self._running = False
            return
        self._sock.listen(16)
        self._sock.settimeout(1.0)

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

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        logger.info("Fake %s listening on %s:%d mode=%s", self.name, self.listen_addr, self.port, self.mode)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


class ServiceManager:
    def __init__(
        self,
        ports: Dict[str, int],
        listen_addr: str = "0.0.0.0",
        on_connect: Optional[Callable] = None,
        ssh_jail: bool = True,
        ssh_jail_timeout: int = 300,
    ):
        self.ports = ports
        self.listen_addr = listen_addr
        self.on_connect = on_connect
        self.ssh_jail = ssh_jail
        self.ssh_jail_timeout = ssh_jail_timeout
        self.services: List[Any] = []
        self._jail = None

    def deploy(self):
        _load_cosmetics()
        mapping = {
            "http": ("http", _http_response(HTTP_SERVER), "http_admin"),
            "https": ("https", _http_response(HTTP_SERVER), "http_admin"),
            "mysql": ("mysql", MYSQL_GREETING, "banner"),
            "ftp": ("ftp", FTP_BANNER, "banner"),
            "rdp": ("rdp", RDP_BANNER, "banner"),
            "redis": ("redis", REDIS_PONG, "redis"),
            "postgres": ("postgres", POSTGRES_AUTH, "postgres"),
            "elastic": ("elastic", ELASTIC_BANNER, "elastic"),
        }

        if "ssh" in self.ports:
            port = self.ports["ssh"]
            if self.ssh_jail:
                try:
                    from .ssh_jail import SSHJail, PARAMIKO_AVAILABLE

                    if PARAMIKO_AVAILABLE:
                        jail = SSHJail(
                            port=port,
                            listen_addr=self.listen_addr,
                            on_event=self.on_connect,
                            session_timeout=self.ssh_jail_timeout,
                        )
                        if jail.start():
                            self._jail = jail
                            self.services.append(jail)
                            logger.info("SSH jail active on port %d", port)
                        else:
                            self._start_banner_ssh(port)
                    else:
                        self._start_banner_ssh(port)
                except Exception as e:
                    logger.error("SSH jail error: %s", e)
                    self._start_banner_ssh(port)
            else:
                self._start_banner_ssh(port)

        for key, port in self.ports.items():
            if key == "ssh":
                continue
            if key in mapping:
                name, banner, mode = mapping[key]
                svc = FakeService(name, port, banner, self.listen_addr, self.on_connect, mode=mode)
                svc.start()
                if svc._running:
                    self.services.append(svc)

    def _start_banner_ssh(self, port: int):
        svc = FakeService("ssh", port, SSH_BANNER, self.listen_addr, self.on_connect)
        svc.start()
        if svc._running:
            self.services.append(svc)

    def stop_all(self):
        for svc in self.services:
            try:
                svc.stop()
            except Exception:
                pass
        self.services.clear()
        self._jail = None

    def status(self) -> List[Dict]:
        out = []
        for s in self.services:
            if hasattr(s, "status") and callable(s.status):
                st = s.status()
                if isinstance(st, dict):
                    out.append(st)
                else:
                    out.append({"name": getattr(s, "name", "?"), "port": getattr(s, "port", 0), "running": True})
            else:
                out.append({
                    "name": getattr(s, "name", "?"),
                    "port": getattr(s, "port", 0),
                    "running": getattr(s, "_running", True),
                })
        return out
