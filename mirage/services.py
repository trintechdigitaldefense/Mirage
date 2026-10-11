"""Realistic fake network services for Mirage deception platform."""

from __future__ import annotations

import socket
import threading
import time
import random
import logging
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger("mirage.services")

# Defaults — overridden at deploy by rotation cosmetics when available
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
HTTP_SERVER = "Apache/2.4.52 (Ubuntu)"
FTP_BANNER = b"220 Welcome to FTP Server (vsFTPd 3.0.5)\r\n"

MYSQL_GREETING = (
    b"\x4a\x00\x00\x00\x0a8.0.36\x00\x0f\x00\x00\x00"
    b"abcdefgh\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00abcdefghijklmnop\x00"
)
RDP_BANNER = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x02\x00\x00\x00"


def _http_response(server: str = HTTP_SERVER) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Server: {server}\r\n".encode()
        + b"Content-Type: text/html\r\n"
        + b"Connection: close\r\n\r\n"
        + b"<!DOCTYPE html><html><head><title>Admin Portal</title></head>"
        + b"<body><h1>Internal Admin Portal</h1>"
        + b"<p>Authorized personnel only. Login required.</p>"
        + b"<form><input name='user' placeholder='Username'>"
        + b"<input name='pass' type='password' placeholder='Password'>"
        + b"<button>Login</button></form></body></html>"
    )


def _load_cosmetics():
    """Pull rotated banners if rotation module is available."""
    global SSH_BANNER, HTTP_SERVER, FTP_BANNER
    try:
        from .rotation import get_ssh_banner, get_http_server, get_ftp_banner
        SSH_BANNER = get_ssh_banner()
        HTTP_SERVER = get_http_server()
        FTP_BANNER = get_ftp_banner()
    except Exception:
        pass


class FakeService:
    def __init__(self, name: str, port: int, banner: bytes,
                 listen_addr: str = "0.0.0.0",
                 on_connect: Optional[Callable] = None):
        self.name = name
        self.port = port
        self.banner = banner
        self.listen_addr = listen_addr
        self.on_connect = on_connect
        self._sock = None
        self._thread = None
        self._running = False

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        logger.info("Connection to %s (port %d) from %s", self.name, self.port, source_ip)
        if self.on_connect:
            self.on_connect(
                event_type=f"decoy_{self.name}_connect",
                source_ip=source_ip,
                details={
                    "service": self.name,
                    "port": self.port,
                    "source_port": addr[1],
                },
            )
        try:
            conn.settimeout(5.0)
            conn.sendall(self.banner)
            try:
                data = conn.recv(1024)
                if data and self.on_connect:
                    self.on_connect(
                        event_type=f"decoy_{self.name}_data",
                        source_ip=source_ip,
                        details={
                            "service": self.name,
                            "port": self.port,
                            "bytes_received": len(data),
                            "preview": data[:80].decode("utf-8", errors="replace"),
                        },
                    )
            except (socket.timeout, OSError):
                pass
            time.sleep(random.uniform(0.4, 1.8))
        except OSError:
            pass
        finally:
            try:
                conn.close()
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
        self._sock.listen(8)
        self._sock.settimeout(1.0)

        def serve():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                    t.start()
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
        logger.info("Fake %s listening on %s:%d", self.name, self.listen_addr, self.port)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        logger.info("Fake %s stopped", self.name)


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
            "http": ("http", _http_response(HTTP_SERVER)),
            "https": ("https", _http_response(HTTP_SERVER)),
            "mysql": ("mysql", MYSQL_GREETING),
            "ftp": ("ftp", FTP_BANNER),
            "rdp": ("rdp", RDP_BANNER),
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
                            logger.warning("SSH jail failed to bind — falling back to banner decoy")
                            self._start_banner_ssh(port)
                    else:
                        logger.warning("paramiko missing — SSH jail disabled, using banner decoy")
                        self._start_banner_ssh(port)
                except Exception as e:
                    logger.error("SSH jail error: %s — using banner decoy", e)
                    self._start_banner_ssh(port)
            else:
                self._start_banner_ssh(port)

        for key, port in self.ports.items():
            if key == "ssh":
                continue
            if key in mapping:
                name, banner = mapping[key]
                svc = FakeService(name, port, banner, self.listen_addr, self.on_connect)
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
