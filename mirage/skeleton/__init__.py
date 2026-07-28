"""Mirage skeleton decoys — lightweight TCP listeners."""

import socket
import threading
import logging
import time
import random
import struct

logger = logging.getLogger("mirage.skeleton")

BANNERS = {
    22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n<html><body><h1>Welcome</h1></body></html>",
    443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><body><h1>Secure Portal</h1></body></html>",
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f",
    8080: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><body><h1>Dashboard</h1><p>Unauthorized</p></body></html>"
}


class SkeletonService:
    """Manages a single decoy TCP listener on a port."""

    def __init__(self, port: int, interface: str = "", on_connection=None):
        self.port = port
        self.interface = interface
        self.on_connection = on_connection
        self._server = None
        self._thread = None
        self._running = False

    def _handle(self, conn, addr):
        logger.info("DECOY_CONNECTED port=%d from=%s", self.port, addr)
        if self.on_connection:
            self.on_connection("decoy_connect", {
                "port": self.port, "source_ip": addr[0],
                "source_port": addr[1], "protocol": "tcp"
            })
        try:
            banner = BANNERS.get(self.port, b"\n")
            if isinstance(banner, str):
                banner = banner.encode()
            conn.sendall(banner)
            time.sleep(random.uniform(0.3, 2.0))
        except OSError:
            pass
        finally:
            conn.close()

    def start(self):
        if self._running:
            return
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_addr = self.interface if self.interface else "0.0.0.0"
        self._server.bind((bind_addr, self.port))
        self._server.listen(5)
        self._server.settimeout(1.0)

        def serve():
            while self._running:
                try:
                    conn, addr = self._server.accept()
                    t = threading.Thread(target=self._handle, args=(conn, addr))
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            self._server.close()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        logger.info("Decoy on port %d started", self.port)

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        logger.info("Decoy on port %d stopped", self.port)


class SkeletonManager:
    """Manages all decoy skeleton services."""

    def __init__(self, ports: list | None = None, interface: str = "", on_connection=None):
        self.ports = ports or [22, 80, 443, 3306, 8080]
        self.interface = interface
        self.on_connection = on_connection
        self.services: list[SkeletonService] = []

    def deploy(self, ports: list | None = None):
        if ports:
            self.ports = ports
        for p in self.ports:
            srv = SkeletonService(p, self.interface, self.on_connection)
            srv.start()
            self.services.append(srv)
        logger.info("Skeleton decoys deployed on ports: %s", self.ports)

    def tear_down(self):
        for srv in self.services:
            srv.stop()
        self.services.clear()
        logger.info("All skeleton decoys stopped")

    def status(self) -> list:
        return [srv.port for srv in self.services if srv._running]


def join_all(self):
    """Wait for all services to stop."""
    for srv in self.services:
        if srv._thread:
            srv._thread.join()
