"""Fake DNS canary records — Stage 2 guardrails on UDP path."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable, List, Optional, Set

from . import guardrails

logger = logging.getLogger("mirage.dns_canary")

DEFAULT_CANARIES = [
    "dev-db-admin.internal.local",
    "backup-vault.local",
    "payroll-sql.internal.local",
    "vpn-gateway-mgmt.local",
    "ad-backup.corp.local",
]


def _parse_qname(data: bytes, offset: int = 12) -> tuple:
    labels = []
    pos = offset
    try:
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1
            labels.append(data[pos : pos + length].decode("utf-8", errors="replace"))
            pos += length
        return ".".join(labels).lower(), pos
    except Exception:
        return "", offset


def _build_nxdomain(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    hdr = bytearray(query[:12])
    hdr[2] = 0x81
    hdr[3] = 0x83
    hdr[6:12] = b"\x00\x00\x00\x00\x00\x00"
    return bytes(hdr) + query[12:]


class DNSCanary:
    def __init__(
        self,
        port: int = 5353,
        listen_addr: str = "127.0.0.1",
        canary_names: Optional[List[str]] = None,
        on_event: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        names = canary_names or DEFAULT_CANARIES
        self.canaries: Set[str] = {n.lower().rstrip(".") for n in names}
        self.on_event = on_event
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _handle(self, data: bytes, addr):
        source_ip = addr[0]
        allowed, reason = guardrails.accept_allowed("dns_canary", source_ip)
        if not allowed:
            return
        try:
            name, _ = _parse_qname(data)
            if not name:
                return
            matched = name in self.canaries or any(
                name.endswith("." + c) or name == c for c in self.canaries
            )
            hit = matched or any(
                token in name
                for token in ("dev-db", "backup-vault", "payroll-sql", "vpn-gateway", "ad-backup")
            )
            if hit and self.on_event:
                try:
                    self.on_event(
                        event_type="dns_canary_lookup",
                        source_ip=source_ip,
                        details={
                            "service": "dns_canary",
                            "qname": name,
                            "matched": matched,
                            "port": self.port,
                        },
                    )
                except Exception:
                    pass
            try:
                resp = _build_nxdomain(data)
                if resp and self._sock:
                    self._sock.sendto(resp, addr)
            except OSError:
                pass
        finally:
            guardrails.session_release("dns_canary", source_ip)

    def start(self) -> bool:
        if self._running:
            return True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_addr, self.port))
        except OSError as e:
            logger.error("DNS canary bind failed on %d: %s", self.port, e)
            return False
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                if guardrails.listeners_paused():
                    time.sleep(0.5)
                    continue
                try:
                    data, addr = self._sock.recvfrom(512)
                    if data:
                        self._handle(data, addr)
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
        logger.info("DNS canary on %s:%d", self.listen_addr, self.port)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> dict:
        return {
            "name": "dns_canary",
            "port": self.port,
            "running": self._running,
            "canary_count": len(self.canaries),
        }
