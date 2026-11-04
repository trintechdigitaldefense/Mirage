"""TCP Tarpit — hold scanner threads with sub-byte-per-second responses.

Accepts connections on designated ports and drips data slowly so automated
scanners (Nmap scripts, Masscan follow-ups, brute tools) burn time and sockets.
Passive only: no outbound traffic, no exploit of the peer.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("mirage.tarpit")

# Slow drip payload (looks like a partial SSH/HTTP handshake fragment)
DRIP = b"."


class TarpitPort:
    def __init__(
        self,
        port: int,
        listen_addr: str = "0.0.0.0",
        drip_interval: float = 2.0,
        max_session_sec: float = 120.0,
        on_event: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        self.drip_interval = max(0.5, float(drip_interval))
        self.max_session_sec = max(10.0, float(max_session_sec))
        self.on_event = on_event
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        if self.on_event:
            try:
                self.on_event(
                    event_type="tarpit_hold",
                    source_ip=source_ip,
                    details={
                        "service": "tarpit",
                        "port": self.port,
                        "source_port": addr[1],
                        "drip_interval": self.drip_interval,
                    },
                )
            except Exception:
                pass
        start = time.time()
        try:
            conn.settimeout(self.drip_interval + 1.0)
            while self._running and (time.time() - start) < self.max_session_sec:
                try:
                    conn.sendall(DRIP)
                except OSError:
                    break
                time.sleep(self.drip_interval)
                try:
                    # Drain any scanner payload without responding quickly
                    conn.recv(256)
                except (socket.timeout, OSError):
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
            logger.error("Tarpit bind failed on %d: %s", self.port, e)
            return False
        self._sock.listen(32)
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    ).start()
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
        logger.info("Tarpit listening on %s:%d (drip=%.1fs)", self.listen_addr, self.port, self.drip_interval)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> Dict:
        return {
            "name": "tarpit",
            "port": self.port,
            "running": self._running,
            "drip_interval": self.drip_interval,
        }


class TarpitManager:
    """Run tarpits on multiple ports (e.g. 2223, 3390, 4451)."""

    def __init__(
        self,
        ports: List[int],
        listen_addr: str = "0.0.0.0",
        drip_interval: float = 2.0,
        max_session_sec: float = 120.0,
        on_event: Optional[Callable] = None,
    ):
        self.ports = ports or []
        self.listen_addr = listen_addr
        self.drip_interval = drip_interval
        self.max_session_sec = max_session_sec
        self.on_event = on_event
        self._pits: List[TarpitPort] = []

    def deploy(self):
        for p in self.ports:
            pit = TarpitPort(
                port=int(p),
                listen_addr=self.listen_addr,
                drip_interval=self.drip_interval,
                max_session_sec=self.max_session_sec,
                on_event=self.on_event,
            )
            if pit.start():
                self._pits.append(pit)

    def stop(self):
        for pit in self._pits:
            pit.stop()
        self._pits.clear()

    def status(self) -> List[Dict]:
        return [p.status() for p in self._pits]
