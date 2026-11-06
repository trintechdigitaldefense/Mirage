"""TCP Tarpit — hold scanners; accept-time guardrails (v2.5)."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional

from . import guardrails

logger = logging.getLogger("mirage.tarpit")
DRIP = b"."


class TarpitPort:
    def __init__(
        self,
        port: int,
        listen_addr: str = "127.0.0.1",
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
        allowed, reason = guardrails.accept_allowed("tarpit", source_ip)
        if not allowed:
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
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
            conn.settimeout(self.drip_interval + 1.0)
            while self._running and (time.time() - start) < self.max_session_sec:
                if guardrails.listeners_paused():
                    break
                try:
                    conn.sendall(DRIP)
                except OSError:
                    break
                time.sleep(self.drip_interval)
                try:
                    conn.recv(256)
                except (socket.timeout, OSError):
                    pass
        finally:
            guardrails.session_release("tarpit", source_ip)
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

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        logger.info("Tarpit on %s:%d", self.listen_addr, self.port)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> Dict:
        return {"name": "tarpit", "port": self.port, "running": self._running, "drip_interval": self.drip_interval}


class TarpitManager:
    def __init__(
        self,
        ports: List[int],
        listen_addr: str = "127.0.0.1",
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
