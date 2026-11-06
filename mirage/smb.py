"""Decoy SMB shares — low-interaction tripwire (Stage 2 guardrails).

Not a full SMB protocol server. Connection + negotiate probe only.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from . import guardrails

logger = logging.getLogger("mirage.smb")


class FakeSMBShare:
    def __init__(
        self,
        name: str,
        port: int = 4450,
        listen_addr: str = "127.0.0.1",
        share_names: Optional[List[str]] = None,
        on_connect: Optional[Callable] = None,
    ):
        self.name = name
        self.port = port
        self.listen_addr = listen_addr
        self.share_names = share_names or ["Finance", "HR", "Backups"]
        self.on_connect = on_connect
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def _handle(self, conn: socket.socket, addr):
        source_ip = addr[0]
        allowed, reason = guardrails.accept_allowed("smb", source_ip)
        if not allowed:
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            if self.on_connect:
                self.on_connect(
                    event_type="decoy_smb_connect",
                    source_ip=source_ip,
                    details={
                        "service": "smb",
                        "port": self.port,
                        "shares": self.share_names,
                        "source_port": addr[1],
                    },
                )
            conn.settimeout(8.0)
            data = conn.recv(4096)
            if not data:
                return
            dialect_hint = "unknown"
            if b"SMB 2" in data or b"\xfeSMB" in data:
                dialect_hint = "SMB2+"
            elif len(data) > 8 and data[4:8] == b"\xffSMB":
                dialect_hint = "SMB1"
            if self.on_connect:
                self.on_connect(
                    event_type="decoy_smb_negotiate",
                    source_ip=source_ip,
                    details={
                        "service": "smb",
                        "port": self.port,
                        "dialect": dialect_hint,
                        "bytes_received": len(data),
                        "shares": self.share_names,
                    },
                )
            try:
                time.sleep(0.3)
                conn.sendall(b"\x00\x00\x00\x01\x00")
            except OSError:
                pass
        except (socket.timeout, OSError):
            pass
        finally:
            guardrails.session_release("smb", source_ip)
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
            logger.error("Cannot bind SMB decoy on port %d: %s", self.port, e)
            self._running = False
            return False
        self._sock.listen(5)
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
        logger.info("Fake SMB on %s:%d shares=%s", self.listen_addr, self.port, self.share_names)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "port": self.port,
            "running": self._running,
            "shares": self.share_names,
        }


class SMBManager:
    def __init__(
        self,
        port: int = 4450,
        listen_addr: str = "127.0.0.1",
        share_names: Optional[List[str]] = None,
        on_connect: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        self.share_names = share_names or ["Finance", "HR", "Backups"]
        self.on_connect = on_connect
        self._share: Optional[FakeSMBShare] = None

    def deploy(self) -> bool:
        self._share = FakeSMBShare(
            name="smb",
            port=self.port,
            listen_addr=self.listen_addr,
            share_names=self.share_names,
            on_connect=self.on_connect,
        )
        return self._share.start()

    def stop(self):
        if self._share:
            self._share.stop()
            self._share = None

    def status(self) -> List[Dict[str, Any]]:
        if self._share:
            return [self._share.status()]
        return []
