"""Decoy SMB shares & mapped drives — Feature 08.

Fake SMB shares that look like Finance, HR and Backups. Connection and
basic session activity are logged. Full protocol fidelity is intentionally
limited — this is a high-signal tripwire, not a production file server.

Passive observation only. No real files are served from production data,
no relay, no egress from the decoy process beyond the alert callback.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mirage.smb")

# Minimal SMB negotiate response fragments (SMB1 dialect list style).
# Enough to look like a Windows share to casual scanners and to capture
# the connection + dialect probe. Not a complete SMB implementation.

SMB_NEGOTIATE_RESPONSE_HEADER = bytes([
    0x00, 0x00, 0x00, 0x35,  # NetBIOS length (placeholder, adjusted)
    0xff, 0x53, 0x4d, 0x42,  # SMB magic
    0x72,                    # Negotiate Protocol
    0x00, 0x00, 0x00, 0x00,  # Status success
    0x98,                    # Flags
    0x53, 0xc8,              # Flags2
    0x00, 0x00,              # PID high
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
    0x00, 0x00,              # Reserved
    0x00, 0x00,              # TID
    0x00, 0x00,              # PID
    0x00, 0x00,              # UID
    0x00, 0x00,              # MID
])


class FakeSMBShare:
    def __init__(
        self,
        name: str,
        port: int = 4450,  # non-privileged default; 445 needs root
        listen_addr: str = "0.0.0.0",
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
        logger.info("SMB connection from %s to decoy shares %s", source_ip, self.share_names)

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

        try:
            conn.settimeout(8.0)
            data = conn.recv(4096)
            if not data:
                return

            preview = data[:64].hex()
            dialect_hint = "unknown"
            if b"SMB 2" in data or b"\xfeSMB" in data:
                dialect_hint = "SMB2+"
            elif data[4:8] == b"\xffSMB":
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
                        "preview_hex": preview,
                        "shares": self.share_names,
                    },
                )

            # Send a short, non-functional response so the client doesn't
            # hang forever. We deliberately do not implement full tree connect.
            try:
                # Simple TCP close after a brief delay looks like a filtered share
                time.sleep(0.3)
                # Optional: send a minimal reject-style payload
                conn.sendall(b"\x00\x00\x00\x01\x00")
            except OSError:
                pass

        except (socket.timeout, OSError):
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
            logger.error("Cannot bind SMB decoy on port %d: %s", self.port, e)
            self._running = False
            return
        self._sock.listen(5)
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
        logger.info(
            "Fake SMB decoy listening on %s:%d shares=%s",
            self.listen_addr, self.port, self.share_names,
        )

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        logger.info("Fake SMB decoy stopped")

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
        listen_addr: str = "0.0.0.0",
        share_names: Optional[List[str]] = None,
        on_connect: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        self.share_names = share_names or ["Finance", "HR", "Backups"]
        self.on_connect = on_connect
        self._share: Optional[FakeSMBShare] = None

    def deploy(self):
        self._share = FakeSMBShare(
            name="smb",
            port=self.port,
            listen_addr=self.listen_addr,
            share_names=self.share_names,
            on_connect=self.on_connect,
        )
        self._share.start()

    def stop(self):
        if self._share:
            self._share.stop()
            self._share = None

    def status(self) -> List[Dict[str, Any]]:
        if self._share:
            return [self._share.status()]
        return []
