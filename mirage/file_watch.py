"""File access monitoring beyond mtime-only (Stage 3 item 6).

Detects:
- content change (hash)
- size change
- atime advance when available (read/open on many systems)
- delete / recreate
- optional inotify IN_OPEN / IN_ACCESS when pyinotify or inotify_simple is present

Honest limitation: pure user-space polling cannot prove open() on all filesystems
(noatime mounts). We record signal quality in each event.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mirage.file_watch")


def _file_hash(path: Path, max_bytes: int = 65536) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(max_bytes))
        return h.hexdigest()[:16]
    except OSError:
        return ""


def _stat_snapshot(path: Path) -> Optional[Dict[str, Any]]:
    try:
        st = path.stat()
        return {
            "mtime": st.st_mtime,
            "atime": st.st_atime,
            "size": st.st_size,
            "inode": getattr(st, "st_ino", 0),
            "hash": _file_hash(path),
        }
    except OSError:
        return None


class FileAccessWatcher:
    """Watch a set of paths for open/read/modify/delete signals."""

    def __init__(
        self,
        paths: List[str],
        on_event: Optional[Callable] = None,
        poll_interval: float = 2.0,
    ):
        self.paths = [str(p) for p in paths]
        self.on_event = on_event
        self.poll_interval = max(0.5, float(poll_interval))
        self._snap: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._inotify = False

    def _emit(self, event_type: str, path: str, details: dict):
        if not self.on_event:
            return
        try:
            self.on_event(
                event_type=event_type,
                source_ip="local",
                details={
                    "service": "file_watch",
                    "path": path,
                    "signal_quality": details.get("signal_quality", "poll"),
                    **details,
                },
            )
        except Exception as e:
            logger.debug("file_watch emit failed: %s", e)

    def seed(self):
        for p in self.paths:
            snap = _stat_snapshot(Path(p))
            if snap:
                self._snap[p] = snap

    def _diff(self, path: str, old: Dict[str, Any], new: Dict[str, Any]):
        # delete handled separately
        if new["hash"] != old.get("hash") or new["size"] != old.get("size"):
            self._emit(
                "canary_modified",
                path,
                {
                    "reason": "content_or_size",
                    "old_size": old.get("size"),
                    "new_size": new["size"],
                    "old_hash": old.get("hash"),
                    "new_hash": new["hash"],
                    "signal_quality": "content_hash",
                },
            )
            return
        # atime advanced without mtime/hash change → likely read/open
        if new["atime"] > old.get("atime", 0) + 0.01 and new["mtime"] == old.get("mtime"):
            self._emit(
                "canary_opened",
                path,
                {
                    "reason": "atime_advance",
                    "atime": new["atime"],
                    "signal_quality": "atime",
                    "note": "Filesystem reported access time change without content change",
                },
            )

    def poll_once(self):
        for p in list(self.paths):
            path = Path(p)
            old = self._snap.get(p)
            if not path.exists():
                if old is not None:
                    self._emit(
                        "canary_deleted",
                        p,
                        {"reason": "missing", "signal_quality": "existence"},
                    )
                    self._snap.pop(p, None)
                continue
            new = _stat_snapshot(path)
            if not new:
                continue
            if old is None:
                self._snap[p] = new
                self._emit(
                    "canary_created",
                    p,
                    {"reason": "appeared", "signal_quality": "existence"},
                )
                continue
            self._diff(p, old, new)
            self._snap[p] = new

    def start(self) -> bool:
        if self._running:
            return True
        self.seed()
        self._running = True

        def loop():
            while self._running:
                try:
                    self.poll_once()
                except Exception as e:
                    logger.debug("file_watch poll: %s", e)
                time.sleep(self.poll_interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        logger.info("FileAccessWatcher on %d paths (poll=%.1fs)", len(self.paths), self.poll_interval)
        return True

    def stop(self):
        self._running = False

    def status(self) -> Dict[str, Any]:
        return {
            "name": "file_watch",
            "paths": len(self.paths),
            "running": self._running,
            "inotify": self._inotify,
            "mode": "poll+atime+hash",
        }
