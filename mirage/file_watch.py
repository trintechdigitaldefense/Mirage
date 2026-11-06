"""File access monitoring using metadata polling and change-triggered hashing.

The watcher never reads an unchanged file during a poll. This matters because
reading a file can itself advance atime and create a false canary_opened event.
Polling cannot prove every open on every filesystem (for example noatime
mounts); signal_quality records the evidence source.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mirage.file_watch")


def _file_hash(path: Path, max_bytes: int = 65536) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            digest.update(stream.read(max_bytes))
        return digest.hexdigest()[:16]
    except OSError:
        return ""


def _stat_snapshot(
    path: Path, previous: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Read metadata cheaply; hash only on first sight or metadata changes."""
    try:
        stat = path.stat()
        changed = (
            previous is None
            or stat.st_mtime != previous.get("mtime")
            or stat.st_size != previous.get("size")
            or getattr(stat, "st_ino", 0) != previous.get("inode", 0)
        )
        file_hash = (
            _file_hash(path)
            if changed
            else str(previous.get("hash") or "")
        )
        # Hashing can affect atime. Capture metadata again so our own read
        # does not get misreported as an external open on the next poll.
        if changed:
            stat = path.stat()
        return {
            "mtime": stat.st_mtime,
            "atime": stat.st_atime,
            "size": stat.st_size,
            "inode": getattr(stat, "st_ino", 0),
            "hash": file_hash,
        }
    except OSError:
        return None


class FileAccessWatcher:
    """Watch configured paths for metadata, content, and access-time signals."""

    def __init__(
        self,
        paths: List[str],
        on_event: Optional[Callable] = None,
        poll_interval: float = 2.0,
    ):
        self.paths = [str(path) for path in paths]
        self.on_event = on_event
        self.poll_interval = max(0.5, float(poll_interval))
        self._snap: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # No native inotify backend is currently implemented.
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
        except Exception as exc:
            logger.debug("file_watch emit failed: %s", exc)

    def seed(self):
        for configured_path in self.paths:
            snapshot = _stat_snapshot(Path(configured_path))
            if snapshot:
                self._snap[configured_path] = snapshot

    def _diff(self, path: str, old: Dict[str, Any], new: Dict[str, Any]):
        replaced = new.get("inode") != old.get("inode")
        if (
            replaced
            or new["hash"] != old.get("hash")
            or new["size"] != old.get("size")
            or new["mtime"] != old.get("mtime")
        ):
            self._emit(
                "canary_modified",
                path,
                {
                    "reason": "file_replaced" if replaced else "content_or_metadata",
                    "old_size": old.get("size"),
                    "new_size": new["size"],
                    "old_hash": old.get("hash"),
                    "new_hash": new.get("hash"),
                    "signal_quality": "content_hash",
                },
            )
            return

        if new["atime"] > old.get("atime", 0) + 0.01:
            self._emit(
                "canary_opened",
                path,
                {
                    "reason": "atime_advance",
                    "atime": new["atime"],
                    "signal_quality": "atime",
                    "note": "Filesystem reported access-time change without content change",
                },
            )

    def poll_once(self):
        for configured_path in list(self.paths):
            path = Path(configured_path)
            old = self._snap.get(configured_path)
            if not path.exists():
                if old is not None:
                    self._emit(
                        "canary_deleted",
                        configured_path,
                        {"reason": "missing", "signal_quality": "existence"},
                    )
                    self._snap.pop(configured_path, None)
                continue

            new = _stat_snapshot(path, previous=old)
            if not new:
                continue
            if old is None:
                self._snap[configured_path] = new
                self._emit(
                    "canary_created",
                    configured_path,
                    {"reason": "appeared", "signal_quality": "existence"},
                )
                continue

            self._diff(configured_path, old, new)
            self._snap[configured_path] = new

    def start(self) -> bool:
        if self._running:
            return True
        self.seed()
        self._running = True

        def loop():
            while self._running:
                try:
                    self.poll_once()
                except Exception as exc:
                    logger.exception("file_watch poll failed: %s", exc)
                time.sleep(self.poll_interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        logger.info(
            "FileAccessWatcher on %d paths (poll=%.1fs)",
            len(self.paths),
            self.poll_interval,
        )
        return True

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(1.0, self.poll_interval + 0.5))

    def status(self) -> Dict[str, Any]:
        return {
            "name": "file_watch",
            "paths": len(self.paths),
            "running": self._running,
            "inotify": self._inotify,
            "mode": "metadata-poll+change-triggered-hash",
        }
