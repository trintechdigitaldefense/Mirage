"""Mirage triggers — alert/persistence layer."""

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger("mirage.triggers")


class Trigger:
    """A single decoy artifact that triggers an alert when interacted with."""

    def __init__(self, name: str, path: str = "", content: str = "", alert_type: str = "decoy_touched"):
        self.name = name
        self.path = path
        self.content = content
        self.alert_type = alert_type
        self.checksum = hashlib.sha256(content.encode()).hexdigest() if content else ""
        self._persisted = False

    def deploy(self, base_dir: str = "/tmp/mirage_decoys") -> str:
        os.makedirs(base_dir, exist_ok=True)
        file_path = os.path.join(base_dir, self.path or self.name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(self.content)
        self.checksum = hashlib.sha256(self.content.encode()).hexdigest()
        self._persisted = True
        logger.info("Trigger deployed: %s at %s", self.name, file_path)
        return file_path

    def verify(self) -> bool:
        if not self._persisted:
            return False
        file_path = os.path.join("/tmp/mirage_decoys", self.path or self.name)
        if not os.path.exists(file_path):
            return False
        with open(file_path) as f:
            current = f.read()
        return hashlib.sha256(current.encode()).hexdigest() == self.checksum

    def check(self, base_dir: str = "/tmp/mirage_decoys") -> dict | None:
        """Returns alert dict if tampered, else None."""
        file_path = os.path.join(base_dir, self.path or self.name)
        if not os.path.exists(file_path):
            return {"type": self.alert_type, "trigger": self.name, "event": "deleted"}
        with open(file_path) as f:
            content = f.read()
        if hashlib.sha256(content.encode()).hexdigest() != self.checksum:
            return {"type": self.alert_type, "trigger": self.name, "event": "modified"}
        return None


class TriggerManager:
    """Manages a set of decoy triggers with optional persistence watcher."""

    def __init__(self, base_dir: str = "/tmp/mirage_decoys", on_alert=None):
        self.base_dir = base_dir
        self.on_alert = on_alert
        self.triggers: list[Trigger] = []
        self._watcher_thread = None
        self._watching = False

    def add(self, trigger: Trigger):
        self.triggers.append(trigger)

    def deploy_all(self):
        out = []
        for t in self.triggers:
            p = t.deploy(self.base_dir)
            out.append(p)
        logger.info("All triggers deployed (%d total)", len(self.triggers))
        return out

    def check_all(self) -> list[dict]:
        current_state_path = os.path.join(self.base_dir, ".mirage_check_state.json")
        if os.path.exists(current_state_path):
            try:
                with open(current_state_path) as f:
                    _ = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        alerts = []
        for t in self.triggers:
            result = t.check(self.base_dir)
            if result:
                alerts.append(result)
                if self.on_alert:
                    self.on_alert("trigger_alert", result)
        return alerts

    def watch(self, interval: float = 5.0):
        """Continuously check triggers in a background thread."""

        def loop():
            while self._watching:
                alerts = self.check_all()
                if alerts:
                    logger.warning("Trigger alerts detected: %s", alerts)
                time.sleep(interval)

        self._watching = True
        self._watcher_thread = threading.Thread(target=loop, daemon=True)
        self._watcher_thread.start()
        logger.info("Trigger watcher started (interval=%ss)", interval)

    def stop_watching(self):
        self._watching = False
        logger.info("Trigger watcher stopped")

    def cleanup(self):
        import shutil
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)
            logger.info("All trigger artifacts cleaned up")

    def status(self) -> dict:
        return {
            "total_triggers": len(self.triggers),
            "active_triggers": [t.name for t in self.triggers],
            "watching": self._watching,
        }
