"""Central service registry for Mirage deception listeners (Stage 2).

Every decoy should register so deploy can report RUNNING / FAILED / DISABLED
and stop can shut them down reliably.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mirage.registry")


class ServiceState(str, Enum):
    DISABLED = "DISABLED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    DEGRADED = "DEGRADED"


@dataclass
class ServiceRecord:
    name: str
    port: int = 0
    state: ServiceState = ServiceState.STOPPED
    error: str = ""
    stop_fn: Optional[Callable[[], None]] = field(default=None, repr=False)
    meta: Dict[str, Any] = field(default_factory=dict)


class ServiceRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._services: Dict[str, ServiceRecord] = {}

    def register(
        self,
        name: str,
        port: int = 0,
        state: ServiceState = ServiceState.RUNNING,
        error: str = "",
        stop_fn: Optional[Callable[[], None]] = None,
        **meta,
    ):
        with self._lock:
            key = f"{name}:{port}" if port else name
            self._services[key] = ServiceRecord(
                name=name,
                port=port,
                state=state,
                error=error,
                stop_fn=stop_fn,
                meta=meta,
            )

    def set_state(self, name: str, state: ServiceState, error: str = "", port: int = 0):
        with self._lock:
            key = f"{name}:{port}" if port and f"{name}:{port}" in self._services else None
            if key is None:
                for k, rec in self._services.items():
                    if rec.name == name:
                        key = k
                        break
            if key and key in self._services:
                self._services[key].state = state
                self._services[key].error = error

    def stop_all(self):
        with self._lock:
            items = list(self._services.items())
        for key, rec in items:
            if rec.stop_fn:
                try:
                    rec.stop_fn()
                except Exception as e:
                    logger.warning("stop %s failed: %s", key, e)
            self.set_state(rec.name, ServiceState.STOPPED, port=rec.port)

    def status_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": k,
                    "name": r.name,
                    "port": r.port,
                    "state": r.state.value,
                    "error": r.error,
                    **r.meta,
                }
                for k, r in self._services.items()
            ]

    def summary(self) -> Dict[str, Any]:
        rows = self.status_list()
        counts: Dict[str, int] = {}
        for r in rows:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        healthy = counts.get("RUNNING", 0)
        failed = counts.get("FAILED", 0)
        return {
            "total": len(rows),
            "running": healthy,
            "failed": failed,
            "counts": counts,
            "healthy": failed == 0 and healthy > 0,
        }

    def clear(self):
        with self._lock:
            self._services.clear()


# Process-wide registry used by deploy
REGISTRY = ServiceRegistry()
