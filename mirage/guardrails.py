"""Fail-safe & anti-abuse guardrails — Feature 12 (v2.5 enforcement).

Listeners MUST call accept_allowed() before processing a new session.
Circuit breaker trips pause listeners — not only suppress alerts.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Callable, Dict, List, Tuple

logger = logging.getLogger("mirage.guardrails")

MAX_RESPONSE_BYTES = 65536
DEFAULT_RATE_LIMIT = 30
DEFAULT_RATE_WINDOW = 60
CIRCUIT_BREAKER_THRESHOLD = 500
CIRCUIT_BREAKER_WINDOW = 60
DEFAULT_MAX_CONCURRENT_GLOBAL = 200
DEFAULT_MAX_CONCURRENT_PER_SERVICE = 50
DEFAULT_MAX_PER_SOURCE = 20


class RateLimiter:
    def __init__(self, limit: int = DEFAULT_RATE_LIMIT, window: int = DEFAULT_RATE_WINDOW):
        self.limit = limit
        self.window = window
        self._hits: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.time()
        with self._lock:
            self._hits[source] = [t for t in self._hits[source] if now - t < self.window]
            if len(self._hits[source]) >= self.limit:
                return False
            self._hits[source].append(now)
            return True

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self._hits.items()}


class CircuitBreaker:
    def __init__(self, threshold: int = CIRCUIT_BREAKER_THRESHOLD, window: int = CIRCUIT_BREAKER_WINDOW):
        self.threshold = threshold
        self.window = window
        self._events: list = []
        self._tripped = False
        self._trip_reason = ""
        self._lock = threading.Lock()
        self._on_trip: List[Callable] = []

    def on_trip(self, cb: Callable):
        self._on_trip.append(cb)

    def record(self) -> bool:
        now = time.time()
        with self._lock:
            if self._tripped:
                return False
            self._events = [t for t in self._events if now - t < self.window]
            self._events.append(now)
            if len(self._events) >= self.threshold:
                self._tripped = True
                self._trip_reason = (
                    f"Circuit breaker: {len(self._events)} events in {self.window}s "
                    f"(threshold {self.threshold})"
                )
                logger.critical(self._trip_reason)
                for cb in self._on_trip:
                    try:
                        cb(self._trip_reason)
                    except Exception:
                        pass
                return False
            return True

    def is_tripped(self) -> bool:
        with self._lock:
            return self._tripped

    def reason(self) -> str:
        with self._lock:
            return self._trip_reason

    def reset(self):
        with self._lock:
            self._tripped = False
            self._trip_reason = ""
            self._events.clear()
            logger.info("Circuit breaker reset — listeners may resume")

    def status(self) -> dict:
        with self._lock:
            return {
                "tripped": self._tripped,
                "reason": self._trip_reason,
                "events_in_window": len(self._events),
                "threshold": self.threshold,
                "window": self.window,
            }


class SessionTracker:
    def __init__(
        self,
        max_global: int = DEFAULT_MAX_CONCURRENT_GLOBAL,
        max_per_service: int = DEFAULT_MAX_CONCURRENT_PER_SERVICE,
        max_per_source: int = DEFAULT_MAX_PER_SOURCE,
    ):
        self.max_global = max_global
        self.max_per_service = max_per_service
        self.max_per_source = max_per_source
        self._global = 0
        self._by_service: Dict[str, int] = defaultdict(int)
        self._by_source: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def try_acquire(self, service: str, source: str) -> Tuple[bool, str]:
        with self._lock:
            if self._global >= self.max_global:
                return False, "global session limit"
            if self._by_service[service] >= self.max_per_service:
                return False, f"service limit ({service})"
            if source and self._by_source[source] >= self.max_per_source:
                return False, f"per-source session limit ({source})"
            self._global += 1
            self._by_service[service] += 1
            if source:
                self._by_source[source] += 1
            return True, ""

    def release(self, service: str, source: str):
        with self._lock:
            self._global = max(0, self._global - 1)
            self._by_service[service] = max(0, self._by_service[service] - 1)
            if source:
                self._by_source[source] = max(0, self._by_source[source] - 1)

    def status(self) -> dict:
        with self._lock:
            return {
                "active_global": self._global,
                "max_global": self.max_global,
                "by_service": dict(self._by_service),
                "max_per_service": self.max_per_service,
                "max_per_source": self.max_per_source,
            }


_rate_limiter = RateLimiter()
_circuit = CircuitBreaker()
_sessions = SessionTracker()
_guardrails_enabled = True
_listeners_paused = False
_pause_callbacks: List[Callable] = []


def configure(
    rate_limit: int = DEFAULT_RATE_LIMIT,
    rate_window: int = DEFAULT_RATE_WINDOW,
    breaker_threshold: int = CIRCUIT_BREAKER_THRESHOLD,
    breaker_window: int = CIRCUIT_BREAKER_WINDOW,
    max_global: int = DEFAULT_MAX_CONCURRENT_GLOBAL,
    max_per_service: int = DEFAULT_MAX_CONCURRENT_PER_SERVICE,
    max_per_source: int = DEFAULT_MAX_PER_SOURCE,
    enabled: bool = True,
):
    global _rate_limiter, _circuit, _sessions, _guardrails_enabled, _listeners_paused
    _rate_limiter = RateLimiter(rate_limit, rate_window)
    _circuit = CircuitBreaker(breaker_threshold, breaker_window)
    _sessions = SessionTracker(max_global, max_per_service, max_per_source)
    _guardrails_enabled = enabled
    _listeners_paused = False

    def _on_trip(reason: str):
        global _listeners_paused
        _listeners_paused = True
        logger.critical("Listeners PAUSED: %s", reason)
        for cb in list(_pause_callbacks):
            try:
                cb(reason)
            except Exception:
                pass

    _circuit.on_trip(_on_trip)


def register_pause_callback(cb: Callable):
    _pause_callbacks.append(cb)


def listeners_paused() -> bool:
    return _listeners_paused or _circuit.is_tripped()


def accept_allowed(service: str, source_ip: str = "") -> Tuple[bool, str]:
    """Call BEFORE handling a new connection."""
    if not _guardrails_enabled:
        return True, ""
    if listeners_paused():
        return False, _circuit.reason() or "listeners paused (circuit breaker)"
    if not _circuit.record():
        return False, _circuit.reason()
    if source_ip and not _rate_limiter.allow(source_ip):
        return False, f"rate limit exceeded for {source_ip}"
    ok, reason = _sessions.try_acquire(service or "unknown", source_ip or "")
    if not ok:
        return False, reason
    return True, ""


def session_release(service: str, source_ip: str = ""):
    _sessions.release(service or "unknown", source_ip or "")


def check_source(source_ip: str) -> Tuple[bool, str]:
    if not _guardrails_enabled:
        return True, ""
    if _circuit.is_tripped() or _listeners_paused:
        return False, _circuit.reason() or "circuit breaker open"
    if not _circuit.record():
        return False, _circuit.reason()
    if source_ip and not _rate_limiter.allow(source_ip):
        return False, f"rate limit exceeded for {source_ip}"
    return True, ""


def assert_no_egress_doctrine() -> str:
    return (
        "Mirage guardrails (v2.5): decoys do not relay traffic; secrets are redacted; "
        "per-source rate limits and session caps apply at accept time; circuit breaker "
        "pauses listeners. Deception is passive observation only."
    )


def status() -> dict:
    return {
        "enabled": _guardrails_enabled,
        "listeners_paused": listeners_paused(),
        "circuit_breaker": _circuit.status(),
        "sessions": _sessions.status(),
        "rate_limiter_sources": len(_rate_limiter.stats()),
        "doctrine": assert_no_egress_doctrine(),
    }


def reset_breaker():
    global _listeners_paused
    _circuit.reset()
    _listeners_paused = False
