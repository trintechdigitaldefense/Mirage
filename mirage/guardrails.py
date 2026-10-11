"""Fail-safe & anti-abuse guardrails — Feature 12.

Hard limits baked in so Mirage cannot be used as a DDoS reflector,
pivot point, or data store for real secrets:

- Decoy services never relay traffic onward
- Never store real client production data in decoys
- Never respond from real hostnames by default
- Per-source rate limits
- Circuit-breaker kill switch

These limits ARE the legal story. Document them in the ROE pack.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Dict, Optional, Tuple

logger = logging.getLogger("mirage.guardrails")

# Doctrine constants — do not weaken without legal review
MAX_RESPONSE_BYTES = 65536          # decoy responses stay small
DEFAULT_RATE_LIMIT = 30             # events per window per source
DEFAULT_RATE_WINDOW = 60            # seconds
CIRCUIT_BREAKER_THRESHOLD = 500     # total events in window → trip
CIRCUIT_BREAKER_WINDOW = 60


class RateLimiter:
    """Per-source sliding window rate limiter."""

    def __init__(self, limit: int = DEFAULT_RATE_LIMIT, window: int = DEFAULT_RATE_WINDOW):
        self.limit = limit
        self.window = window
        self._hits: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._hits[source]
            # drop expired
            self._hits[source] = [t for t in bucket if now - t < self.window]
            if len(self._hits[source]) >= self.limit:
                return False
            self._hits[source].append(now)
            return True

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self._hits.items()}


class CircuitBreaker:
    """Global kill switch when decoy traffic looks abusive."""

    def __init__(
        self,
        threshold: int = CIRCUIT_BREAKER_THRESHOLD,
        window: int = CIRCUIT_BREAKER_WINDOW,
    ):
        self.threshold = threshold
        self.window = window
        self._events: list = []
        self._tripped = False
        self._trip_reason = ""
        self._lock = threading.Lock()

    def record(self) -> bool:
        """Record an event. Returns True if still healthy, False if tripped."""
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
            logger.info("Circuit breaker reset")

    def status(self) -> dict:
        with self._lock:
            return {
                "tripped": self._tripped,
                "reason": self._trip_reason,
                "events_in_window": len(self._events),
                "threshold": self.threshold,
                "window": self.window,
            }


# Process-wide singletons used by alert/service paths
_rate_limiter = RateLimiter()
_circuit = CircuitBreaker()
_guardrails_enabled = True


def configure(
    rate_limit: int = DEFAULT_RATE_LIMIT,
    rate_window: int = DEFAULT_RATE_WINDOW,
    breaker_threshold: int = CIRCUIT_BREAKER_THRESHOLD,
    breaker_window: int = CIRCUIT_BREAKER_WINDOW,
    enabled: bool = True,
):
    global _rate_limiter, _circuit, _guardrails_enabled
    _rate_limiter = RateLimiter(rate_limit, rate_window)
    _circuit = CircuitBreaker(breaker_threshold, breaker_window)
    _guardrails_enabled = enabled


def check_source(source_ip: str) -> Tuple[bool, str]:
    """Return (allowed, reason). Call before emitting/responding."""
    if not _guardrails_enabled:
        return True, ""
    if _circuit.is_tripped():
        return False, _circuit.reason() or "circuit breaker open"
    if not _circuit.record():
        return False, _circuit.reason()
    if source_ip and not _rate_limiter.allow(source_ip):
        return False, f"rate limit exceeded for {source_ip}"
    return True, ""


def assert_no_egress_doctrine() -> str:
    """Human-readable doctrine statement for ROE / reports."""
    return (
        "Mirage guardrails (Feature 12): decoy processes do not relay traffic, "
        "do not store real production credentials or data, do not bind real "
        "production hostnames as authoritative, apply per-source rate limits, "
        "and halt all listeners if the circuit breaker trips. Deception is "
        "passive observation only."
    )


def status() -> dict:
    return {
        "enabled": _guardrails_enabled,
        "circuit_breaker": _circuit.status(),
        "rate_limiter_sources": len(_rate_limiter.stats()),
        "doctrine": assert_no_egress_doctrine(),
    }


def reset_breaker():
    _circuit.reset()
