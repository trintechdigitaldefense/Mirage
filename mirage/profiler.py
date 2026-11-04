"""Attack pattern profiling — sequence behaviour across Mirage decoys.

When one IP hits multiple decoys, classify: port sweeper, credential stuffing,
manual recon, botnet scan, etc. Emits structured profile events for reports
and Sentinel.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

_lock = threading.Lock()
# ip -> list of (ts, event_type, service)
_history: Dict[str, List[tuple]] = defaultdict(list)
_WINDOW = 600  # 10 minutes
_last_profile: Dict[str, float] = {}


def _prune(ip: str, now: float):
    _history[ip] = [(t, e, s) for t, e, s in _history[ip] if now - t <= _WINDOW]


def record(
    event_type: str,
    source_ip: str,
    details: Optional[Dict[str, Any]] = None,
    on_profile: Optional[Callable] = None,
) -> Optional[Dict[str, Any]]:
    """Record an event and optionally emit a profile if threshold met."""
    if not source_ip or source_ip in ("local", "127.0.0.1", "::1", "unknown"):
        return None
    details = details or {}
    service = (details.get("service") or event_type or "").lower()
    now = time.time()

    with _lock:
        _prune(source_ip, now)
        _history[source_ip].append((now, event_type, service))
        events = list(_history[source_ip])

        # Cooldown per IP profiles
        if now - _last_profile.get(source_ip, 0) < 60:
            return None

        unique_services = {s for _, _, s in events if s}
        unique_types = {e for _, e, _ in events}
        count = len(events)

        if count < 2 and len(unique_services) < 2:
            return None

        profile = _classify(count, unique_services, unique_types, events)
        _last_profile[source_ip] = now

    if on_profile:
        try:
            on_profile(
                event_type="attack_profile",
                source_ip=source_ip,
                details=profile,
            )
        except Exception:
            pass
    return profile


def _classify(
    count: int,
    services: set,
    types: set,
    events: List[tuple],
) -> Dict[str, Any]:
    svc = sorted(services)
    type_str = " ".join(sorted(types)).lower()

    # Credential-oriented
    if any(x in type_str for x in ("ssh_jail_login", "http_login", "credential", "redis", "mysql", "postgres")):
        if count >= 3:
            label = "credential_stuffing"
            techniques = ["T1110", "T1078"]
            severity = "critical"
        else:
            label = "credential_probe"
            techniques = ["T1110"]
            severity = "high"
    # Many distinct services quickly → port sweeper / automated scan
    elif len(services) >= 4 or count >= 8:
        label = "port_sweeper"
        techniques = ["T1046", "T1595"]
        severity = "high"
    elif len(services) >= 2 and count >= 3:
        label = "automated_recon"
        techniques = ["T1046", "T1595.002"]
        severity = "high"
    elif "dns_canary" in type_str or "dns_canary_lookup" in type_str:
        label = "internal_dns_recon"
        techniques = ["T1018", "T1046"]
        severity = "high"
    elif "tarpit" in type_str:
        label = "scanner_held"
        techniques = ["T1046"]
        severity = "medium"
    elif "trail_hop" in type_str or "beacon" in type_str:
        label = "manual_follow_through"
        techniques = ["T1083", "T1021"]
        severity = "critical"
    else:
        label = "manual_reconnaissance"
        techniques = ["T1595"]
        severity = "medium"

    return {
        "profile": label,
        "event_count": count,
        "services": svc,
        "attack_techniques": techniques,
        "severity": severity,
        "window_sec": _WINDOW,
        "summary": f"{label} across {len(services)} decoy service(s) ({count} events)",
    }


def snapshot(source_ip: str = "") -> Dict[str, Any]:
    with _lock:
        if source_ip:
            return {source_ip: list(_history.get(source_ip, []))}
        return {ip: list(ev) for ip, ev in _history.items()}
