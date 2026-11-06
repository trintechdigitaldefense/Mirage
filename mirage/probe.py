"""Post-bind health probes — prove a listener is actually reachable (Stage 2)."""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional, Tuple


def probe_tcp(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    if not port:
        return False, "no port"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, "ok"
    except OSError as e:
        return False, str(e)[:80]


def probe_udp(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    """Best-effort UDP probe: send empty datagram; success = socket sent (not full protocol)."""
    if not port:
        return False, "no port"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00\x00", (host, int(port)))
        s.close()
        return True, "udp_sent"
    except OSError as e:
        return False, str(e)[:80]


def probe_registry_rows(
    rows: List[Dict[str, Any]],
    *,
    host: str = "127.0.0.1",
    timeout: float = 1.0,
) -> List[Dict[str, Any]]:
    """Attach probe_ok / probe_detail to each RUNNING row with a port."""
    out = []
    for r in rows:
        row = dict(r)
        port = int(row.get("port") or 0)
        state = (row.get("state") or "").upper()
        name = (row.get("name") or "").lower()
        if state != "RUNNING" or not port:
            row["probe_ok"] = None
            row["probe_detail"] = "skipped"
            out.append(row)
            continue
        if name in ("dns_canary", "dns"):
            ok, detail = probe_udp(host, port, timeout)
        else:
            ok, detail = probe_tcp(host, port, timeout)
        row["probe_ok"] = ok
        row["probe_detail"] = detail
        out.append(row)
    return out


def probe_summary(probed: List[Dict[str, Any]]) -> Dict[str, Any]:
    checked = [r for r in probed if r.get("probe_ok") is not None]
    ok = sum(1 for r in checked if r.get("probe_ok"))
    fail = sum(1 for r in checked if r.get("probe_ok") is False)
    return {"probed": len(checked), "ok": ok, "fail": fail, "healthy": fail == 0 and ok > 0}
