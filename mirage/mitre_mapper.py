"""MITRE ATT&CK automated mapper — structured SIEM-ready events.

Maps Mirage event types to technique IDs and streams JSON lines to
~/.mirage/siem_events.jsonl for dashboards / external SIEM.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir
from .intent import classify_event

# Direct event_type → techniques (supplements intent engine)
TECHNIQUE_MAP: Dict[str, List[str]] = {
    "ssh_jail_command": ["T1059", "T1021.004"],
    "ssh_jail_login": ["T1110", "T1078", "T1021.004"],
    "telnet_jail_command": ["T1059", "T1021.004"],
    "telnet_jail_login": ["T1110", "T1078"],
    "http_login_capture": ["T1110", "T1078"],
    "web_api_hit": ["T1190", "T1595.002"],
    "dns_canary_lookup": ["T1018", "T1046"],
    "tarpit_hold": ["T1046", "T1595"],
    "decoy_smb_connect": ["T1021.002", "T1135"],
    "beacon_hit": ["T1552", "T1078"],
    "trail_hop": ["T1083", "T1021"],
    "canary_modified": ["T1005", "T1083"],
    "cloud_decoy_access": ["T1530", "T1580"],
    "attack_profile": ["T1046", "T1595"],
    "firewall_drop": ["T1095"],  # informational — defender action
}

TECHNIQUE_NAMES = {
    "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1021.004": "Remote Services: SSH",
    "T1021.001": "Remote Services: RDP",
    "T1021.002": "Remote Services: SMB",
    "T1190": "Exploit Public-Facing Application",
    "T1595": "Active Scanning",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1018": "Remote System Discovery",
    "T1083": "File and Directory Discovery",
    "T1005": "Data from Local System",
    "T1552": "Unsecured Credentials",
    "T1530": "Data from Cloud Storage",
    "T1580": "Cloud Infrastructure Discovery",
    "T1135": "Network Share Discovery",
    "T1213": "Data from Information Repositories",
}


def map_event(event_type: str, details: Optional[Dict] = None) -> Dict[str, Any]:
    details = details or {}
    techniques = list(TECHNIQUE_MAP.get(event_type, []))
    # Enrich via intent classifier
    cls = classify_event({"event_type": event_type, "details": details})
    for t in cls.get("attack_techniques") or []:
        if t not in techniques:
            techniques.append(t)
    named = [
        {"id": t, "name": TECHNIQUE_NAMES.get(t, t)}
        for t in techniques
    ]
    return {
        "event_type": event_type,
        "intent": cls.get("intent"),
        "severity": cls.get("severity") or details.get("severity") or "medium",
        "confidence": cls.get("confidence"),
        "mitre_techniques": named,
        "technique_ids": techniques,
        "verdict": cls.get("verdict"),
    }


def stream_siem(
    event_type: str,
    source_ip: str = "",
    details: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Append one SIEM-ready JSON line; return the record."""
    mapped = map_event(event_type, details)
    record = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "Mirage",
        "source_ip": source_ip,
        "details": details or {},
        **mapped,
    }
    path = ensure_data_dir() / "siem_events.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass
    return record
