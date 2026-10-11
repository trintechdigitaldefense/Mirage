"""Attack-intent narrative engine for Mirage."""

from __future__ import annotations

from typing import Any, Dict, List


INTENT_RULES: List[Dict[str, Any]] = [
    {
        "match": ["ssh_jail_command"],
        "intent": "interactive_compromise",
        "verdict": "Attacker authenticated to the decoy SSH and typed commands — full interactive session captured.",
        "confidence": 0.98,
        "attack": ["T1059", "T1021.004"],
        "severity": "critical",
    },
    {
        "match": ["ssh_jail_login"],
        "intent": "credential_access",
        "verdict": "Someone submitted credentials to the decoy SSH service and was dropped into the jail.",
        "confidence": 0.95,
        "attack": ["T1110", "T1078", "T1021.004"],
        "severity": "critical",
    },
    {
        "match": ["ssh_jail_session_end"],
        "intent": "interactive_compromise",
        "verdict": "Decoy SSH session closed. Review the command transcript for tools, targets and intent.",
        "confidence": 0.90,
        "attack": ["T1059", "T1021.004"],
        "severity": "high",
    },
    {
        "match": ["ssh_jail_connect", "ssh_jail"],
        "intent": "credential_access",
        "verdict": "Connection to the credential-harvesting SSH jail — attacker is probing interactive remote access.",
        "confidence": 0.88,
        "attack": ["T1021.004"],
        "severity": "high",
    },
    {
        "match": ["cloud_decoy_access", "cloud_decoy"],
        "intent": "cloud_data_hunt",
        "verdict": "Someone listed or fetched from the decoy cloud bucket — hunting backups or exported data.",
        "confidence": 0.92,
        "attack": ["T1530", "T1580"],
        "severity": "critical",
    },
    {
        "match": ["decoy_ssh_connect", "decoy_ssh_data"],
        "intent": "credential_access",
        "verdict": "Someone was probing for remote access credentials, not just scanning.",
        "confidence": 0.85,
        "attack": ["T1110", "T1021.004"],
        "severity": "high",
    },
    {
        "match": ["decoy_rdp_connect", "decoy_rdp_data"],
        "intent": "credential_access",
        "verdict": "Remote Desktop probe — attacker was hunting interactive access.",
        "confidence": 0.80,
        "attack": ["T1021.001"],
        "severity": "high",
    },
    {
        "match": ["decoy_mysql_connect", "decoy_mysql_data"],
        "intent": "data_discovery",
        "verdict": "Database service was touched. Classic sign of data-oriented reconnaissance.",
        "confidence": 0.75,
        "attack": ["T1046", "T1213"],
        "severity": "high",
    },
    {
        "match": ["decoy_http_connect", "decoy_http_data", "decoy_https_connect", "decoy_https_data"],
        "intent": "web_recon",
        "verdict": "Web service interaction — looking for admin panels or misconfigurations.",
        "confidence": 0.70,
        "attack": ["T1190", "T1595"],
        "severity": "medium",
    },
    {
        "match": ["decoy_ftp_connect", "decoy_ftp_data"],
        "intent": "file_transfer_probe",
        "verdict": "FTP service touched. Possible attempt to stage or exfiltrate files.",
        "confidence": 0.75,
        "attack": ["T1048", "T1021"],
        "severity": "medium",
    },
    {
        "match": ["decoy_smb_connect", "decoy_smb_negotiate"],
        "intent": "share_recon",
        "verdict": "Decoy file share was probed. Looking for Finance/HR/Backups data or credentials on mapped drives.",
        "confidence": 0.85,
        "attack": ["T1021.002", "T1135"],
        "severity": "high",
    },
    {
        "match": ["beacon_hit"],
        "intent": "credential_exfil_test",
        "verdict": "A planted honey token was used or fetched from outside the expected path — data may have left the network.",
        "confidence": 0.95,
        "attack": ["T1552", "T1078"],
        "severity": "critical",
    },
    {
        "match": ["trail_hop"],
        "intent": "lateral_follow",
        "verdict": "Attacker followed a breadcrumb trail between decoys — they are actively mapping the environment, not just scanning.",
        "confidence": 0.90,
        "attack": ["T1083", "T1021"],
        "severity": "critical",
    },
    {
        "match": ["canary_modified", "canary_deleted"],
        "intent": "file_theft_or_tamper",
        "verdict": "A planted decoy document was opened, changed or deleted. Strong signal of hands-on activity.",
        "confidence": 0.90,
        "attack": ["T1005", "T1083"],
        "severity": "critical",
    },
    {
        "match": ["canary_"],
        "intent": "decoy_interaction",
        "verdict": "Interaction with a canary/decoy asset that legitimate users should never touch.",
        "confidence": 0.80,
        "attack": ["T1083"],
        "severity": "high",
    },
]


def classify_event(event: Dict[str, Any]) -> Dict[str, Any]:
    et = (event.get("event_type") or "").lower()
    details = event.get("details") or {}
    if isinstance(details, str):
        try:
            import json
            details = json.loads(details)
        except Exception:
            details = {}

    service = (details.get("service") or "").lower()
    canary = (details.get("canary") or "").lower()

    for rule in INTENT_RULES:
        for m in rule["match"]:
            if m in et or m in service or m in canary:
                return {
                    "intent": rule["intent"],
                    "verdict": rule["verdict"],
                    "confidence": rule["confidence"],
                    "attack_techniques": rule["attack"],
                    "severity": rule["severity"],
                    "raw_event_type": event.get("event_type"),
                }

    return {
        "intent": "unknown_interaction",
        "verdict": "Unclassified interaction with a deception asset. Still high-signal — legitimate users do not touch decoys.",
        "confidence": 0.50,
        "attack_techniques": [],
        "severity": "medium",
        "raw_event_type": event.get("event_type"),
    }


def classify_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = []
    for e in events:
        c = classify_event(e)
        row = dict(e)
        row["classification"] = c
        enriched.append(row)
    return enriched


def summarize_intents(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return {
            "total_events": 0,
            "primary_intent": None,
            "verdict": "No attacker interaction observed with deception assets during this period.",
            "intents": {},
        }

    classified = classify_events(events)
    counts: Dict[str, int] = {}
    highest = None
    for e in classified:
        intent = e["classification"]["intent"]
        counts[intent] = counts.get(intent, 0) + 1
        if highest is None or e["classification"]["confidence"] > highest["classification"]["confidence"]:
            highest = e

    primary = max(counts, key=counts.get) if counts else None
    primary_verdict = highest["classification"]["verdict"] if highest else ""

    return {
        "total_events": len(events),
        "primary_intent": primary,
        "verdict": primary_verdict,
        "intents": counts,
        "classified_events": classified,
    }
