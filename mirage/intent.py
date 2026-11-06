"""Attack-intent narrative — honest confidence (Stage 4 item 13–14)."""

from __future__ import annotations

from typing import Any, Dict, List

# Confidence is about "attacker engaged a decoy", NOT "real account was compromised".
INTENT_RULES: List[Dict[str, Any]] = [
    {
        "match": ["ssh_jail_command", "telnet_jail_command"],
        "intent": "interactive_decoy_session",
        "verdict": (
            "Commands were typed inside a Mirage decoy shell. This proves interaction with "
            "a trap, not compromise of a real host or real account."
        ),
        "confidence": 0.92,
        "attack": ["T1059", "T1021.004"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["ssh_jail_login", "telnet_jail_login"],
        "intent": "credential_submission_to_decoy",
        "verdict": (
            "Credentials were submitted to a decoy login. Treat as hostile intent against the "
            "decoy surface — not as proof a production account password is known or valid."
        ),
        "confidence": 0.90,
        "attack": ["T1110", "T1078"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["http_login_capture", "web_api_hit"],
        "intent": "web_credential_or_path_probe",
        "verdict": (
            "Decoy web/API path or login form was used. High signal for scanning or credential "
            "stuffing against the trap — not confirmed access to a real application."
        ),
        "confidence": 0.88,
        "attack": ["T1190", "T1110", "T1595.002"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["dns_canary_lookup"],
        "intent": "internal_recon",
        "verdict": "A decoy internal DNS name was queried — recon signal before any real service."
        ,
        "confidence": 0.85,
        "attack": ["T1018", "T1046"],
        "severity": "medium",
        "scope": "decoy_only",
    },
    {
        "match": ["tarpit_hold"],
        "intent": "automated_scan",
        "verdict": "Source held in TCP tarpit — typical of automated scanners."
        ,
        "confidence": 0.75,
        "attack": ["T1046", "T1595"],
        "severity": "low",
        "scope": "decoy_only",
    },
    {
        "match": ["cloud_decoy_access"],
        "intent": "cloud_data_hunt",
        "verdict": (
            "Decoy cloud listing was accessed. Indicates interest in backup/export-shaped data; "
            "not access to the client's real cloud account."
        ),
        "confidence": 0.90,
        "attack": ["T1530", "T1580"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["decoy_smb_connect", "decoy_smb_negotiate"],
        "intent": "share_recon",
        "verdict": (
            "Low-interaction SMB decoy was contacted (not a full file server). Share recon signal only."
        ),
        "confidence": 0.80,
        "attack": ["T1021.002", "T1135"],
        "severity": "medium",
        "scope": "decoy_only",
    },
    {
        "match": ["beacon_hit"],
        "intent": "honeytoken_callback",
        "verdict": (
            "A planted honeytoken or document web-bug phoned home. Strong signal the token left "
            "the expected path or was opened — still not proof of a real production secret leak."
        ),
        "confidence": 0.93,
        "attack": ["T1552", "T1078"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["canary_opened"],
        "intent": "decoy_file_read",
        "verdict": (
            "Decoy file access time or open signal advanced without content change — likely read/open. "
            "Signal quality depends on filesystem atime support."
        ),
        "confidence": 0.70,
        "attack": ["T1005", "T1083"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["canary_modified", "canary_deleted", "trail_hop"],
        "intent": "decoy_file_tamper",
        "verdict": "Planted decoy document was modified, deleted, or a breadcrumb trail hop was followed.",
        "confidence": 0.88,
        "attack": ["T1005", "T1083"],
        "severity": "high",
        "scope": "decoy_only",
    },
    {
        "match": ["ssh_jail", "telnet_jail", "decoy_"],
        "intent": "decoy_service_touch",
        "verdict": "Interaction with a Mirage decoy service. Legitimate users should not touch these surfaces.",
        "confidence": 0.72,
        "attack": ["T1046"],
        "severity": "medium",
        "scope": "decoy_only",
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
    path = (details.get("path") or "").lower()

    for rule in INTENT_RULES:
        for m in rule["match"]:
            if m in et or m in service or m in canary or m in path:
                return {
                    "intent": rule["intent"],
                    "verdict": rule["verdict"],
                    "confidence": rule["confidence"],
                    "attack_techniques": rule["attack"],
                    "severity": rule["severity"],
                    "scope": rule.get("scope", "decoy_only"),
                    "raw_event_type": event.get("event_type"),
                    "disclaimer": (
                        "Confidence refers to decoy engagement only. "
                        "It does not assert real account compromise or real data breach."
                    ),
                }

    return {
        "intent": "unknown_decoy_interaction",
        "verdict": "Unclassified interaction with a deception asset.",
        "confidence": 0.45,
        "attack_techniques": [],
        "severity": "medium",
        "scope": "decoy_only",
        "raw_event_type": event.get("event_type"),
        "disclaimer": (
            "Confidence refers to decoy engagement only. "
            "It does not assert real account compromise or real data breach."
        ),
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
            "disclaimer": "Mirage reports decoy engagement, not proven production compromise.",
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
        "disclaimer": "Mirage reports decoy engagement, not proven production compromise.",
    }
