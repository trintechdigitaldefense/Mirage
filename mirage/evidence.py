"""Legal-grade interaction evidence — Feature 10.

Every interaction logged with timestamp, source, payload hash and ROE
reference, exported as a tamper-evident evidence bundle (SHA-256 manifest).
Usable for police reports, insurance claims and fraud investigations.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir, load_config
from .db import get_recent_events, get_all_events
from .intent import classify_events
from .guardrails import assert_no_egress_doctrine


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _normalize_event(e: Dict[str, Any]) -> Dict[str, Any]:
    details = e.get("details") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {"raw": details}
    payload = json.dumps(details, sort_keys=True, default=str)
    return {
        "id": e.get("id"),
        "timestamp": e.get("timestamp"),
        "event_type": e.get("event_type"),
        "source_ip": e.get("source_ip") or "",
        "severity": e.get("severity") or "high",
        "authorization_ref": e.get("authorization_ref") or "",
        "details": details,
        "payload_sha256": _sha256_text(payload),
    }


def build_evidence_bundle(
    hours: int = 24,
    limit: Optional[int] = None,
    engagement_id: str = "",
) -> Dict[str, Any]:
    """Build an in-memory evidence package ready to export."""
    cfg = load_config()
    org = cfg.get("organization_name") or "Client"
    auth_ref = cfg.get("authorization_ref") or "N/A"

    if limit:
        events = get_all_events(limit=limit)
    else:
        events = get_recent_events(hours=hours)

    normalized = [_normalize_event(e) for e in events]
    classified = classify_events(normalized)

    # Strip classification objects that aren't JSON-stable for hashing
    for row in classified:
        cls = row.get("classification") or {}
        row["intent"] = cls.get("intent")
        row["verdict"] = cls.get("verdict")
        row["attack_techniques"] = cls.get("attack_techniques") or []
        row.pop("classification", None)

    created = datetime.utcnow().isoformat() + "Z"
    engagement_id = engagement_id or f"MIR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    body = {
        "format": "TrinTech-Mirage-Evidence-v1",
        "engagement_id": engagement_id,
        "organization": org,
        "authorization_ref": auth_ref,
        "generated_at": created,
        "generator": "Mirage by TrinTech Digital Defense",
        "doctrine": assert_no_egress_doctrine(),
        "event_count": len(classified),
        "events": classified,
    }

    body_json = json.dumps(body, indent=2, sort_keys=True, default=str)
    body_hash = _sha256_text(body_json)

    manifest = {
        "format": "TrinTech-Evidence-Manifest-v1",
        "engagement_id": engagement_id,
        "organization": org,
        "authorization_ref": auth_ref,
        "generated_at": created,
        "files": [
            {
                "name": "events.json",
                "sha256": body_hash,
                "bytes": len(body_json.encode("utf-8")),
            }
        ],
        "chain_note": (
            "SHA-256 of events.json is the integrity anchor. Any alteration of "
            "event content changes this digest. Matches FortifyOne-style chain."
        ),
        "manifest_sha256": "",
    }
    # Hash the manifest without the self-referential field first
    manifest_for_hash = dict(manifest)
    manifest_for_hash.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = _sha256_text(
        json.dumps(manifest_for_hash, indent=2, sort_keys=True)
    )

    return {
        "engagement_id": engagement_id,
        "body": body,
        "body_json": body_json,
        "body_sha256": body_hash,
        "manifest": manifest,
    }


def export_evidence(
    hours: int = 24,
    limit: Optional[int] = None,
    engagement_id: str = "",
) -> Path:
    """Write a tamper-evident zip under ~/.mirage/evidence/."""
    pkg = build_evidence_bundle(hours=hours, limit=limit, engagement_id=engagement_id)
    out_dir = ensure_data_dir() / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_org = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in (pkg["body"]["organization"] or "client")
    )[:30]
    zip_path = out_dir / f"mirage_evidence_{safe_org}_{stamp}.zip"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("events.json", pkg["body_json"])
        zf.writestr(
            "manifest.json",
            json.dumps(pkg["manifest"], indent=2, sort_keys=True),
        )
        zf.writestr(
            "README.txt",
            (
                "Mirage Legal-Grade Evidence Bundle\n"
                "===================================\n"
                f"Engagement: {pkg['engagement_id']}\n"
                f"Organization: {pkg['body']['organization']}\n"
                f"ROE / Auth ref: {pkg['body']['authorization_ref']}\n"
                f"Generated: {pkg['body']['generated_at']}\n"
                f"events.json SHA-256: {pkg['body_sha256']}\n\n"
                "Verify integrity:\n"
                "  sha256sum events.json\n"
                "Compare to manifest.json -> files[0].sha256\n\n"
                f"{assert_no_egress_doctrine()}\n"
            ),
        )

    return zip_path
