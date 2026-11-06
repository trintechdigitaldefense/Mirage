"""Evidence bundles with optional HMAC signature (Stage 4 items 18–19).

Signing key lives under ~/.mirage/keys/ (outside evidence/).
Limitations are documented in every bundle README — not court-certified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import ensure_data_dir, load_config
from .db import get_recent_events, get_all_events
from .intent import classify_events
from .guardrails import assert_no_egress_doctrine

EVIDENCE_LIMITATIONS = (
    "LIMITATIONS (read carefully)\n"
    "----------------------------\n"
    "1. This bundle records interactions with Mirage decoys only.\n"
    "2. It does NOT prove compromise of real accounts, real hosts, or real data.\n"
    "3. Integrity is local HMAC-SHA256 (or SHA-256 of events.json). It is NOT\n"
    "   a qualified electronic signature, not timestamped by a TSA, and not\n"
    "   independently court-certified.\n"
    "4. Use for internal investigation, insurance narrative support, and\n"
    "   authorized law-enforcement cooperation under your ROE — not as sole\n"
    "   legal proof of attribution or damages.\n"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def keys_dir() -> Path:
    d = ensure_data_dir() / "keys"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def ensure_signing_key() -> Path:
    """Create HMAC key outside evidence/ if missing."""
    path = keys_dir() / "evidence_hmac.key"
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def sign_payload(body: bytes) -> str:
    key = ensure_signing_key().read_bytes()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_signature(body: bytes, signature_hex: str) -> bool:
    key_path = keys_dir() / "evidence_hmac.key"
    if not key_path.exists():
        return False
    key = key_path.read_bytes()
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex or "")


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
    cfg = load_config()
    org = cfg.get("organization_name") or "Client"
    auth_ref = cfg.get("authorization_ref") or "N/A"

    if limit:
        events = get_all_events(limit=limit)
    else:
        events = get_recent_events(hours=hours)

    normalized = [_normalize_event(e) for e in events]
    classified = classify_events(normalized)

    for row in classified:
        cls = row.get("classification") or {}
        row["intent"] = cls.get("intent")
        row["verdict"] = cls.get("verdict")
        row["attack_techniques"] = cls.get("attack_techniques") or []
        row["confidence"] = cls.get("confidence")
        row["scope"] = cls.get("scope", "decoy_only")
        row["disclaimer"] = cls.get("disclaimer")
        row.pop("classification", None)

    created = datetime.utcnow().isoformat() + "Z"
    engagement_id = engagement_id or f"MIR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    body = {
        "format": "TrinTech-Mirage-Evidence-v2",
        "engagement_id": engagement_id,
        "organization": org,
        "authorization_ref": auth_ref,
        "generated_at": created,
        "generator": "Mirage by TrinTech Digital Defense",
        "doctrine": assert_no_egress_doctrine(),
        "limitations": EVIDENCE_LIMITATIONS,
        "event_count": len(classified),
        "events": classified,
    }

    body_json = json.dumps(body, indent=2, sort_keys=True, default=str)
    body_bytes = body_json.encode("utf-8")
    body_hash = _sha256_bytes(body_bytes)
    signature = sign_payload(body_bytes)

    manifest = {
        "format": "TrinTech-Evidence-Manifest-v2",
        "engagement_id": engagement_id,
        "organization": org,
        "authorization_ref": auth_ref,
        "generated_at": created,
        "files": [
            {
                "name": "events.json",
                "sha256": body_hash,
                "hmac_sha256": signature,
                "bytes": len(body_bytes),
            }
        ],
        "signing": {
            "algorithm": "HMAC-SHA256",
            "key_location": "~/.mirage/keys/evidence_hmac.key (outside evidence/)",
            "note": "Verify with: mirage evidence --verify <zip>",
        },
        "limitations_ref": "See README.txt and events.json limitations field",
        "manifest_sha256": "",
    }
    manifest_for_hash = dict(manifest)
    manifest_for_hash.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = _sha256_text(json.dumps(manifest_for_hash, indent=2, sort_keys=True))

    return {
        "engagement_id": engagement_id,
        "body": body,
        "body_json": body_json,
        "body_sha256": body_hash,
        "hmac_sha256": signature,
        "manifest": manifest,
    }


def export_evidence(
    hours: int = 24,
    limit: Optional[int] = None,
    engagement_id: str = "",
) -> Path:
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
        zf.writestr("manifest.json", json.dumps(pkg["manifest"], indent=2, sort_keys=True))
        zf.writestr("signature.hmac", pkg["hmac_sha256"] + "\n")
        zf.writestr(
            "README.txt",
            (
                "Mirage Evidence Bundle (v2)\n"
                "===========================\n"
                f"Engagement: {pkg['engagement_id']}\n"
                f"Organization: {pkg['body']['organization']}\n"
                f"ROE / Auth ref: {pkg['body']['authorization_ref']}\n"
                f"Generated: {pkg['body']['generated_at']}\n"
                f"events.json SHA-256: {pkg['body_sha256']}\n"
                f"events.json HMAC-SHA256: {pkg['hmac_sha256']}\n\n"
                f"{EVIDENCE_LIMITATIONS}\n"
                f"{assert_no_egress_doctrine()}\n"
            ),
        )

    return zip_path


def verify_evidence_zip(zip_path: str) -> Tuple[bool, str]:
    """Verify bundle structure, manifest integrity, event metadata, SHA-256 and HMAC."""
    path = Path(zip_path)
    if not path.exists():
        return False, "file not found"
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            required = {"events.json", "manifest.json", "signature.hmac"}
            if not required.issubset(set(names)):
                return False, "required evidence files missing"
            if len(names) != len(set(names)):
                return False, "duplicate archive entry names"
            if archive.getinfo("events.json").file_size > 50 * 1024 * 1024:
                return False, "events.json exceeds verification size limit"
            if archive.getinfo("manifest.json").file_size > 1024 * 1024:
                return False, "manifest.json exceeds verification size limit"
            events_bytes = archive.read("events.json")
            manifest_bytes = archive.read("manifest.json")
            signature_file = archive.read("signature.hmac")

        manifest = json.loads(manifest_bytes.decode("utf-8"))
        events_body = json.loads(events_bytes.decode("utf-8"))
        signature = signature_file.decode("utf-8").strip()

        if manifest.get("format") != "TrinTech-Evidence-Manifest-v2":
            return False, "unsupported evidence manifest format"
        files = manifest.get("files")
        if not isinstance(files, list) or len(files) != 1:
            return False, "invalid manifest files list"
        file_meta = files[0]
        if file_meta.get("name") != "events.json":
            return False, "manifest does not identify events.json"

        expected_manifest_hash = manifest.get("manifest_sha256") or ""
        manifest_for_hash = dict(manifest)
        manifest_for_hash.pop("manifest_sha256", None)
        actual_manifest_hash = _sha256_text(
            json.dumps(manifest_for_hash, indent=2, sort_keys=True)
        )
        if not expected_manifest_hash or not hmac.compare_digest(
            expected_manifest_hash, actual_manifest_hash
        ):
            return False, "manifest SHA-256 mismatch"

        actual_events_hash = _sha256_bytes(events_bytes)
        if file_meta.get("bytes") != len(events_bytes):
            return False, "events.json byte-length mismatch"
        if not file_meta.get("sha256") or not hmac.compare_digest(
            str(file_meta["sha256"]), actual_events_hash
        ):
            return False, "events.json SHA-256 mismatch"
        manifest_signature = str(file_meta.get("hmac_sha256") or "")
        if not manifest_signature or not hmac.compare_digest(
            manifest_signature, signature
        ):
            return False, "signature file does not match manifest"
        if not verify_signature(events_bytes, signature):
            return False, "HMAC signature invalid (wrong key or tampered body)"

        if events_body.get("format") != "TrinTech-Mirage-Evidence-v2":
            return False, "unsupported events document format"
        if events_body.get("event_count") != len(events_body.get("events") or []):
            return False, "event_count does not match events list"
        for field in ("engagement_id", "organization", "authorization_ref", "generated_at"):
            if events_body.get(field) != manifest.get(field):
                return False, f"manifest metadata mismatch: {field}"

        return True, "OK — manifest, SHA-256 and HMAC verified"
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        return False, str(exc)[:200]
