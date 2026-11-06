"""Central sensitive-data redaction for Mirage.

All paths that persist or emit events (DB, console, webhook, SIEM, evidence)
must pass details through redact_details() first.

We preserve useful telemetry: username (optional), auth method, presence of
a secret, and a non-reversible fingerprint for correlation — never the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Set

# Keys whose values are always redacted (case-insensitive match on key)
SECRET_KEYS: Set[str] = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "aws_secret_access_key",
    "authorization",
    "auth",
    "cookie",
    "session",
    "private_key",
    "privatekey",
    "credential",
    "credentials",
    "post_preview",
    "body",
    "raw_body",
}

# Patterns that look like secrets inside free-form strings
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)authorization:\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

REDACTED = "[REDACTED]"


def _fingerprint_key() -> bytes:
    """Load or atomically create a per-install HMAC key for secret fingerprints."""
    configured = os.environ.get("MIRAGE_REDACTION_KEY")
    if configured:
        return configured.encode("utf-8")

    from .config import ensure_data_dir, load_config

    key_dir = ensure_data_dir(load_config()) / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "redaction_hmac.key"
    try:
        with key_path.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    key = key_path.read_bytes()
    if len(key) < 32:
        raise RuntimeError("Mirage redaction HMAC key is invalid or truncated")
    return key


def fingerprint(value: str, *, salt: Optional[str] = None) -> str:
    """Return a keyed, short correlation fingerprint; never use this for authentication."""
    if not value:
        return ""
    # Keep explicit salt support for callers relying on the legacy API. Normal
    # redaction always uses the protected per-install key instead.
    key = salt.encode("utf-8") if salt is not None else _fingerprint_key()
    digest = hmac.new(
        key, value.encode("utf-8", errors="replace"), hashlib.sha256
    ).hexdigest()
    return digest[:12]


def _redact_string(s: str) -> str:
    out = s
    for pat in _SECRET_PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


def redact_value(key: str, value: Any) -> Any:
    k = (key or "").lower().replace("-", "_")
    if k in SECRET_KEYS or any(sk in k for sk in ("password", "secret", "token", "credential")):
        if isinstance(value, str) and value:
            return {
                "present": True,
                "length": len(value),
                "fingerprint": fingerprint(value),
                "value": REDACTED,
            }
        if value:
            return {"present": True, "value": REDACTED}
        return {"present": False, "value": REDACTED}
    if isinstance(value, dict):
        return redact_details(value)
    if isinstance(value, list):
        return [redact_details(v) if isinstance(v, dict) else (
            _redact_string(v) if isinstance(v, str) else v
        ) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def redact_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a deep-copied, redacted details dict safe for storage/export."""
    if not details:
        return {}
    if not isinstance(details, dict):
        return {"_raw": REDACTED}
    out: Dict[str, Any] = {}
    for k, v in details.items():
        out[k] = redact_value(str(k), v)
    # Normalise common credential shape for analysts
    if "password" in details or "passwd" in details or "pwd" in details:
        raw = details.get("password") or details.get("passwd") or details.get("pwd") or ""
        if isinstance(raw, str) and raw and "password_present" not in out:
            out["password_present"] = True
            out["password_fingerprint"] = fingerprint(raw)
        # Ensure no plaintext key survives alternate names
        for pk in ("password", "passwd", "pwd", "pass"):
            if pk in out and isinstance(out[pk], str):
                out[pk] = REDACTED
    return out


def assert_no_plaintext_secrets(payload: Any, banned: Optional[List[str]] = None) -> None:
    """Raise AssertionError if any banned test secrets appear in serialised payload."""
    import json

    banned = banned or []
    text = json.dumps(payload, default=str)
    for b in banned:
        if b and b in text:
            raise AssertionError(f"Secret value leaked into payload: {b!r}")
