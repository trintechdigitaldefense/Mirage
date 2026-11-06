"""Regression: known test passwords must never appear in stored/exported payloads."""

import json

from mirage.redaction import redact_details, assert_no_plaintext_secrets, fingerprint


def test_password_redacted():
    details = {
        "username": "admin",
        "password": "SuperSecretTestPass-NEVER-STORE",
        "service": "ssh_jail",
    }
    safe = redact_details(details)
    blob = json.dumps(safe)
    assert "SuperSecretTestPass-NEVER-STORE" not in blob
    assert safe.get("password_present") is True or (
        isinstance(safe.get("password"), dict) and safe["password"].get("value") == "[REDACTED]"
    )


def test_post_preview_redacted():
    details = {
        "path": "/api/v1/auth",
        "post_preview": "username=alice&password=Hunter2TestOnly",
    }
    safe = redact_details(details)
    blob = json.dumps(safe)
    assert "Hunter2TestOnly" not in blob


def test_fingerprint_stable_not_reversible():
    fp1 = fingerprint("same-secret")
    fp2 = fingerprint("same-secret")
    assert fp1 == fp2
    assert fp1 != "same-secret"
    assert len(fp1) == 12


def test_assert_no_plaintext_raises():
    try:
        assert_no_plaintext_secrets({"x": "LeakMe123"}, banned=["LeakMe123"])
        raised = False
    except AssertionError:
        raised = True
    assert raised


def test_nested_token_redacted():
    details = {"headers": {"Authorization": "Bearer abc.def.ghi", "X-Other": "ok"}}
    safe = redact_details(details)
    blob = json.dumps(safe)
    assert "abc.def.ghi" not in blob
