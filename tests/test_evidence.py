import json
import zipfile

from mirage import evidence


def test_evidence_bundle_verifies_manifest_and_hmac(monkeypatch, tmp_path):
    monkeypatch.setattr(evidence, "ensure_data_dir", lambda cfg=None: tmp_path)
    monkeypatch.setattr(
        evidence,
        "load_config",
        lambda: {
            "organization_name": "Test Org",
            "authorization_ref": "ROE-TEST",
        },
    )
    monkeypatch.setattr(evidence, "get_recent_events", lambda hours: [])
    monkeypatch.setattr(evidence, "get_all_events", lambda limit: [])
    monkeypatch.setattr(evidence, "assert_no_egress_doctrine", lambda: "passive-only")

    bundle_path = evidence.export_evidence(hours=24)
    valid, message = evidence.verify_evidence_zip(str(bundle_path))
    assert valid, message

    tampered_path = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle_path, "r") as source:
        entries = {name: source.read(name) for name in source.namelist()}
    manifest = json.loads(entries["manifest.json"].decode("utf-8"))
    manifest["organization"] = "Changed Org"
    entries["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    with zipfile.ZipFile(tampered_path, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, content in entries.items():
            target.writestr(name, content)

    valid, message = evidence.verify_evidence_zip(str(tampered_path))
    assert not valid
    assert "manifest SHA-256 mismatch" in message
