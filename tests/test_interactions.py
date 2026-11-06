"""Controlled interaction tests — Stage 3 item 12."""

from mirage.intent import classify_event
from mirage.sessions import enrich_event_fields, session_id_for
from mirage.tokens import register_token, record_hit, lifecycle_summary
from mirage.file_watch import _file_hash
from mirage.probe import probe_tcp
from pathlib import Path


def test_enrich_adds_uids():
    d = enrich_event_fields("beacon_hit", "1.2.3.4", {"service": "beacon", "token_id": "T1"})
    assert "event_uid" in d
    assert "session_id" in d
    assert d["decoy_id"]


def test_session_stable():
    a = session_id_for("10.0.0.1", "ssh_jail")
    b = session_id_for("10.0.0.1", "ssh_jail")
    assert a == b


def test_token_lifecycle():
    register_token("TEST-UNIT-1", "aws_access_key", path="/tmp/x", label="unit")
    record_hit("TEST-UNIT-1", source_ip="9.9.9.9")
    s = lifecycle_summary()
    assert s["total"] >= 1


def test_classify_decoy_scope():
    c = classify_event({"event_type": "ssh_jail_login", "details": {"service": "ssh_jail"}})
    assert c.get("scope") == "decoy_only"
    assert "not" in (c.get("disclaimer") or "").lower() or "decoy" in (c.get("verdict") or "").lower()


def test_file_hash(tmp_path: Path):
    p = tmp_path / "a.txt"
    p.write_text("hello")
    assert _file_hash(p)


def test_probe_closed():
    ok, _ = probe_tcp("127.0.0.1", 1, timeout=0.2)
    assert ok is False
