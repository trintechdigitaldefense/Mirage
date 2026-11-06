"""Stage 2 probe helpers."""

from mirage.probe import probe_tcp, probe_summary, probe_registry_rows


def test_probe_tcp_closed_port():
    ok, detail = probe_tcp("127.0.0.1", 1, timeout=0.3)
    assert ok is False
    assert detail


def test_probe_summary():
    rows = [
        {"name": "a", "port": 0, "state": "RUNNING", "probe_ok": None},
        {"name": "b", "port": 1, "state": "RUNNING", "probe_ok": True},
        {"name": "c", "port": 2, "state": "RUNNING", "probe_ok": False},
    ]
    s = probe_summary(rows)
    assert s["ok"] == 1
    assert s["fail"] == 1
