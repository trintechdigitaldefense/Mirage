from mirage import alerts


def test_cooldown_suppresses_notifications_but_keeps_audit_stream(monkeypatch):
    calls = {"db": [], "siem": [], "webhook": []}

    monkeypatch.setattr(
        alerts,
        "load_config",
        lambda: {
            "authorization_ref": "TEST-ROE",
            "guardrails_enabled": False,
            "alert_cooldown_seconds": 300,
            "alert_channel": "both",
            "webhook_url": "https://example.invalid/hook",
            "mitre_siem_stream": True,
        },
    )
    monkeypatch.setattr(
        alerts, "enrich_event_fields", lambda event, source, details: details
    )
    monkeypatch.setattr(
        alerts,
        "is_in_cooldown",
        lambda key, seconds: True,
    )
    monkeypatch.setattr(
        alerts, "log_event", lambda **kwargs: calls["db"].append(kwargs)
    )
    monkeypatch.setattr(
        alerts, "_append_siem",
        lambda *args: calls["siem"].append(args),
    )
    monkeypatch.setattr(
        alerts, "_post_webhook",
        lambda *args: calls["webhook"].append(args),
    )

    alerts.emit("ssh_login_attempt", "192.0.2.10", {"username": "analyst"})

    assert len(calls["db"]) == 1
    assert len(calls["siem"]) == 1
    assert calls["webhook"] == []
