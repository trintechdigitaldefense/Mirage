from mirage import cli


def test_event_callback_uses_taxonomy_severity(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        cli,
        "emit",
        lambda event, source, details, severity: emitted.append(
            (event, source, details, severity)
        ),
    )

    cli._on_event("dns_canary_lookup", "192.0.2.15", {})
    cli._on_event("ssh_jail_command", "192.0.2.16", {})
    cli._on_event("tarpit_hold", "192.0.2.17", {})

    assert [item[3] for item in emitted] == ["medium", "high", "low"]
