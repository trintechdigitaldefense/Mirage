"""Guardrail accept-time enforcement tests."""

from mirage import guardrails


def test_accept_allowed_and_release():
    guardrails.configure(
        rate_limit=100,
        rate_window=60,
        breaker_threshold=1000,
        breaker_window=60,
        max_global=5,
        max_per_service=3,
        max_per_source=2,
        enabled=True,
    )
    ok, reason = guardrails.accept_allowed("http", "10.0.0.1")
    assert ok, reason
    guardrails.session_release("http", "10.0.0.1")


def test_circuit_breaker_blocks_accept():
    guardrails.configure(
        rate_limit=1000,
        rate_window=60,
        breaker_threshold=5,
        breaker_window=60,
        max_global=100,
        enabled=True,
    )
    # Trip by recording via check_source / accept
    for i in range(6):
        guardrails.accept_allowed("tarpit", f"10.1.1.{i}")
    assert guardrails.listeners_paused()
    ok, reason = guardrails.accept_allowed("ssh", "10.9.9.9")
    assert not ok
    assert "circuit" in reason.lower() or "paused" in reason.lower()
    guardrails.reset_breaker()
    assert not guardrails.listeners_paused()
