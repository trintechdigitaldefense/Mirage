# Mirage — Active Deception Platform

**TrinTech Digital Defense** · **v2.5.0** (Stage 1 complete · Stage 2 registry)

Passive deception with **credential redaction**, accept-time guardrails, loopback-default bind, and a **service registry** that reports real RUNNING/FAILED state.

> Still **not** full production certification. HTTPS TLS, file open/read monitoring, evidence signing, and honest confidence scoring remain on the roadmap.

---

## Upgrade (safe)

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
# dirty tree? FORCE=1 bash start.sh upgrade
```

`~/.mirage` (config, events, evidence) is **never** deleted by upgrade.

---

## Stage 1 — critical security (done)

| Item | Status |
|------|--------|
| Central redaction (`redaction.py`) | Done — DB / console / webhook / SIEM |
| Source-level no plaintext password (SSH / Telnet / HTTP / web API) | Done |
| `accept_allowed` on services, tarpit, web API, telnet, SSH jail | Done |
| Circuit breaker **pauses** accept loops | Done |
| Default bind `127.0.0.1` + `allow_external_bind` | Done |
| HTTPS disabled until real TLS | Done |
| Safe `start.sh` upgrade | Done |
| DB init-once, indexes, retention, chmod | Done |
| Safe `mirage clean --yes` (path-jailed) | Done |
| `mirage stop` via `~/.mirage/mirage.pid` | Done |
| Mandatory pytest CI | Done |

## Stage 2 — service registry (done)

| Item | Status |
|------|--------|
| `mirage/registry.py` | Done |
| Deploy registers each listener RUNNING/FAILED/DISABLED | Done |
| Deploy summary shows failed components (no false “all healthy”) | Done |
| `mirage health` includes registry rows | Done |
| `REGISTRY.stop_all` on shutdown | Done |

### Still open

- File **open/read** monitoring (beyond mtime)
- Evidence **signing** (not only local SHA-256)
- Detection confidence: decoy login ≠ real account compromise
- Optional TLS for HTTPS decoy
- Full SMB protocol (currently low-interaction)

---

## Quick start

```bash
mirage init --org "Client" --auth-ref ROE-2026-001 --sector clinic
mirage deploy          # binds 127.0.0.1 by default
mirage status
mirage health
curl -s http://127.0.0.1:8081/.env
mirage stop            # SIGTERM to deploy PID
mirage clean --yes     # decoys only; never events/evidence
pytest -q tests/
```

External bind (ROE required): set `allow_external_bind: true` and `listen_address: "0.0.0.0"` in `~/.mirage/config.json`.

---

## Doctrine

- Passiveception is **passive observation** (no attack-back, no relay).
- Submitted secrets are **redacted** (fingerprint only).
- Circuit breaker trip → listeners pause until `mirage killswitch --reset`.
- SMB is **low-interaction**, not a full protocol server.

*Defend. Detect. Dominate.*
