# Mirage — Active Deception Platform

**TrinTech Digital Defense** · **v2.5.0** (security & reliability hardening)

Passive deception: fake services, SSH/Telnet sandboxes, web API decoys, canaries, tarpits, DNS canaries — with **credential redaction**, accept-time guardrails, and loopback-default bind.

> **Not production-ready end-to-end yet.** Stage 1 critical defects are being closed. Do not market as court-certified evidence or full SMB/HTTPS protocol fidelity until Stages 2–4 complete.

---

## Upgrade (safe)

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
```

- **Does not** delete `~/.mirage` (config, events, evidence)
- **Refuses** `git reset --hard` if the working tree is dirty unless `FORCE=1`
- Installs package; preserves operator data

```bash
FORCE=1 bash start.sh upgrade   # only if you accept discarding local uncommitted code changes
```

---

## v2.5 Stage 1 — critical security (this release)

| Fix | Behaviour |
|-----|-----------|
| **Credential redaction** | `mirage/redaction.py` — passwords/tokens never written to DB, console, webhook, or SIEM; fingerprint only |
| **Guardrails at accept** | `accept_allowed()` — rate limit, session caps, circuit breaker **pauses listeners** |
| **Default bind** | `127.0.0.1` — set `allow_external_bind: true` + `listen_address: 0.0.0.0` only under ROE |
| **HTTPS** | **Disabled** by default (`https_enabled: false`) until real TLS exists |
| **Safe upgrade** | No silent hard-reset; data dir preserved |
| **DB** | Init-once, indexes, retention hook, chmod 600, redact on write |
| **CI** | Mandatory `tests/`; pytest must pass |

### Remaining Stage 1 / 2 work

- Wire `accept_allowed` into every listener accept loop
- Safe `mirage clean` path validation + real `mirage stop`
- File **open/read** monitoring (not only mtime)
- Evidence signing (not only SHA-256 next to the bundle)
- Honest confidence scoring (decoy login ≠ real account compromise)

---

## Quick start

```bash
mirage init --org "Client" --auth-ref ROE-2026-001 --sector clinic
# Optional external exposure (ROE required):
# edit ~/.mirage/config.json → allow_external_bind true, listen_address 0.0.0.0
mirage deploy
curl -s http://127.0.0.1:8081/.env
mirage alerts
pytest -q tests/
```

Default ports stay non-production: SSH **2222**, Telnet **2323**, Web API **8081**, SMB **4450**, DNS canary **5353**.

---

## Doctrine

- Passiveception is **passive observation** (no attack-back, no relay).
- Submitted secrets to decoys are **telemetry events**, not trophies — **redacted**.
- Circuit breaker trip → listeners pause until `mirage killswitch --reset`.
- Firewall DROP via Sentinel is **off** unless ROE enables `sentinel_firewall_drop`.

*Defend. Detect. Dominate.*
