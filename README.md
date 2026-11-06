# Mirage — Active Deception Platform

**TrinTech Digital Defense** · **v2.5.x**

Passive decoys with redaction, guardrails, registry, probes, file-access signals, honeytoken lifecycle, honest confidence, signed evidence, and a **local** operator dashboard.

> **Not fully production-certified.** Stages 6–7 (multi-tenant hardening, soak tests, signed releases) remain. SMB = low-interaction. HTTPS = disabled until TLS.

---

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
```

---

## Roadmap status

| Stage | Status |
|-------|--------|
| **1 Security** | Done — redaction, accept guardrails, bind default, safe clean/stop |
| **2 Registry** | Done — RUNNING/FAILED/DEGRADED + post-bind probes |
| **3 Telemetry** | Done — file open/read watcher, token lifecycle, interaction tests |
| **4 Detection/evidence** | Done — decoy_only confidence, event UID/session, ack/FP, HMAC evidence + verify |
| **5 Dashboard** | MVP — loopback Bearer-token GET UI (`mirage/dashboard.py`) |
| **6 Integrations** | Partial — mesh exists; tenant isolation / hardened Sentinel still open |
| **7 Packaging** | Partial — tests + docs started; soak + signed release open |

---

## Quick start

```bash
mirage init --org Client --auth-ref ROE-2026-001 --sector clinic
mirage deploy
mirage tokens
mirage evidence
mirage evidence --verify ~/.mirage/evidence/<bundle>.zip
mirage ack --list
pytest -q tests/
```

See `docs/EVIDENCE_LIMITATIONS.md`, `docs/STAGE3_TELEMETRY.md`, `docs/CHANGELOG.md`.

*Defend. Detect. Dominate.*
