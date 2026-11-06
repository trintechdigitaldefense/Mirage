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
| **3 Telemetry** | Partial — metadata polling + atime signals (filesystem-dependent); no native inotify backend; token lifecycle and interaction tests |
| **4 Detection/evidence** | Core implemented — decoy_only confidence, event UID/session, ack/FP, HMAC evidence; manifest and signature verification hardened |
| **5 Dashboard** | MVP — optional loopback-only Bearer-token GET UI, started with `mirage deploy --dashboard` |
| **6 Integrations** | Partial — mesh exists; tenant isolation / hardened Sentinel still open |
| **7 Packaging** | Partial — tests + docs started; soak + signed release open |

---

## Quick start

```bash
mirage init --org Client --auth-ref ROE-2026-001 --sector clinic
mirage deploy --dashboard  # optional local operator dashboard
mirage tokens
mirage evidence
mirage evidence --verify ~/.mirage/evidence/<bundle>.zip
mirage ack --list
pytest -q tests/
```

See `docs/EVIDENCE_LIMITATIONS.md`, `docs/STAGE3_TELEMETRY.md`, `docs/CHANGELOG.md`.

The dashboard binds only to `127.0.0.1`. Authentication uses an HTTP `Authorization: Bearer` header; URL query-string tokens are rejected. The generated token is stored in `~/.mirage/dashboard_token.txt` (or the configured Mirage data directory) with restrictive file permissions. Do not expose the dashboard through a public reverse proxy without a separately reviewed access-control and TLS design.

*Defend. Detect. Dominate.*
