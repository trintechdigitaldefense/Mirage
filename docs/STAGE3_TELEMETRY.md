# Stage 3 — Deception & Telemetry

| Item | Implementation |
|------|----------------|
| File open/read monitoring | `mirage/file_watch.py` — atime + size + content hash polling; emits `canary_opened` / `canary_modified` / `canary_deleted` |
| Honeytoken lifecycle | `mirage/tokens.py` — deployed → hit; `mirage tokens` CLI |
| DNS canary | UDP listener + NXDOMAIN; guardrails; tests under `tests/` |
| Beacon / web-bug | Beacon listener records hits; tokens registry updates |
| SMB | Documented as **low-interaction only** |
| Banner rotation | `rotation.py` already process-wide; concurrent reads are safe |
| Controlled interaction tests | `tests/test_interactions.py` |
