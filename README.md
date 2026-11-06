# Mirage — Active Deception Platform

**TrinTech Digital Defense** · **v2.5.0** · **Stage 1 + Stage 2 complete**

Passive deception with credential redaction, accept-time guardrails, loopback-default bind, service registry, and **post-bind health probes**.

> Stages 3–7 (file open/read, evidence signing, dashboard, enterprise packaging) remain. SMB stays **low-interaction**. HTTPS stays **disabled** until real TLS.

---

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
```

---

## Stage 2 complete

| Item | Status |
|------|--------|
| `accept_allowed` on services, SSH, Telnet, web API, tarpit, DNS, SMB, beacon, cloud | Done |
| Session caps + circuit pause on accept loops | Done |
| Service registry RUNNING / FAILED / DISABLED / DEGRADED | Done |
| Post-bind TCP/UDP probes on deploy + `mirage health` | Done |
| Honest SMB/beacon register (bind failure → FAILED) | Done |
| `mirage stop` via PID; safe `clean --yes` | Done |

### Next (Stage 3+)

- File open/read monitoring  
- Evidence signing  
- Honest confidence wording  
- Expanded tests / soak  
- Dashboard  

---

## Quick start

```bash
mirage init --org Client --auth-ref ROE-2026-001 --sector clinic
mirage deploy    # prints probe OK/FAIL per port
mirage health
mirage stop
pytest -q tests/
```

*Defend. Detect. Dominate.*
