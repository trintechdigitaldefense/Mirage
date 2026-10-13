# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹  
**v2.2** — pilot-ready under signed ROE

Fake services, SSH jail, honey tokens, trails, SMB shares, cloud decoys and email canaries — turned into owner-readable stories and legal-grade evidence.

---

## Client pilot path (required)

1. **Sign ROE** — `docs/ROE_TEMPLATE.md` (scope, ports, no-attack-back)  
2. **Port map** — `docs/PORT_MAP_TEMPLATE.md` (avoid real SSH 22 / RDP 3389 / SMB 445)  
3. **Init** — org + ROE ref + sector  
4. **Agree** — who gets alerts + report cadence  
5. **Deploy** — confirm `health` + one live probe  
6. Full checklist — `docs/DEPLOYMENT_CHECKLIST.md` or `mirage checklist`

```bash
pip install -r requirements.txt && pip install -e .

mirage checklist
mirage init --org "Acme Medical" --auth-ref ROE-2026-001 --sector clinic
mirage agree --recipients "ops@acme.tt" --channel both --cadence weekly --webhook https://hooks.example/mirage
mirage deploy
mirage health
# live probe
curl -s http://127.0.0.1:8080/ >/dev/null
curl -s http://127.0.0.1:9000/ >/dev/null
mirage alerts
mirage report --story
mirage evidence
```

Default decoy ports avoid production clashes: SSH jail **2222**, RDP **33890**, SMB **4450**, MySQL **3307**.

---

## Commands

| Command | Purpose |
|---------|---------|
| `checklist` | Pilot deployment checklist |
| `init` | Org + ROE ref + sector |
| `agree` | Alert recipients + report cadence |
| `deploy` | Full stack |
| `health` / `coverage` / `status` | Confirm sensors |
| `alerts` / `report --story` | Events + narrative |
| `evidence` | SHA-256 evidence zip |
| `mesh` / `rotate` / `packs` | Multi-site, cosmetics, verticals |
| `killswitch [--reset]` | Circuit breaker |

---

## Doctrine

Passive observation only. No relay, no attack-back. Rate limits + circuit breaker enforced. Deploy only with written permission.

---

**TrinTech Digital Defense** · trintechdigitaldefense@gmail.com · +1 (868) 362-0679  

*Defend. Detect. Dominate.*
