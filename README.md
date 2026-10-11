# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹  
**v2.2**

Fake services, SSH jail, honey tokens, trails, SMB shares, cloud decoys and email canaries — turned into owner-readable stories and legal-grade evidence.

---

## Quick Start

```bash
pip install -r requirements.txt && pip install -e .

mirage packs                                 # list industry packs
mirage init --org "Acme Medical" --auth-ref ROE-2026-001 --sector clinic
mirage deploy
mirage health
mirage report --story
mirage evidence
```

## Commands

| Command | Purpose |
|---------|---------|
| `deploy` | Full stack: services, SSH jail, canaries, SMB, beacons, cloud decoy |
| `report --story` | Client narrative |
| `alerts` | Events + intent |
| `coverage` | Heatmap / blind spots |
| `evidence` | SHA-256 evidence zip |
| `mesh` | Multi-site registry |
| `rotate` | Banner/hostname cosmetics |
| `health` | SLA / heartbeat for portal |
| `packs` | Industry vertical packs |
| `killswitch [--reset]` | Trip or clear circuit breaker |
| `bait [--write]` | Preview/write decoy docs |

## Feature map

**v2.1 core:** story report · intent · bait factory · trails · beacons · SMB · SSH jail · mesh · coverage · evidence · rotation · guardrails  

**v2.2 stretch:** industry packs (clinic/retail/legal/finance/hospitality) · AD decoy accounts · cloud decoy bucket · email canaries · health heartbeat · killswitch · live banner rotation on deploy

## Doctrine

Passive observation only. No relay, no attack-back. Rate limits + circuit breaker enforced.

---

**TrinTech Digital Defense** · trintechdigitaldefense@gmail.com · +1 (868) 362-0679  
Authorized defensive use only.

*Defend. Detect. Dominate.*
