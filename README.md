# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹  
**v2.1 — "The Trap That Talks"**

Lightweight deception layer for networks that have no security team.  
Fake services, honey tokens, breadcrumb trails, SSH jail and decoy shares turn attacker interaction into clear, owner-readable stories — with legal-grade evidence and hard safety guardrails.

Designed for Caribbean SMBs. Self-hosted or run as a managed service by TrinTech.  
Pairs with **Sentinel** (continuous monitoring) and **FortifyOne** (professional audit).

---

## What Clients Actually Receive

> “At 14:22 UTC, source 203.0.113.45 logged into the decoy SSH and ran `find / -name '*.pem'`. Full command transcript attached.”

That is the kind of report business owners understand, forward, and renew for.

---

## What’s in v2.1

### Revenue tier
| Feature | Command |
|---------|---------|
| **Story Report** | `mirage report --story` |
| **Attack-Intent Engine** | built into alerts + reports |
| **Decoy Document Factory** | `mirage bait [--sector] [--write]` |

### Depth tier
| Feature | Notes |
|---------|-------|
| **Breadcrumb Trails** | Cross-linked decoys, hop logging |
| **Beaconing Honey Tokens** | Phone-home AWS/Azure-style secrets |
| **Decoy SMB Shares** | Finance / HR / Backups on port 4450 |
| **SSH Credential Jail** | Accept any password, fake shell, log commands, 5-min cap |

### Trust / Safety tier
| Feature | Command |
|---------|---------|
| **Multi-site Mesh** | `mirage mesh [status\|register\|group]` |
| **Coverage Heatmap** | `mirage coverage` |
| **Legal Evidence Bundle** | `mirage evidence [--hours 24]` |
| **Realism Rotation** | `mirage rotate` |
| **Anti-abuse Guardrails** | rate limits + circuit breaker (always on by default) |

---

## Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/Mirage.git
cd Mirage
pip install -r requirements.txt
pip install -e .

mirage init --org "Acme Medical" --auth-ref ROE-2026-001 --sector clinic
mirage deploy
mirage status
mirage coverage
mirage alerts
mirage report --story
mirage evidence
mirage mesh
```

Deploy starts: fake services + SSH jail, canaries/trails/tokens, SMB, beacon listener, mesh registration, guardrails.

---

## Typical Engagement Flow

1. Sign Rules of Engagement  
2. `mirage init --org "..." --auth-ref "..." --sector ...`  
3. `mirage deploy`  
4. Leave running  
5. Interaction → alert + intent + (optional) SSH command transcript  
6. Deliver **story report** + **evidence zip** when needed  

---

## Continuous Protection Package

| Component | Role |
|-----------|------|
| **FortifyOne** | Point-in-time network audit |
| **Sentinel** | Continuous monitoring, FIM, reverse-shell detection |
| **Mirage** | Active deception (this tool) |

---

## Doctrine

Deception stays **passive**. Mirage watches, records and reports — it never retaliates, relays, or touches third-party systems. Guardrails enforce rate limits and a circuit breaker so the product cannot be abused as a reflector or pivot.

---

## Contact

**TrinTech Digital Defense**  
Email: trintechdigitaldefense@gmail.com  
WhatsApp: +1 (868) 362-0679  
Web: https://trintechdigitaldefense.github.io

---

Authorized defensive deception only.  
Deploy only on networks you own or have explicit written permission to protect.  
Unauthorized use may violate the Trinidad & Tobago Cybercrime Act.

*Defend. Detect. Dominate.*
