# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹  
**v2.1 — "The Trap That Talks"**

Lightweight deception layer for networks that have no security team.  
Fake services, honey tokens, breadcrumb trails and decoy shares turn attacker interaction into clear, owner-readable stories.

Designed for Caribbean SMBs. Self-hosted or run as a managed service by TrinTech.  
Pairs with **Sentinel** (continuous monitoring) and **FortifyOne** (professional audit).

---

## What Clients Actually Receive

> “At 14:22 UTC, source 203.0.113.45 interacted with the fake SSH service. Someone was probing for remote access credentials, not just scanning.”

That is the kind of report business owners understand, forward, and renew for.

---

## What’s in v2.1

### Revenue tier (ships first)
| Feature | What it does |
|---------|--------------|
| **Story Report** (`--story`) | One-page narrative: what was touched, what it means, what to do next |
| **Attack-Intent Engine** | Classifies events into plain-English verdicts + ATT&CK tags |
| **Decoy Document Factory** | Client- and sector-aware bait (clinic / retail / legal / general) |

### Depth tier (now live)
| Feature | What it does |
|---------|--------------|
| **Breadcrumb Trails** | Decoys cross-link each other; every hop is logged and tells a richer story |
| **Beaconing Honey Tokens** | AWS/Azure-style secrets that phone home when used or fetched from anywhere |
| **Decoy SMB Shares** | Fake Finance / HR / Backups shares that alert on connection and negotiate |

---

## Core Capabilities

| Component | Function |
|-----------|----------|
| **Fake Services** | SSH, HTTP, HTTPS, MySQL, RDP, FTP banners with interaction logging |
| **Decoy SMB** | Finance / HR / Backups share probes (port 4450 by default) |
| **Honey Tokens** | Beaconing cloud keys that alert on external use |
| **Canary Files** | Client-tailored decoy documents with trail links |
| **Intent Classification** | Turns raw events into “what the attacker was trying to do” |
| **Story Reports** | Owner-readable narratives instead of log dumps |
| **Real-time Alerts** | Console + optional webhook |
| **Authorization** | Required ROE reference + action logging |
| **Lightweight** | Pure Python, modest hardware, Pi / small VPS friendly |

---

## Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/Mirage.git
cd Mirage
pip install -r requirements.txt
pip install -e .

mirage init --org "Acme Medical" --auth-ref ROE-2026-001 --sector clinic
# optional: --beacon-url https://beacon.yourdomain.tt

mirage deploy
mirage status
mirage alerts
mirage report --story
mirage bait --sector clinic    # preview trails + tokens + sector bait
```

Deploy starts:
1. Fake network services  
2. Canaries + breadcrumb trails + beacon tokens  
3. Decoy SMB shares  
4. Local beacon listener (unless you set a public `--beacon-url`)

---

## Typical Engagement Flow

1. Sign Rules of Engagement with the client  
2. `mirage init --org "..." --auth-ref "..." --sector ...`  
3. `mirage deploy`  
4. Leave running (or manage via systemd)  
5. Attacker interaction → real-time alert + intent classification  
6. Deliver the **story report** — the document that converts sceptics and drives renewals  

This converts a one-time audit into ongoing active defense and recurring revenue.

---

## Continuous Protection Package

| Component | Role |
|-----------|------|
| **FortifyOne** | Professional point-in-time network audit |
| **Sentinel** | Continuous monitoring, FIM, reverse-shell detection |
| **Mirage** | Active deception (this tool) |

Together these form a practical security offering for Trinidad & Tobago and Caribbean SMBs.

---

## Roadmap

**Shipped**  
Story report · Decoy factory · Intent engine · Breadcrumb trails · Beaconing tokens · Decoy SMB

**Next**  
SSH credential-harvesting jail (Feature 06) · Multi-site mesh · Coverage heatmap · Legal-grade evidence · Realism rotation · Anti-abuse guardrails

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
