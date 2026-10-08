# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹

Lightweight deception layer for networks that have no security team.  
Fake services, honey tokens, and canary files turn attacker interaction into clear, actionable alerts.

Designed for Caribbean SMBs. Self-hosted or run as a managed service by TrinTech.  
Pairs with **Sentinel** (continuous monitoring) and **FortifyOne** (professional audit).

---

## What Clients Actually Receive

> “An attacker from 203.0.113.45 tried to log in to the fake admin account on the decoy SSH service at 14:22 UTC.”

That is the kind of report business owners understand and act on.

---

## Core Capabilities

| Component | Function |
|-----------|----------|
| **Fake Services** | Realistic SSH, HTTP, HTTPS, MySQL, RDP, FTP, SMB banners with interaction logging |
| **Honey Tokens** | Decoy credentials and tokens that alert the moment they are used |
| **Canary Files** | Attractive decoy files (credentials, VPN configs, financials, API keys) |
| **Real-time Alerts** | Console + JSON + optional webhook (WhatsApp / Telegram / email) |
| **Client Reports** | Clean summaries focused on who touched what and when |
| **Authorization** | Required ROE reference + action logging |
| **Lightweight** | Python, modest hardware, Raspberry Pi / small VPS friendly |

---

## Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/Mirage.git
cd Mirage
pip install -r requirements.txt
pip install -e .

mirage init --org "Client Name" --auth-ref ROE-2026-001
mirage deploy
mirage status
mirage alerts
mirage report --client
mirage stop
```

---

## Typical Engagement Flow

1. Sign Rules of Engagement with the client
2. `mirage init --org "..." --auth-ref "..."`
3. `mirage deploy`
4. Leave running (or manage via systemd)
5. Attacker interaction → real-time alert
6. Deliver clean client report

This converts a one-time audit into ongoing active defense and recurring value.

---

## Continuous Protection Package

| Component | Role |
|-----------|------|
| **FortifyOne** | Professional point-in-time network audit |
| **Sentinel** | Continuous monitoring, FIM, reverse-shell detection |
| **Mirage** | Active deception (this tool) |

Together these form a practical security offering for Trinidad & Tobago and Caribbean SMBs.

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
