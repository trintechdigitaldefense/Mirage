# Mirage v2.0 — Active Deception Platform

**TrinTech Digital Defense**

Always-on deception layer for non-SOC environments.  
Fake services, decoy credentials, honey tokens, and canary files that turn attacker interaction into clear, real-time alerts.

Designed for Caribbean SMBs with zero security staff.  
Self-hosted or run as a managed service by TrinTech.

---

## What You Get Instead of Another CVE List

> “An attacker from 203.0.113.45 tried to log in to the fake admin account on the decoy SSH service at 14:22 UTC.”

That is the report clients actually understand and act on.

---

## Core Capabilities (v2.0)

| Component | What it does |
|-----------|--------------|
| **Fake Services** | Realistic SSH, HTTP, HTTPS, MySQL, RDP, FTP, SMB banners + light interaction logging |
| **Honey Tokens** | Decoy credentials and tokens that alert the moment they are used or exfiltrated |
| **Canary Files** | Attractive decoy files (credentials, VPN configs, financials, API keys) that trigger on access/modification |
| **Real-time Alerts** | Console + JSON log + optional webhook (WhatsApp / Telegram / email) |
| **Client Reports** | Clean “we caught them” summaries instead of technical noise |
| **Authorization** | Required ROE reference + action logging |
| **Lightweight** | Python, modest hardware, Raspberry Pi / small VPS friendly |

---

## Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/mirage.git
cd mirage
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

## Typical Deployment Flow

1. Sign Rules of Engagement with the client.
2. `mirage init --org "..." --auth-ref "..."`
3. `mirage deploy` (starts fake services + canary files + honey tokens)
4. Leave it running (or manage via systemd).
5. When an attacker touches a decoy → real-time alert.
6. Deliver clean client report: who touched what and when.

This turns a one-time engagement into continuous active defense and monthly recurring value.

---

## Authorized Use Only

Mirage is for authorized defensive deception only.  
Deploy only on networks you own or have explicit written permission to protect.  
Unauthorized use may violate the Trinidad and Tobago Cybercrimes Act.

---

## Contact

TrinTech Digital Defense  
Email: trintechdigitaldefense@gmail.com  
WhatsApp: +1-868-362-0679  
Website: https://trintechdigitaldefense.github.io/

Built in Trinidad & Tobago for the Caribbean.
