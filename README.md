<div align="center">

# Mirage v1.0.0 — TrinTech Deception Grid

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20termux%20%7C%20raspberry%20pi-lightgrey.svg)](https://github.com/trintechdigitaldefense/Mirage)
[![TrinTech Digital Defense](https://img.shields.io/badge/TrinTech-Digital%20Defense-red.svg)](https://trintechdigitaldefense.github.io)

**A lightweight deception framework that tricks attackers by deploying fake network services and decoy files across your network. When an attacker touches a decoy, you get an instant alert.**

*Zero external dependencies. Runs on Python stdlib + optional scapy. No Docker. No cloud. No enterprise license.*

</div>

---

## How It Works


```
┌────────────────────────────┐
│        ATTACKER            │
│   (scans your network)      │
└──────────┬─────────────────┘
│
┌────────────────────┼────────────────────┐
▼                    ▼                    ▼
┌──────────┐       ┌────────────────┐    ┌──────────────┐
│ Decoy    │       │ Decoy          │    │ Decoy        │
│ SSH      │       │ HTTP Server    │    │ MySQL Server │
│ (port 22)│       │ (port 80)      │    │ (port 3306)  │
└──────────┘       └────────────────┘    └──────────────┘
│                    │                    │
└────────────────────┼────────────────────┘
▼
┌─────────────────────┐
│   ALERT SYSTEM      │
│  - JSON log file    │
│  - Terminal output  │
│  - WhatsApp link    │
│  - Email (optional) │
└─────────────────────┘
```

## Two Decoy Types

| Type | What It Does | Example |
|------|-------------|---------|
| **Skeleton** (Network) | Pretends to be real services on common ports | SSH, HTTP, MySQL, nginx on ports 22, 80, 443, 3306, 8080 |
| **Trigger** (Filesystem) | Creates fake juicy files an attacker would steal | `db_credentials.txt`, `vpn.ovpn`, `q2_report.xlsx` |

---

## What Happens When An Attacker Hits a Decoy

```text
Time:  2026-07-27T12:00:00Z
Event: DECOY_CONNECTED
Data:  port=22, source_ip=192.168.1.105

Warning on screen:
WhatsApp alert link generated:
Email alert sent (if configured):

```
You see **exactly** who touched what and when. No alarms. Just data.
## The "Impossible" Part
| Metric | Mirage | Enterprise Deception (e.g. TrapX, Attivo) |
|---|---|---|
| **Cost** | $0 | $10k–$100k+/year |
| **Dependencies** | 0 (stdlib) | Docker, Kubernetes, agents, orchestrators |
| **Deploy time** | 3 seconds | 3 days |
| **Hardware needed** | Any Linux box or Raspberry Pi | Enterprise-grade servers |
| **Lines of code** | ~1,600 | Millions |
Most cybersecurity firms say *"deception tech is only for big enterprises with big budgets."*
Mirage proves that's a lie.
## Quick Start & Reference
Clone the repository and run Mirage directly using python:
```bash
git clone [https://github.com/trintechdigitaldefense/Mirage.git](https://github.com/trintechdigitaldefense/Mirage.git)
cd Mirage

# Command Reference
python3 -m mirage deploy --network 192.168.1.0/24    # Start the deception grid
python3 -m mirage alerts                               # View triggered alerts
python3 -m mirage status                               # Check what's running
python3 -m mirage kill                                  # Stop everything
python3 -m mirage clean                                 # Remove all decoy files

```
## Testing Your Deployment
While Mirage is running in a primary terminal, test it locally in a second terminal:
```bash
curl http://localhost:80
python3 -m mirage alerts

```
You should see decoy_connect events immediately logged.
## Use Cases
 1. **Small Business Network** — Deploy on a Raspberry Pi or low-power device in the wiring closet. If an attacker taps in, you know instantly.
 2. **Pen Test Engagement** — Leave decoys running to detect lateral movement during client assessments.
 3. **Home Lab** — Practice detection engineering. Simulate real attacks, watch the alerts come in.
 4. **Classroom Demo** — Show students exactly how honeypots work in 60 seconds.
## What Makes It TrinTech
> *"We build tools that shouldn't be possible, for the people who can't afford the ones that are."*
> 
Mirage is a security auditing and deception utility created by **TrinTech Digital Defense**. It is specifically designed for Caribbean SMBs, medical clinics, and law firms who require robust enterprise-grade security visibility on a shoestring budget.
## Author & License
 * **Author:** Jason Junior Ramdharry
 * **Organization:** TrinTech Digital Defense
 * **Website:** trintechdigitaldefense.github.io
 * **License:** Distributed under the MIT License. For authorized security testing and defensive operations only.
```

```
