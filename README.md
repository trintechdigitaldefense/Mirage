# Mirage — Active Deception Platform

**TrinTech Digital Defense** · **v2.4**

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
```

## v2.4 highlights

| Feature | Detail |
|---------|--------|
| **SSH + Telnet sandboxes** | Command logging only — no real OS execution (ports 2222 / 2323) |
| **Web API decoys** | `/.env`, `/wp-login.php`, `/api/v1/auth`, `/admin/config.json` on **8081** |
| **TCP tarpit / sinkhole** | Local slow-down only — **never** reflects traffic to the attacker |
| **Micro-segmentation** | Optional iptables DROP via Sentinel (`sentinel_firewall_drop=false` by default) |
| **Credential injection** | `id_rsa_decoy`, `~/.aws`-style files, browser session notes under `~/.mirage/decoys/` |
| **Document web-bugs** | `Passwords_2026.html`, `Network_Topology.pdf` with beacon callbacks |
| **MITRE mapper** | Every alert → `~/.mirage/siem_events.jsonl` with technique IDs |

## Probe

```bash
mirage deploy
curl -s http://127.0.0.1:8081/.env
curl -s http://127.0.0.1:8081/wp-login.php
curl -s -X POST http://127.0.0.1:8081/api/v1/auth -d 'user=a&pass=b'
mirage alerts
tail ~/.mirage/siem_events.jsonl
```

## Doctrine

Passive by default. No attack-back. Sinkhole = local tarpit only. Firewall isolation requires explicit ROE + config.

*Defend. Detect. Dominate.*
