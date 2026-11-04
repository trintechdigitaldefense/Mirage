# Mirage — Active Deception Platform

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹  
**v2.3** — recon interruption + honey credentials + Sentinel hook

Fake services, SSH jail, tarpits, DNS canaries, honey tokens, trails, SMB, cloud decoys — turned into owner-readable stories and legal-grade evidence.

---

## One command — pull & upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
```

```bash
cd /path/to/Mirage && bash start.sh upgrade && bash start.sh deploy
```

---

## v2.3 features

| Area | What |
|------|------|
| **Dynamic banner mutator** | IIS / Cisco / Apache / Win SMB banners; per-connection mutation confuses Nmap/Shodan |
| **TCP tarpit** | Slow drip on decoy ports (default 2223, 3391, 4451) to burn scanner threads |
| **Honey credentials** | `.env`, `aws_credentials`, `config.json` pointing at Mirage ports |
| **DNS canaries** | UDP listener (5353) for `backup-vault.local`, `dev-db-admin.internal.local`, … |
| **Redis / Postgres / Elastic** | Low-interaction decoys with authentic-looking errors |
| **HTTP admin capture** | POST credentials logged; returns 500 / Invalid Gateway |
| **Attack profiler** | Multi-decoy sequences → port_sweeper / credential_stuffing / MITRE tags |
| **Sentinel hook** | JSONL + optional Unix socket; firewall DROP **off** unless ROE enables it |

Default ports avoid production: SSH jail **2222**, RDP **33890**, SMB **4450**, Redis **63790**, Postgres **54320**, DNS canary **5353**.

`sentinel_firewall_drop` defaults to **false** (observe-only). Enable only with written ROE for active response.

---

## Quick start

```bash
mirage init --org "Acme Medical" --auth-ref ROE-2026-001 --sector clinic
mirage agree --recipients "ops@acme.tt" --channel both --cadence weekly
mirage deploy
mirage health
# probe
curl -s http://127.0.0.1:8080/
curl -s http://127.0.0.1:9000/
dig @127.0.0.1 -p 5353 backup-vault.local
mirage alerts
mirage report --story
```

---

## Doctrine

Passive observation by default. No relay, no attack-back. Rate limits + circuit breaker. Firewall drops require explicit config + ROE.

---

**TrinTech Digital Defense** · trintechdigitaldefense@gmail.com · +1 (868) 362-0679  

*Defend. Detect. Dominate.*
