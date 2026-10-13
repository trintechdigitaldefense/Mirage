# Mirage Client Deployment Checklist

Use this for every pilot or production deploy. Do not skip ROE or the live probe.

**Client:** _______________________________  
**ROE ref:** _______________________________  
**Operator:** _______________________________  
**Date:** _______________

---

## 1. Signed ROE

- [ ] ROE completed from `docs/ROE_TEMPLATE.md`
- [ ] Scope (networks / hosts) filled in
- [ ] No-attack-back section acknowledged
- [ ] Client and TrinTech signatures dated
- [ ] ROE reference string assigned (e.g. `ROE-2026-014`)

## 2. Written port map

- [ ] `docs/PORT_MAP_TEMPLATE.md` completed for this site
- [ ] Confirmed **no clash** with real SSH (22), RDP (3389), SMB (445)
- [ ] RDP decoy on non-standard port (default **33890**)
- [ ] Port map attached as ROE Appendix A

## 3. Initialize Mirage

```bash
mirage init --org "CLIENT NAME" --auth-ref ROE-XXXX-XXXX --sector clinic
# sectors: general | clinic | retail | legal | finance | hospitality
```

- [ ] Organization name set
- [ ] Authorization ref matches signed ROE
- [ ] Sector / pack selected
- [ ] Optional: `--beacon-url https://...` if external token callbacks are required

## 4. Deploy and confirm

```bash
mirage deploy
# separate terminal:
mirage health
mirage coverage
mirage status
```

- [ ] `mirage health` shows controls ON, circuit breaker OK
- [ ] `mirage coverage` acceptable for agreed scope
- [ ] Deploy process left running (or under process supervisor)

### Live probe (mandatory once per site)

```bash
curl -s http://127.0.0.1:8080/ | head
curl -s http://127.0.0.1:9000/ | head
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@127.0.0.1
# type: whoami  then  exit
mirage alerts
```

- [ ] HTTP decoy returns page and creates alert
- [ ] Cloud decoy returns listing and creates alert
- [ ] SSH jail accepts login and logs at least one command
- [ ] `mirage alerts` shows new events (not empty)

## 5. Alert and report agreement

Record who gets what and how often:

| Item | Agreed value |
|------|----------------|
| Alert recipients | |
| Channel (console / webhook URL / other) | |
| Critical events: notify within | e.g. 1 hour / same business day |
| `mirage report --story` cadence | Weekly / Monthly / Per critical event |
| `mirage evidence` | On request / After critical / End of month |

- [ ] Client contact confirmed the table above
- [ ] Webhook tested if used (`webhook_url` in config)
- [ ] First story report scheduled: _______________

## 6. Handoff

- [ ] Client has ROE copy + port map
- [ ] TrinTech has ROE ref in `mirage status`
- [ ] Heartbeat path noted: `~/.mirage/heartbeat.json`
- [ ] Evidence output path noted: `~/.mirage/evidence/`

**Operator sign-off:** _______________ **Date:** _______________

---

## Quick command card

```text
mirage init --org "..." --auth-ref ROE-... --sector ...
mirage deploy
mirage health && mirage coverage && mirage status
mirage alerts
mirage report --story
mirage evidence
mirage killswitch          # emergency quiet
mirage killswitch --reset
```

*Mirage v2.2 · TrinTech Digital Defense*
