# Rules of Engagement — Mirage Active Deception

**TrinTech Digital Defense**  
**Document type:** Authorization / Rules of Engagement (ROE)  
**Classification:** Confidential

---

## 1. Parties

| Role | Name | Contact |
|------|------|---------|
| **Client (Authorizing Party)** | _______________________________ | _______________________________ |
| **Provider** | TrinTech Digital Defense | trintechdigitaldefense@gmail.com · +1 (868) 362-0679 |
| **Primary client contact** | _______________________________ | _______________________________ |
| **Technical contact** | _______________________________ | _______________________________ |

**ROE reference (use in Mirage):** `ROE-________-____`  
**Engagement / site name:** _______________________________

---

## 2. Authorization

The Client authorizes TrinTech Digital Defense to deploy and operate the **Mirage** active deception platform on the systems and network ranges listed in **Section 3**, solely for defensive monitoring and early detection of unauthorized activity.

This authorization is limited to the scope below. Activity outside this scope is not permitted.

---

## 3. Scope

### In scope

| Item | Detail |
|------|--------|
| Network ranges / VLANs | _______________________________________________ |
| Host(s) running Mirage | _______________________________________________ |
| Physical / cloud location | _______________________________________________ |
| Business hours / monitoring window | _______________________________________________ |
| Sector pack | general / clinic / retail / legal / finance / hospitality |

### Out of scope (explicit)

- Any system or network **not** listed above  
- Production data stores, real credentials, or live customer databases  
- Third-party networks, ISPs, or systems the Client does not own or administer  
- Offensive testing, vulnerability exploitation, or “hacking back”  

---

## 4. Approved decoy ports (site port map)

Only the ports listed here may be bound by Mirage on in-scope hosts. **Do not use ports already serving real production services** (especially real SSH 22, real RDP 3389, real SMB 445).

| Decoy role | Port | Enabled (Y/N) | Notes |
|------------|------|---------------|-------|
| SSH jail | 2222 | | Fake interactive login; logs commands |
| HTTP admin decoy | 8080 | | |
| HTTPS admin decoy | 8443 | | |
| MySQL decoy | 3307 | | |
| FTP decoy | 2121 | | |
| RDP decoy | 33890 | | Non-standard; avoid 3389 if real RDP exists |
| SMB decoy | 4450 | | Avoid 445 if real file shares exist |
| Beacon listener | 8888 | | Honey-token callbacks |
| Cloud decoy bucket | 9000 | | Fake open storage listing |

Attach a completed **Port Map** (`docs/PORT_MAP_TEMPLATE.md`) as Appendix A.

---

## 5. Doctrine — no attack-back

Mirage and TrinTech personnel operating under this ROE shall:

1. **Observe and record only** — decoys may accept connections and log interaction; they must not pivot, exploit, or attack the source.  
2. **Not relay traffic** through Client systems to third parties.  
3. **Not place real production secrets** inside decoy files or services.  
4. **Not engage** the suspected attacker outside the Client’s authorized systems.  
5. **Respect rate limits and kill-switch** controls built into Mirage so the deployment cannot be abused as a reflector or flood source.

Any response beyond alerting, reporting, and evidence export requires a **separate written authorization** from the Client.

---

## 6. Alerts and reporting

| Item | Agreement |
|------|-----------|
| Alert recipients (names / channels) | _______________________________________________ |
| Primary channel (console / webhook / email / WhatsApp) | _______________________________________________ |
| Escalation contact (after hours) | _______________________________________________ |
| Story report cadence | Weekly / Monthly / After each critical event / Other: _______ |
| Evidence export | On request / After critical event / End of engagement |

Critical classes (SSH jail login/commands, beacon hits, trail hops, cloud decoy access, canary tamper) should be notified **as soon as practical**, not only on the scheduled report.

---

## 7. Duration and termination

| Item | Date / condition |
|------|------------------|
| Start date | _______________ |
| End date (or “until terminated”) | _______________ |
| Either party may terminate by written notice | _______________ days |

On termination, TrinTech will stop Mirage listeners, remove or hand over decoy artifacts as agreed, and provide a final report if requested.

---

## 8. Confidentiality and evidence

- Findings, reports, and evidence bundles are confidential to the Client and TrinTech.  
- Evidence packages may include timestamps, source IPs, interaction details, and integrity hashes for insurer, counsel, or law enforcement at the Client’s direction.  
- TrinTech will not disclose engagement details to third parties except as required by law or with Client consent.

---

## 9. Acknowledgement

By signing, the Client confirms they own or are legally authorized to monitor the in-scope systems, have read the no-attack-back doctrine, and approve the port map in Appendix A.

| | Client | TrinTech Digital Defense |
|--|--------|---------------------------|
| **Name** | | |
| **Title** | | |
| **Signature** | | |
| **Date** | | |

---

*Mirage · TrinTech Digital Defense · Trinidad & Tobago*  
*Authorized defensive deception only.*
