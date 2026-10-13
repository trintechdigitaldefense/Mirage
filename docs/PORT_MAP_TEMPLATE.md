# Mirage Site Port Map

**Client:** _______________________________  
**Site / hostname:** _______________________________  
**ROE reference:** `ROE-________-____`  
**Date:** _______________  
**Prepared by:** _______________________________

---

## Rule

Decoy ports must **not** collide with real production services on the same host or VIP.

| Real service (do not steal) | Typical port | Mirage default decoy |
|-----------------------------|--------------|----------------------|
| Real SSH | 22 | **2222** (SSH jail) |
| Real HTTP | 80 | **8080** |
| Real HTTPS | 443 | **8443** |
| Real MySQL | 3306 | **3307** |
| Real FTP | 21 | **2121** |
| Real RDP | 3389 | **33890** |
| Real SMB | 445 | **4450** |

---

## Approved map for this site

| Decoy | Port | Bind address | Enabled | Conflicts checked (Y/N) | Notes |
|-------|------|--------------|---------|-------------------------|-------|
| SSH jail | 2222 | 0.0.0.0 / ____ | Y / N | | Command-logging trap |
| HTTP | 8080 | | Y / N | | Fake admin portal |
| HTTPS | 8443 | | Y / N | | |
| MySQL | 3307 | | Y / N | | |
| FTP | 2121 | | Y / N | | |
| RDP | 33890 | | Y / N | | Avoid 3389 |
| SMB | 4450 | | Y / N | | Shares: ________ |
| Beacon | 8888 | | Y / N | | Public URL if used: ________ |
| Cloud decoy | 9000 | | Y / N | | Fake bucket listing |

---

## Host firewall / security group notes

- Allow decoy ports only from networks where attacker traffic might appear (or leave open if that is the point of the trap).  
- Management access to the Mirage host should use **real** admin channels, not decoy ports.  
- Document any cloud security-group changes here: _______________________________________________

---

## Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Client technical contact | | | |
| TrinTech operator | | | |

*Attach to ROE as Appendix A.*
