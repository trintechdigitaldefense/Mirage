# Mirage Evidence Limitations

**Honest scope**

Mirage evidence bundles record **interactions with decoys** under an authorized Rules of Engagement (ROE).

They do **not**:

- Prove that a real production account was compromised
- Prove that real customer data was exfiltrated
- Constitute a court-certified or TSA-timestamped signature chain by default
- Replace forensic acquisition of real systems

**Integrity**

- `events.json` is hashed with SHA-256
- HMAC-SHA256 is computed with a key stored at `~/.mirage/keys/evidence_hmac.key` (**outside** the evidence directory)
- Verify: `mirage evidence --verify /path/to/bundle.zip`

**Allowed uses**

- Internal detection validation and incident narrative
- Support material for insurance / IR under your contract and ROE
- Sharing with law enforcement when your counsel and ROE permit

**SMB / HTTPS claims**

- SMB decoys are **low-interaction** tripwires, not full file servers
- HTTPS is **disabled** until real TLS termination exists
