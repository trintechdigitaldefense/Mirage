"""Active Directory decoy accounts — Feature 14.

Creates believable-but-fake domain account records (svc_backup, finance_admin)
planted where attackers look. Any local 'use' of these credentials in decoy
files is already covered by canary watchers; this module materialises the
account list and optional honey password file for SMB/SSH jail correlation.

Full live AD integration requires Samba/AD on the decoy host and is documented
as an operator step — Mirage ships the content and event hooks here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


def default_decoy_accounts(org: str = "Company") -> List[Dict[str, str]]:
    org_slug = "".join(c if c.isalnum() else "" for c in (org or "Company"))[:12].lower() or "corp"
    return [
        {
            "sam": "svc_backup",
            "display": "Backup Service Account",
            "password": "B@ckup_S3rvice_2026!",
            "desc": "Scheduled backup jobs — do not disable",
            "ou": f"OU=ServiceAccounts,DC={org_slug},DC=local",
        },
        {
            "sam": "finance_admin",
            "display": "Finance Administrator",
            "password": "Fin@nce_Adm1n!",
            "desc": "ERP finance module admin",
            "ou": f"OU=Finance,DC={org_slug},DC=local",
        },
        {
            "sam": "svc_scan",
            "display": "Vulnerability Scanner",
            "password": "Sc@nner_ReadOnly1",
            "desc": "Read-only vulnerability scanner",
            "ou": f"OU=ServiceAccounts,DC={org_slug},DC=local",
        },
        {
            "sam": f"{org_slug}_helpdesk",
            "display": "Helpdesk Shared",
            "password": "Helpdesk_Temp2026",
            "desc": "Shared helpdesk — rotate monthly",
            "ou": f"OU=IT,DC={org_slug},DC=local",
        },
    ]


def render_accounts_file(org: str = "Company") -> str:
    accounts = default_decoy_accounts(org)
    lines = [
        f"# {org} — Privileged / service accounts (INTERNAL)",
        f"# Exported {datetime.utcnow().strftime('%Y-%m-%d')} — CONFIDENTIAL",
        f"# Domain: {org.lower().replace(' ', '')}.local",
        "",
        f"{'SAM':<22} {'Display':<28} {'Password':<24} OU",
        "-" * 100,
    ]
    for a in accounts:
        lines.append(
            f"{a['sam']:<22} {a['display']:<28} {a['password']:<24} {a['ou']}"
        )
    lines += [
        "",
        "# DECOY ACCOUNTS — any authentication attempt against these should alert",
        "# Plant in places attackers dump credentials; wire to Sentinel honeyauth when available",
    ]
    return "\n".join(lines) + "\n"


def accounts_as_dicts(org: str = "Company") -> List[Dict[str, Any]]:
    return default_decoy_accounts(org)
