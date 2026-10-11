"""Email-borne canary tokens — Feature 16.

Plantable tokens that travel: tracked links in decoy invoices and web-bug
style URLs embedded in canary documents. If opened anywhere, they phone
home via the same beacon endpoint used by Feature 07.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Dict, List


def _cid(prefix: str = "EM") -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


def generate_email_canaries(
    org: str = "Company",
    beacon_base: str = "",
    count: int = 2,
) -> List[Dict[str, Any]]:
    org = org or "Company"
    items: List[Dict[str, Any]] = []
    for i in range(count):
        tid = _cid()
        url = f"{beacon_base.rstrip('/')}/b/{tid}" if beacon_base else f"https://beacon.invalid/b/{tid}"
        items.append({
            "id": tid,
            "type": "email_link",
            "label": f"{org}_invoice_link_{i+1}",
            "url": url,
            "created": datetime.utcnow().isoformat() + "Z",
        })
        tid2 = _cid("WB")
        bug = f"{beacon_base.rstrip('/')}/b/{tid2}" if beacon_base else f"https://beacon.invalid/b/{tid2}"
        items.append({
            "id": tid2,
            "type": "web_bug",
            "label": f"{org}_doc_pixel_{i+1}",
            "url": bug,
            "created": datetime.utcnow().isoformat() + "Z",
        })
    return items


def render_invoice_canary(org: str, canaries: List[Dict[str, Any]]) -> str:
    link = next((c for c in canaries if c["type"] == "email_link"), None)
    bug = next((c for c in canaries if c["type"] == "web_bug"), None)
    lines = [
        f"{org} — Tax Invoice (COPY)",
        f"Date: {datetime.utcnow().strftime('%Y-%m-%d')}",
        "Invoice #: INV-DECOY-8841",
        "Amount due: TT$ 12,450.00",
        "",
        "View online / download PDF:",
        (link["url"] if link else "(no beacon url configured)"),
        "",
        "Payment terms: Net 15",
        "",
    ]
    if bug:
        # Plaintext stand-in for an HTML pixel — still triggers if fetched
        lines.append(f"[tracking: {bug['url']}]")
    lines.append("# DECOY DOCUMENT — interaction alerts")
    return "\n".join(lines) + "\n"


def render_html_canary(org: str, canaries: List[Dict[str, Any]]) -> str:
    bug = next((c for c in canaries if c["type"] == "web_bug"), None)
    link = next((c for c in canaries if c["type"] == "email_link"), None)
    pixel = f'<img src="{bug["url"]}" width="1" height="1" alt="" />' if bug else ""
    href = link["url"] if link else "#"
    return (
        f"<!DOCTYPE html><html><head><title>{org} Invoice</title></head>"
        f"<body><h1>{org} Invoice INV-DECOY-8841</h1>"
        f"<p>Amount due: TT$ 12,450.00</p>"
        f"<p><a href=\"{href}\">Download statement</a></p>"
        f"{pixel}"
        f"<!-- DECOY -->"
        f"</body></html>\n"
    )
