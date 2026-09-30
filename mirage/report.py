from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .config import ensure_data_dir, load_config
from .db import get_recent_events


def generate_report(hours: int = 24, client_mode: bool = False) -> str:
    events = get_recent_events(hours=hours)
    cfg = load_config()
    org = cfg.get("organization_name") or "Client"
    auth_ref = cfg.get("authorization_ref") or "N/A"

    lines = []

    if client_mode:
        lines.append(f"# Active Deception Summary — {org}")
        lines.append(f"**Prepared by:** TrinTech Digital Defense")
        lines.append(f"**Period:** Last {hours} hours")
        lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
        lines.append(f"**Authorization Reference:** {auth_ref}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Executive Summary")
        if not events:
            lines.append(
                "No attacker interaction with deception assets was observed during this period. "
                "The decoy services and canary files remain active and ready."
            )
        else:
            lines.append(
                f"**{len(events)} deception event(s)** were recorded. "
                "This means someone interacted with a fake service or decoy file that should never be touched by legitimate users."
            )
            lines.append("")
            lines.append("These events are high-signal indicators of reconnaissance or compromise activity.")
    else:
        lines.append("# Mirage Operator Report")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
        lines.append(f"Window: last {hours} hours | Auth: {auth_ref}")
        lines.append("")

    lines.append(f"Total events: {len(events)}")
    lines.append("")

    if events:
        lines.append("## Events")
        for e in events:
            details = e.get("details") or "{}"
            if isinstance(details, str):
                try:
                    import json
                    details = json.loads(details)
                except Exception:
                    details = {}
            lines.append(
                f"- **{e.get('timestamp')}** | `{e.get('event_type')}` | "
                f"Source: `{e.get('source_ip') or 'n/a'}` | {details}"
            )
        lines.append("")

    if client_mode and events:
        lines.append("## What This Means")
        lines.append(
            "Legitimate staff do not connect to decoy SSH/HTTP/MySQL services or open planted credential files. "
            "Any interaction is a strong signal that should be investigated."
        )
        lines.append("")
        lines.append("## Recommended Next Steps")
        lines.append("1. Identify the source IP(s) and determine whether they are internal or external.")
        lines.append("2. Check logs on real systems for related activity around the same timestamps.")
        lines.append("3. If the source is unexpected, isolate the affected segment and contact TrinTech for deeper investigation.")
        lines.append("4. Do not delete or modify the decoy assets — they remain valuable sensors.")

    lines.append("")
    lines.append("---")
    lines.append("Mirage by TrinTech Digital Defense | Authorized defensive use only")
    lines.append("This report is confidential and intended solely for the authorized recipient.")

    text = "\n".join(lines)

    reports_dir = ensure_data_dir() / "reports"
    reports_dir.mkdir(exist_ok=True)
    suffix = "client" if client_mode else "operator"
    fname = f"mirage_report_{suffix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    (reports_dir / fname).write_text(text, encoding="utf-8")
    return text
