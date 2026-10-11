"""Client-facing narrative reports for Mirage.

Feature 01 — The "We Caught Them" report:
Every interaction becomes a one-page narrative the owner can forward.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ensure_data_dir, load_config
from .db import get_recent_events
from .intent import classify_events, summarize_intents


def _parse_details(raw) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return {}


def _story_line(event: Dict[str, Any]) -> str:
    """Turn a single classified event into a plain-English sentence."""
    ts = event.get("timestamp", "")
    src = event.get("source_ip") or "unknown source"
    details = _parse_details(event.get("details"))
    cls = event.get("classification") or {}
    verdict = cls.get("verdict", "Interaction with a deception asset.")
    et = event.get("event_type", "")

    service = details.get("service")
    canary = details.get("canary")

    if "canary" in et:
        action = "deleted" if "deleted" in et else "modified/opened"
        target = canary or details.get("path") or "a decoy file"
        return f"At {ts}, source `{src}` {action} the planted decoy **{target}**. {verdict}"

    if service:
        return f"At {ts}, source `{src}` interacted with the fake **{service.upper()}** service. {verdict}"

    return f"At {ts}, source `{src}` triggered `{et}`. {verdict}"


def generate_story_report(hours: int = 24, client_mode: bool = True) -> str:
    """Feature 01 — narrative 'We Caught Them' report."""
    events = get_recent_events(hours=hours)
    cfg = load_config()
    org = cfg.get("organization_name") or "Client"
    auth_ref = cfg.get("authorization_ref") or "N/A"
    summary = summarize_intents(events)
    classified = summary.get("classified_events", [])

    lines: List[str] = []

    # Header
    lines.append(f"# We Caught Them — Active Deception Report")
    lines.append(f"**Client:** {org}")
    lines.append(f"**Prepared by:** TrinTech Digital Defense")
    lines.append(f"**Period:** Last {hours} hours")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append(f"**Authorization / ROE:** {auth_ref}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive narrative
    lines.append("## What Happened")
    lines.append("")
    if not events:
        lines.append(
            "No attacker interaction with any Mirage deception asset was observed in this period. "
            "The decoy services and planted documents remain live and ready. "
            "Silence is good news — the traps are still set."
        )
    else:
        n = len(events)
        primary = summary.get("primary_intent", "unknown")
        lines.append(
            f"**{n} high-signal event(s)** were recorded against deception assets that legitimate staff never touch."
        )
        lines.append("")
        lines.append(f"**Primary observed intent:** `{primary}`")
        lines.append("")
        lines.append(f"> {summary.get('verdict')}")
        lines.append("")
        lines.append(
            "These are not scanner noise. Someone (or something) interacted with fake services or decoy files "
            "that exist only to detect unauthorized activity."
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # Story timeline
    if classified:
        lines.append("## The Story (Timeline)")
        lines.append("")
        for e in classified:
            lines.append(f"- {_story_line(e)}")
            conf = e.get("classification", {}).get("confidence")
            techniques = e.get("classification", {}).get("attack_techniques") or []
            if techniques:
                lines.append(f"  - Confidence: {conf:.0%} · ATT&CK: {', '.join(techniques)}")
            else:
                lines.append(f"  - Confidence: {conf:.0%}")
        lines.append("")

    # What it proves
    lines.append("## What This Proves")
    lines.append("")
    if events:
        lines.append(
            "Legitimate users do not connect to decoy SSH/HTTP/MySQL/RDP services or open planted credential "
            "and financial files. Any interaction is therefore a strong indicator of reconnaissance, credential "
            "hunting, or active compromise activity on the network."
        )
        lines.append("")
        lines.append(
            "Without Mirage these actions would have left no clear, owner-readable signal. The traps converted "
            "silent probing into a concrete story you can act on."
        )
    else:
        lines.append(
            "The absence of interaction means no one walked into the traps during this window. "
            "That is the desired steady state. The sensors remain armed."
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # Recommended actions
    lines.append("## Recommended Next Steps")
    lines.append("")
    if events:
        lines.append("1. Identify every source IP above — determine whether it is internal, VPN, partner, or external.")
        lines.append("2. Correlate timestamps against real system logs, firewall, and authentication events.")
        lines.append("3. If the source is unexpected, isolate the segment and engage TrinTech for deeper investigation / evidence package.")
        lines.append("4. Do **not** delete or modify the decoy assets — they remain valuable sensors.")
        lines.append("5. Consider expanding coverage (additional decoys or multi-site mesh) if blind spots exist.")
    else:
        lines.append("1. Keep Mirage running — the value is continuous coverage, not only the days something is caught.")
        lines.append("2. Review coverage at next renewal: which subnets/services still lack decoys?")
        lines.append("3. Ensure the ROE and authorization reference remain current.")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Mirage by TrinTech Digital Defense · Trinidad & Tobago*  ")
    lines.append("*Authorized defensive deception only. This report is confidential.*  ")
    lines.append("*Defend. Detect. Dominate.*")

    text = "\n".join(lines)

    # Persist
    reports_dir = ensure_data_dir() / "reports"
    reports_dir.mkdir(exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_org = "".join(c if c.isalnum() or c in "-_" else "_" for c in org)[:30]
    fname = f"mirage_story_{safe_org}_{stamp}.md"
    (reports_dir / fname).write_text(text, encoding="utf-8")
    return text


def generate_report(hours: int = 24, client_mode: bool = False, story: bool = False) -> str:
    """Public entry point used by the CLI.

    - story=True  → Feature 01 narrative report
    - client_mode → lighter client summary (legacy path, now routes to story)
    - otherwise   → operator/raw view
    """
    if story or client_mode:
        return generate_story_report(hours=hours, client_mode=True)

    # Operator / raw view
    events = get_recent_events(hours=hours)
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref") or "N/A"
    classified = classify_events(events)

    lines = [
        "# Mirage Operator Report",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        f"Window: last {hours} hours | Auth: {auth_ref}",
        f"Total events: {len(events)}",
        "",
    ]

    if classified:
        lines.append("## Events (with intent)")
        for e in classified:
            details = _parse_details(e.get("details"))
            cls = e.get("classification", {})
            lines.append(
                f"- **{e.get('timestamp')}** | `{e.get('event_type')}` | "
                f"src=`{e.get('source_ip') or 'n/a'}` | intent=`{cls.get('intent')}` | "
                f"{cls.get('verdict', '')[:80]}"
            )
            lines.append(f"  details: {details}")
        lines.append("")

    lines.append("---")
    lines.append("Mirage by TrinTech Digital Defense | Authorized defensive use only")

    text = "\n".join(lines)
    reports_dir = ensure_data_dir() / "reports"
    reports_dir.mkdir(exist_ok=True)
    fname = f"mirage_operator_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    (reports_dir / fname).write_text(text, encoding="utf-8")
    return text
