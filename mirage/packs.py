"""Industry decoy packs — Feature 13.

Pre-authored deception content per vertical. Packs are content, not code:
YAML-style topologies expressed as Python dicts selected via --sector / --pack.
"""

from __future__ import annotations

from typing import Any, Dict, List


PACKS: Dict[str, Dict[str, Any]] = {
    "general": {
        "label": "General business",
        "share_names": ["Finance", "HR", "Backups"],
        "extra_docs": [],
    },
    "clinic": {
        "label": "Clinic / healthcare",
        "share_names": ["PatientRecords", "Billing", "Imaging"],
        "extra_docs": [
            {
                "name": "hl7_feed_note",
                "relpath": "integration/hl7_endpoint.txt",
                "content": (
                    "HL7 feed endpoint (internal)\n"
                    "host=hl7.internal\n"
                    "port=2575\n"
                    "# DECOY — clinical integration notes\n"
                ),
            },
            {
                "name": "pacs_access",
                "relpath": "imaging/pacs_credentials.txt",
                "content": (
                    "PACS workstation credentials\n"
                    "user=pacs_tech\n"
                    "pass=Imaging_2026!\n"
                    "# DECOY\n"
                ),
            },
        ],
    },
    "retail": {
        "label": "Retail / POS",
        "share_names": ["POS", "Inventory", "SupplierInvoices"],
        "extra_docs": [
            {
                "name": "pos_batch",
                "relpath": "pos/end_of_day_batch.txt",
                "content": (
                    "EOD settlement batch reference\n"
                    "merchant=DECOY8821\n"
                    "# DECOY\n"
                ),
            },
        ],
    },
    "legal": {
        "label": "Law firm",
        "share_names": ["Matters", "Trust", "Discovery"],
        "extra_docs": [
            {
                "name": "trust_ledger",
                "relpath": "trust/ledger_export_note.txt",
                "content": (
                    "Trust ledger export path\n"
                    "\\\\files\\Trust\\Exports\\n"
                    "# Privileged — DECOY\n"
                ),
            },
        ],
    },
    "finance": {
        "label": "Financial services",
        "share_names": ["Treasury", "Compliance", "CustomerKYC"],
        "extra_docs": [
            {
                "name": "swift_note",
                "relpath": "treasury/swift_ops.txt",
                "content": (
                    "SWIFT operations contact sheet\n"
                    "BIC=DECOYTTTX\n"
                    "# DECOY — not a real endpoint\n"
                ),
            },
        ],
    },
    "hospitality": {
        "label": "Hotel / hospitality",
        "share_names": ["Reservations", "PMS", "Housekeeping"],
        "extra_docs": [
            {
                "name": "pms_export",
                "relpath": "pms/guest_export_sample.txt",
                "content": (
                    "PMS guest export sample\n"
                    "Do not email externally\n"
                    "# DECOY\n"
                ),
            },
        ],
    },
}


def list_packs() -> List[Dict[str, str]]:
    return [{"id": k, "label": v["label"]} for k, v in PACKS.items()]


def get_pack(sector: str) -> Dict[str, Any]:
    key = (sector or "general").lower()
    # aliases
    aliases = {
        "medical": "clinic",
        "healthcare": "clinic",
        "health": "clinic",
        "pos": "retail",
        "shop": "retail",
        "store": "retail",
        "law": "legal",
        "firm": "legal",
        "hotel": "hospitality",
        "tourism": "hospitality",
        "bank": "finance",
        "insurance": "finance",
    }
    key = aliases.get(key, key)
    return PACKS.get(key, PACKS["general"])


def pack_share_names(sector: str) -> List[str]:
    return list(get_pack(sector).get("share_names") or ["Finance", "HR", "Backups"])


def pack_extra_docs(sector: str, org: str = "Company") -> List[Dict[str, str]]:
    docs = []
    for d in get_pack(sector).get("extra_docs") or []:
        content = d["content"]
        if "{org}" in content:
            content = content.replace("{org}", org)
        docs.append({
            "name": d["name"],
            "relpath": d["relpath"],
            "content": content if org in content or True else content,
        })
    return docs
