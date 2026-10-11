"""Canary / decoy files and honey tokens.

Feature 02 — Decoy document factory
Feature 05 — Breadcrumb trails
Feature 07 — Beaconing honey tokens
Feature 13 — Industry packs
Feature 14 — AD decoy accounts
Feature 16 — Email-borne canaries
"""

from __future__ import annotations

import os
import time
import threading
import logging
from pathlib import Path
from typing import Callable, List, Dict, Optional, Any

from .beacons import generate_tokens, tokens_to_env_file
from .trails import build_trail_documents, save_trail_meta, load_trail_meta, resolve_hop
from .packs import pack_extra_docs
from .email_canary import generate_email_canaries, render_invoice_canary, render_html_canary
from .ad_decoy import render_accounts_file

logger = logging.getLogger("mirage.canaries")


def _build_default_baits(
    org: str = "Company",
    sector: str = "general",
    beacon_base: str = "",
    include_trails: bool = True,
) -> List[Dict[str, str]]:
    org = org or "Company"
    sector = (sector or "general").lower()

    if sector in ("clinic", "medical", "healthcare", "health"):
        finance_name = "Patient_Billing_Summary_Q2.txt"
        finance_body = (
            f"CONFIDENTIAL — {org} Clinical Operations\n"
            f"Q2 Patient Billing Summary\n"
            f"Total billed: TT$ 1.85M\n"
            f"Outstanding AR: TT$ 312k\n"
            f"# Decoy canary — interaction triggers alert\n"
        )
        extra = {
            "name": "patient_records_index",
            "relpath": "records/patient_index_snippet.txt",
            "content": (
                f"{org} — Restricted Patient Index (sample)\n"
                f"For authorized clinical staff only.\n"
                f"# DECOY FILE\n"
            ),
        }
    elif sector in ("retail", "pos", "shop", "store"):
        finance_name = "Supplier_Invoices_Pending.txt"
        finance_body = (
            f"{org} — Accounts Payable\n"
            f"PO-88421  TT$ 48,200  due 2026-10-15\n"
            f"# Decoy canary\n"
        )
        extra = {
            "name": "pos_config",
            "relpath": "pos/terminal_config.bak",
            "content": (
                f"# {org} POS terminal backup\n"
                f"MERCHANT_ID=DECOY8821\n"
                f"TERMINAL_KEY=sk_live_decoy_do_not_use\n"
                f"# Honey token\n"
            ),
        }
    elif sector in ("legal", "law", "firm"):
        finance_name = "Matter_Trust_Summary.txt"
        finance_body = (
            f"{org} — Trust Account Summary (CONFIDENTIAL)\n"
            f"Client funds held — internal only\n"
            f"# Decoy canary\n"
        )
        extra = {
            "name": "matter_index",
            "relpath": "matters/active_matters_index.txt",
            "content": f"{org} Active Matters Index — Privileged\n# DECOY\n",
        }
    else:
        finance_name = "Q2_Board_Report.txt"
        finance_body = (
            f"CONFIDENTIAL — {org} Board Eyes Only\n"
            f"Q2 Revenue: TT$ 4.2M\n"
            f"# This is a decoy canary file\n"
        )
        extra = None

    tokens = generate_tokens(org=org, count=2, beacon_base=beacon_base)
    secrets_content = tokens_to_env_file(tokens, org=org)
    email_cans = generate_email_canaries(org=org, beacon_base=beacon_base, count=1)

    baits: List[Dict[str, Any]] = [
        {
            "name": "db_credentials",
            "relpath": "config/db_credentials.txt",
            "content": (
                f"# {org} — Production Database Credentials — CONFIDENTIAL\n"
                f"DB_HOST=10.0.0.15\nDB_USER=admin\nDB_PASS=Pr0d_S3cure_2026!\n"
                f"DB_NAME={org.lower().replace(' ', '_')}_erp\n"
                f"# DECOY — any use or modification alerts\n"
            ),
        },
        {
            "name": "vpn_config",
            "relpath": "config/company-vpn.ovpn",
            "content": (
                f"# {org} corporate VPN profile\nclient\ndev tun\nproto udp\n"
                f"remote vpn.internal.{org.lower().replace(' ', '')}.tt 1194\n"
                f"auth-user-pass\n# DECOY\n"
            ),
        },
        {
            "name": "api_keys_beacon",
            "relpath": "secrets/api_keys.env",
            "content": secrets_content,
            "beacon_token_ids": [t["id"] for t in tokens],
        },
        {
            "name": "financial_report",
            "relpath": f"finance/{finance_name}",
            "content": finance_body,
        },
        {
            "name": "admin_password",
            "relpath": "admin/passwords.txt",
            "content": (
                f"# {org} privileged accounts — DO NOT DISTRIBUTE\n"
                f"admin:Tr1nTech_Admin_2026!\nroot:ChangeMeImmediately!\nbackup:B@ckup_S3cret\n"
                f"# See shares/README_Finance.txt for drive mappings\n"
            ),
        },
        {
            "name": "ad_decoy_accounts",
            "relpath": "admin/domain_accounts_export.txt",
            "content": render_accounts_file(org),
        },
        {
            "name": "email_invoice_canary",
            "relpath": "finance/INV-DECOY-8841.txt",
            "content": render_invoice_canary(org, email_cans),
            "beacon_token_ids": [c["id"] for c in email_cans],
        },
        {
            "name": "email_invoice_html",
            "relpath": "finance/INV-DECOY-8841.html",
            "content": render_html_canary(org, email_cans),
            "beacon_token_ids": [c["id"] for c in email_cans],
        },
    ]

    if extra:
        baits.append(extra)

    # Industry pack extras (Feature 13)
    for doc in pack_extra_docs(sector, org=org):
        baits.append(doc)

    if include_trails:
        trail_docs, _meta = build_trail_documents(org=org)
        for td in trail_docs:
            if td["relpath"] == "admin/passwords.txt":
                continue
            baits.append({
                "name": td["name"],
                "relpath": td["relpath"],
                "content": td["content"],
                "trail_node": td.get("trail_node"),
            })

    return baits


class CanaryManager:
    def __init__(
        self,
        base_dir: str,
        on_alert: Optional[Callable] = None,
        organization: str = "",
        sector: str = "general",
        beacon_base: str = "",
    ):
        self.base_dir = Path(base_dir)
        self.on_alert = on_alert
        self.organization = organization or "Company"
        self.sector = sector or "general"
        self.beacon_base = beacon_base or ""
        self.canaries: List[Dict] = []
        self.beacon_token_ids: List[str] = []
        self._watcher_thread = None
        self._running = False
        self._mtimes: Dict[str, float] = {}
        self._trail_meta: Dict[str, Any] = {}

    def generate_baits(self, org: str = None, sector: str = None) -> List[Dict[str, str]]:
        return _build_default_baits(
            org=org or self.organization,
            sector=sector or self.sector,
            beacon_base=self.beacon_base,
            include_trails=True,
        )

    def deploy(self, canary_defs: List[Dict] = None):
        defs = canary_defs or self.generate_baits()
        self.base_dir.mkdir(parents=True, exist_ok=True)

        trail_docs, trail_meta = build_trail_documents(org=self.organization)
        save_trail_meta(self.base_dir, trail_meta)
        self._trail_meta = trail_meta

        for c in defs:
            full = self.base_dir / c["relpath"]
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(c["content"], encoding="utf-8")
            try:
                os.chmod(full, 0o640)
            except OSError:
                pass
            self._mtimes[str(full)] = full.stat().st_mtime
            entry = {"name": c["name"], "path": str(full)}
            if c.get("trail_node"):
                entry["trail_node"] = c["trail_node"]
            self.canaries.append(entry)
            if c.get("beacon_token_ids"):
                self.beacon_token_ids.extend(c["beacon_token_ids"])
            logger.info("Canary deployed: %s", full)

        self._start_watcher()

    def _emit_canary_event(self, event_type: str, canary: Dict):
        details: Dict[str, Any] = {
            "canary": canary["name"],
            "path": canary["path"],
        }
        hop = resolve_hop(self._trail_meta or load_trail_meta(self.base_dir), canary["path"])
        if hop:
            details["trail"] = hop
            event_type = "trail_hop" if "node" in hop or "hop_from" in hop else event_type

        if self.on_alert:
            self.on_alert(event_type=event_type, source_ip="local", details=details)

    def _start_watcher(self):
        if self._running:
            return
        self._running = True

        def watch():
            while self._running:
                for c in self.canaries:
                    path = Path(c["path"])
                    try:
                        if not path.exists():
                            self._emit_canary_event("canary_deleted", c)
                            continue
                        mtime = path.stat().st_mtime
                        if mtime != self._mtimes.get(str(path)):
                            self._mtimes[str(path)] = mtime
                            self._emit_canary_event("canary_modified", c)
                    except OSError:
                        pass
                time.sleep(3)

        self._watcher_thread = threading.Thread(target=watch, daemon=True)
        self._watcher_thread.start()

    def stop(self):
        self._running = False

    def cleanup(self):
        self.stop()
        for c in self.canaries:
            try:
                Path(c["path"]).unlink(missing_ok=True)
            except OSError:
                pass
        meta = self.base_dir / ".mirage_trails.json"
        if meta.exists():
            try:
                meta.unlink()
            except OSError:
                pass
        self.canaries.clear()
        logger.info("Canary files removed")

    def status(self) -> List[Dict]:
        return [
            {
                "name": c["name"],
                "path": c["path"],
                "exists": Path(c["path"]).exists(),
                "trail_node": c.get("trail_node"),
            }
            for c in self.canaries
        ]
