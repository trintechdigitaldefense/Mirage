"""Canary / decoy files and honey tokens.

Feature 02 — Decoy document factory:
Generates realistic, client-tailored bait on deploy.
"""

from __future__ import annotations

import os
import time
import threading
import logging
from pathlib import Path
from typing import Callable, List, Dict, Optional, Any

logger = logging.getLogger("mirage.canaries")


def _build_default_baits(org: str = "Company", sector: str = "general") -> List[Dict[str, str]]:
    """Produce client-aware decoy documents.

    org and sector are injected so the bait looks native to the target.
    """
    org = org or "Company"
    sector = (sector or "general").lower()

    # Sector flavour
    if sector in ("clinic", "medical", "healthcare", "health"):
        finance_name = "Patient_Billing_Summary_Q2.txt"
        finance_body = (
            f"CONFIDENTIAL — {org} Clinical Operations\n"
            f"Q2 Patient Billing Summary\n"
            f"Total billed: TT$ 1.85M\n"
            f"Outstanding AR: TT$ 312k\n"
            f"Primary insurer codes on file — internal use only\n"
            f"# Decoy canary — interaction triggers alert\n"
        )
        extra = {
            "name": "patient_records_index",
            "relpath": "records/patient_index_snippet.txt",
            "content": (
                f"{org} — Restricted Patient Index (sample)\n"
                f"Do not distribute. For authorized clinical staff only.\n"
                f"Last export: 2026-09-14\n"
                f"# DECOY FILE\n"
            ),
        }
    elif sector in ("retail", "pos", "shop", "store"):
        finance_name = "Supplier_Invoices_Pending.txt"
        finance_body = (
            f"{org} — Accounts Payable\n"
            f"Pending supplier invoices — do not share externally\n"
            f"PO-88421  TT$ 48,200  due 2026-10-15\n"
            f"PO-88455  TT$ 12,750  due 2026-10-22\n"
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
            f"Matter balances as of last reconciliation\n"
            f"Client funds held — internal only\n"
            f"# Decoy canary\n"
        )
        extra = {
            "name": "matter_index",
            "relpath": "matters/active_matters_index.txt",
            "content": (
                f"{org} Active Matters Index — Privileged\n"
                f"For authorized fee earners only.\n"
                f"# DECOY\n"
            ),
        }
    else:
        finance_name = "Q2_Board_Report.txt"
        finance_body = (
            f"CONFIDENTIAL — {org} Board Eyes Only\n"
            f"Q2 Revenue: TT$ 4.2M\n"
            f"Projected Q3: TT$ 5.1M\n"
            f"Bank Account ending 4821 — primary operating\n"
            f"# This is a decoy canary file\n"
        )
        extra = None

    baits = [
        {
            "name": "db_credentials",
            "relpath": "config/db_credentials.txt",
            "content": (
                f"# {org} — Production Database Credentials — CONFIDENTIAL\n"
                f"DB_HOST=10.0.0.15\n"
                f"DB_USER=admin\n"
                f"DB_PASS=Pr0d_S3cure_2026!\n"
                f"DB_NAME={org.lower().replace(' ', '_')}_erp\n"
                f"# Last rotated: 2026-08-12\n"
                f"# DECOY — any use or modification alerts\n"
            ),
        },
        {
            "name": "vpn_config",
            "relpath": "config/company-vpn.ovpn",
            "content": (
                f"# {org} corporate VPN profile\n"
                f"client\n"
                f"dev tun\n"
                f"proto udp\n"
                f"remote vpn.internal.{org.lower().replace(' ', '')}.tt 1194\n"
                f"auth-user-pass\n"
                f"# DECOY — do not use. Interaction triggers alert.\n"
            ),
        },
        {
            "name": "api_keys",
            "relpath": "secrets/api_keys.env",
            "content": (
                f"# {org} cloud & payment keys — CONFIDENTIAL\n"
                f"AWS_ACCESS_KEY_ID=AKIA_DECOY_EXAMPLE_KEY\n"
                f"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/DECOY/SECRET\n"
                f"STRIPE_SECRET_KEY=sk_live_decoy_do_not_use\n"
                f"# Honey token — any use will alert\n"
            ),
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
                f"admin:Tr1nTech_Admin_2026!\n"
                f"root:ChangeMeImmediately!\n"
                f"backup:B@ckup_S3cret\n"
                f"# Decoy credentials — use triggers alert\n"
            ),
        },
        {
            "name": "passwords_xlsx_note",
            "relpath": "admin/passwords_README.txt",
            "content": (
                f"{org} — Shared credential workbook location\n"
                f"See passwords.xlsx on the Finance share (network drive).\n"
                f"Last updated by IT — 2026-09-01\n"
                f"# Decoy pointer file\n"
            ),
        },
    ]

    if extra:
        baits.append(extra)

    return baits


class CanaryManager:
    def __init__(self, base_dir: str, on_alert: Optional[Callable] = None,
                 organization: str = "", sector: str = "general"):
        self.base_dir = Path(base_dir)
        self.on_alert = on_alert
        self.organization = organization or "Company"
        self.sector = sector or "general"
        self.canaries: List[Dict] = []
        self._watcher_thread = None
        self._running = False
        self._mtimes: Dict[str, float] = {}

    def generate_baits(self, org: str = None, sector: str = None) -> List[Dict[str, str]]:
        """Feature 02 entry point — produce tailored decoy definitions."""
        return _build_default_baits(
            org=org or self.organization,
            sector=sector or self.sector,
        )

    def deploy(self, canary_defs: List[Dict] = None):
        defs = canary_defs or self.generate_baits()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for c in defs:
            full = self.base_dir / c["relpath"]
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(c["content"], encoding="utf-8")
            try:
                os.chmod(full, 0o640)
            except OSError:
                pass
            self._mtimes[str(full)] = full.stat().st_mtime
            self.canaries.append({"name": c["name"], "path": str(full)})
            logger.info("Canary deployed: %s", full)
        self._start_watcher()

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
                            if self.on_alert:
                                self.on_alert(
                                    event_type="canary_deleted",
                                    source_ip="local",
                                    details={"canary": c["name"], "path": c["path"]},
                                )
                            continue
                        mtime = path.stat().st_mtime
                        if mtime != self._mtimes.get(str(path)):
                            self._mtimes[str(path)] = mtime
                            if self.on_alert:
                                self.on_alert(
                                    event_type="canary_modified",
                                    source_ip="local",
                                    details={"canary": c["name"], "path": c["path"]},
                                )
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
        self.canaries.clear()
        logger.info("Canary files removed")

    def status(self) -> List[Dict]:
        return [
            {"name": c["name"], "path": c["path"], "exists": Path(c["path"]).exists()}
            for c in self.canaries
        ]
