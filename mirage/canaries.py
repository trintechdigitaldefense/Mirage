"""Canary / decoy files and honey tokens."""

import os
import time
import threading
import logging
from pathlib import Path
from typing import Callable, List, Dict, Optional

logger = logging.getLogger("mirage.canaries")

DEFAULT_CANARIES = [
    {
        "name": "db_credentials",
        "relpath": "config/db_credentials.txt",
        "content": (
            "# Production Database Credentials — CONFIDENTIAL\n"
            "DB_HOST=10.0.0.15\n"
            "DB_USER=admin\n"
            "DB_PASS=Pr0d_S3cure_2026!\n"
            "DB_NAME=company_erp\n"
            "# Last rotated: 2026-08-12\n"
        ),
    },
    {
        "name": "vpn_config",
        "relpath": "config/company-vpn.ovpn",
        "content": (
            "client\n"
            "dev tun\n"
            "proto udp\n"
            "remote vpn.internal.company.tt 1194\n"
            "auth-user-pass\n"
            "# DECOY — do not use\n"
        ),
    },
    {
        "name": "api_keys",
        "relpath": "secrets/api_keys.env",
        "content": (
            "AWS_ACCESS_KEY_ID=AKIA_DECOY_EXAMPLE_KEY\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/DECOY/SECRET\n"
            "STRIPE_SECRET_KEY=sk_live_decoy_do_not_use\n"
            "# Honey token — any use will alert\n"
        ),
    },
    {
        "name": "financial_report",
        "relpath": "finance/Q2_Board_Report.txt",
        "content": (
            "CONFIDENTIAL — Board Eyes Only\n"
            "Q2 Revenue: TT$ 4.2M\n"
            "Projected Q3: TT$ 5.1M\n"
            "Bank Account ending 4821 — primary operating\n"
            "# This is a decoy canary file\n"
        ),
    },
    {
        "name": "admin_password",
        "relpath": "admin/passwords.txt",
        "content": (
            "admin:Tr1nTech_Admin_2026!\n"
            "root:ChangeMeImmediately!\n"
            "backup:B@ckup_S3cret\n"
            "# Decoy credentials — use triggers alert\n"
        ),
    },
]


class CanaryManager:
    def __init__(self, base_dir: str, on_alert: Optional[Callable] = None):
        self.base_dir = Path(base_dir)
        self.on_alert = on_alert
        self.canaries: List[Dict] = []
        self._watcher_thread = None
        self._running = False
        self._mtimes: Dict[str, float] = {}

    def deploy(self, canary_defs: List[Dict] = None):
        defs = canary_defs or DEFAULT_CANARIES
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for c in defs:
            full = self.base_dir / c["relpath"]
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(c["content"], encoding="utf-8")
            # Make slightly more realistic permissions
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
                            # Deleted — strong signal
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
        return [{"name": c["name"], "path": c["path"], "exists": Path(c["path"]).exists()} for c in self.canaries]
