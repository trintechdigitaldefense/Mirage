"""Canary / decoy files and honey tokens (v2.4)."""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .beacons import generate_tokens, tokens_to_env_file
from .trails import build_trail_documents, save_trail_meta, load_trail_meta, resolve_hop
from .packs import pack_extra_docs
from .email_canary import generate_email_canaries, render_invoice_canary, render_html_canary
from .ad_decoy import render_accounts_file
from .doc_canary import generate_document_canaries

logger = logging.getLogger("mirage.canaries")

# Fake OpenSSH private key header only — not a valid key, traps tools that grep for PEM
FAKE_SSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
DECOY_KEY_NOT_VALID_b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDECOY/mirage/honey/token/placeholder/onlyAAAAEAAAAAtzc2gtZW
QyNTUxOQAAACDECOY/mirage/honey/token/placeholder/onlyAAAAEH1kZWNveQECAwQF
-----END OPENSSH PRIVATE KEY-----
# Host: decoy-bastion.internal  Port: 2222
# DECOY — use triggers Mirage SSH jail
"""


def _honey_credential_baits(org: str, http_port: int = 8080, mysql_port: int = 3307) -> List[Dict[str, Any]]:
    slug = org.lower().replace(" ", "-").replace("_", "-")[:24] or "company"
    return [
        {
            "name": "dotenv_honey",
            "relpath": "config/.env",
            "content": (
                f"# {org} application secrets — DO NOT COMMIT\n"
                f"DATABASE_URL=mysql://app_user:S3cretPass@{slug}-db.internal:{mysql_port}/{slug}_prod\n"
                f"REDIS_URL=redis://cache.internal:63790/0\n"
                f"API_BASE=http://admin-portal.internal:{http_port}\n"
                f"AWS_ACCESS_KEY_ID=AKIADECOY{slug.upper()[:8]}\n"
                f"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/DECOY/honey/token/key\n"
                f"# DECOY — any use triggers Mirage\n"
            ),
        },
        {
            "name": "aws_credentials_honey",
            "relpath": "config/aws_credentials",
            "content": (
                f"[default]\n"
                f"aws_access_key_id = AKIADECOY{slug.upper()[:8]}\n"
                f"aws_secret_access_key = wJalrXUtnFEMI/DECOY/honey/token/key\n"
                f"region = us-east-1\n"
                f"# endpoint override (decoy): http://127.0.0.1:9000\n"
                f"# DECOY FILE — Mirage canary\n"
            ),
        },
        {
            "name": "aws_dotdir_credentials",
            "relpath": "dot_aws/credentials",
            "content": (
                f"[default]\naws_access_key_id = AKIADECOY{slug.upper()[:8]}\n"
                f"aws_secret_access_key = wJalrXUtnFEMI/DECOY/honey/token/key\n"
                f"# Place as ~/.aws/credentials on bait hosts — DECOY\n"
            ),
        },
        {
            "name": "id_rsa_decoy",
            "relpath": "ssh/id_rsa_decoy",
            "content": FAKE_SSH_KEY,
        },
        {
            "name": "id_rsa_decoy_pub",
            "relpath": "ssh/id_rsa_decoy.pub",
            "content": (
                f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5DECOYmiragehoney {org.lower().replace(' ', '')}@decoy-bastion\n"
            ),
        },
        {
            "name": "config_json_honey",
            "relpath": "config/config.json",
            "content": (
                "{\n"
                f'  "app": "{org} ERP",\n'
                f'  "db_host": "{slug}-db.internal",\n'
                f'  "db_port": {mysql_port},\n'
                f'  "db_user": "admin",\n'
                f'  "db_password": "Pr0d_S3cure_2026!",\n'
                f'  "admin_url": "http://127.0.0.1:{http_port}/login",\n'
                f'  "ssh_bastion": "decoy-bastion.internal:2222",\n'
                '  "_comment": "DECOY — Mirage honey credentials"\n'
                "}\n"
            ),
        },
        {
            "name": "browser_cookies_note",
            "relpath": "browser/session_cookies_export.txt",
            "content": (
                f"# {org} browser session export (decoy)\n"
                f"session_id=DECOY_SESSION_TOKEN_DO_NOT_USE\n"
                f"admin_panel=http://127.0.0.1:{http_port}/admin/\n"
                f"# If dumped by credential tools, callbacks hit Mirage\n"
            ),
        },
    ]


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
        finance_body = f"CONFIDENTIAL — {org} Clinical Operations\n# Decoy canary\n"
        extra = {
            "name": "patient_records_index",
            "relpath": "records/patient_index_snippet.txt",
            "content": f"{org} — Restricted Patient Index\n# DECOY FILE\n",
        }
    elif sector in ("retail", "pos", "shop", "store"):
        finance_name = "Supplier_Invoices_Pending.txt"
        finance_body = f"{org} — Accounts Payable\n# Decoy canary\n"
        extra = {
            "name": "pos_config",
            "relpath": "pos/terminal_config.bak",
            "content": f"# {org} POS\nMERCHANT_ID=DECOY8821\n",
        }
    elif sector in ("legal", "law", "firm"):
        finance_name = "Matter_Trust_Summary.txt"
        finance_body = f"{org} — Trust Account Summary\n# Decoy canary\n"
        extra = {
            "name": "matter_index",
            "relpath": "matters/active_matters_index.txt",
            "content": f"{org} Active Matters Index\n# DECOY\n",
        }
    else:
        finance_name = "Q2_Board_Report.txt"
        finance_body = f"CONFIDENTIAL — {org} Board Eyes Only\n# Decoy canary\n"
        extra = None

    tokens = generate_tokens(org=org, count=2, beacon_base=beacon_base)
    secrets_content = tokens_to_env_file(tokens, org=org)
    email_cans = generate_email_canaries(org=org, beacon_base=beacon_base, count=1)
    doc_cans = generate_document_canaries(org=org, beacon_base=beacon_base or "http://127.0.0.1:8888")

    baits: List[Dict[str, Any]] = [
        {
            "name": "db_credentials",
            "relpath": "config/db_credentials.txt",
            "content": (
                f"# {org} — Production Database Credentials\n"
                f"DB_HOST=10.0.0.15\nDB_USER=admin\nDB_PASS=Pr0d_S3cure_2026!\n"
                f"# DECOY\n"
            ),
        },
        {
            "name": "vpn_config",
            "relpath": "config/company-vpn.ovpn",
            "content": (
                f"# {org} corporate VPN\nclient\ndev tun\n"
                f"remote vpn.internal.{org.lower().replace(' ', '')}.tt 1194\n# DECOY\n"
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
                f"# {org} privileged accounts\n"
                f"admin:Tr1nTech_Admin_2026!\nroot:ChangeMeImmediately!\n"
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

    baits.extend(_honey_credential_baits(org))
    baits.extend(doc_cans)

    if extra:
        baits.append(extra)

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
        details: Dict[str, Any] = {"canary": canary["name"], "path": canary["path"]}
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
        self.canaries.clear()

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
