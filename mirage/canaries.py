"""Canary / decoy files and honey tokens — Stage 3 file watch + token lifecycle."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .beacons import generate_tokens, tokens_to_env_file
from .trails import build_trail_documents, save_trail_meta, load_trail_meta, resolve_hop
from .packs import pack_extra_docs
from .email_canary import generate_email_canaries, render_invoice_canary, render_html_canary
from .ad_decoy import render_accounts_file
from .doc_canary import generate_document_canaries
from .file_watch import FileAccessWatcher
from .tokens import register_token

logger = logging.getLogger("mirage.canaries")

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
                f"[default]\naws_access_key_id = AKIADECOY{slug.upper()[:8]}\n"
                f"aws_secret_access_key = wJalrXUtnFEMI/DECOY/honey/token/key\n"
                f"# DECOY FILE — Mirage canary\n"
            ),
        },
        {
            "name": "id_rsa_decoy",
            "relpath": "ssh/id_rsa_decoy",
            "content": FAKE_SSH_KEY,
        },
        {
            "name": "config_json_honey",
            "relpath": "config/config.json",
            "content": (
                "{\n"
                f'  "app": "{org} ERP",\n'
                f'  "db_password": "Pr0d_S3cure_2026!",\n'
                f'  "admin_url": "http://127.0.0.1:{http_port}/login",\n'
                '  "_comment": "DECOY — Mirage honey credentials"\n'
                "}\n"
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
    finance_name = "Q2_Board_Report.txt"
    finance_body = f"CONFIDENTIAL — {org} Board Eyes Only\n# Decoy canary\n"
    extra = None
    if sector in ("clinic", "medical", "healthcare", "health"):
        finance_name = "Patient_Billing_Summary_Q2.txt"
        finance_body = f"CONFIDENTIAL — {org} Clinical Operations\n# Decoy canary\n"
        extra = {"name": "patient_records_index", "relpath": "records/patient_index_snippet.txt", "content": f"{org} — Restricted Patient Index\n# DECOY FILE\n"}

    tokens = generate_tokens(org=org, count=2, beacon_base=beacon_base)
    secrets_content = tokens_to_env_file(tokens, org=org)
    email_cans = generate_email_canaries(org=org, beacon_base=beacon_base, count=1)
    doc_cans = generate_document_canaries(org=org, beacon_base=beacon_base or "http://127.0.0.1:8888")

    baits: List[Dict[str, Any]] = [
        {"name": "db_credentials", "relpath": "config/db_credentials.txt", "content": f"# {org} DB\nDB_PASS=Pr0d_S3cure_2026!\n# DECOY\n"},
        {"name": "api_keys_beacon", "relpath": "secrets/api_keys.env", "content": secrets_content, "beacon_token_ids": [t["id"] for t in tokens]},
        {"name": "financial_report", "relpath": f"finance/{finance_name}", "content": finance_body},
        {"name": "admin_password", "relpath": "admin/passwords.txt", "content": f"# {org}\nadmin:Tr1nTech_Admin_2026!\n"},
        {"name": "ad_decoy_accounts", "relpath": "admin/domain_accounts_export.txt", "content": render_accounts_file(org)},
        {"name": "email_invoice_canary", "relpath": "finance/INV-DECOY-8841.txt", "content": render_invoice_canary(org, email_cans), "beacon_token_ids": [c["id"] for c in email_cans]},
        {"name": "email_invoice_html", "relpath": "finance/INV-DECOY-8841.html", "content": render_html_canary(org, email_cans), "beacon_token_ids": [c["id"] for c in email_cans]},
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
            baits.append({"name": td["name"], "relpath": td["relpath"], "content": td["content"], "trail_node": td.get("trail_node")})
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
        self._watcher: Optional[FileAccessWatcher] = None
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
        paths: List[str] = []

        for c in defs:
            full = self.base_dir / c["relpath"]
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(c["content"], encoding="utf-8")
            try:
                os.chmod(full, 0o640)
            except OSError:
                pass
            entry = {"name": c["name"], "path": str(full)}
            if c.get("trail_node"):
                entry["trail_node"] = c["trail_node"]
            self.canaries.append(entry)
            paths.append(str(full))
            for tid in c.get("beacon_token_ids") or []:
                self.beacon_token_ids.append(tid)
                register_token(tid, token_type="beacon", path=str(full), label=c["name"])
            logger.info("Canary deployed: %s", full)

        self._watcher = FileAccessWatcher(paths, on_event=self._on_file_event, poll_interval=2.0)
        self._watcher.start()

    def _on_file_event(self, event_type: str = "", source_ip: str = "", details: dict = None):
        details = details or {}
        path = details.get("path") or ""
        name = next((c["name"] for c in self.canaries if c["path"] == path), Path(path).name)
        details["canary"] = name
        hop = resolve_hop(self._trail_meta or load_trail_meta(self.base_dir), path)
        if hop:
            details["trail"] = hop
            if event_type.startswith("canary_"):
                event_type = "trail_hop"
        if self.on_alert:
            self.on_alert(event_type=event_type, source_ip=source_ip or "local", details=details)

    def stop(self):
        if self._watcher:
            self._watcher.stop()

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
            {"name": c["name"], "path": c["path"], "exists": Path(c["path"]).exists(), "trail_node": c.get("trail_node")}
            for c in self.canaries
        ]
