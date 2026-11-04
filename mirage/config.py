import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "data_dir": str(Path.home() / ".mirage"),
    "organization_name": "",
    "authorization_ref": "",
    "sector": "general",
    "site_id": "",
    "webhook_url": None,
    "enable_console_alerts": True,
    "listen_address": "0.0.0.0",
    # Decoy ports — avoid real SSH 22, RDP 3389, SMB 445, MySQL 3306
    "ports": {
        "ssh": 2222,
        "http": 8080,
        "https": 8443,
        "mysql": 3307,
        "ftp": 2121,
        "rdp": 33890,
        "redis": 63790,
        "postgres": 54320,
        "elastic": 9200,
    },
    "ssh_jail_enabled": True,
    "ssh_jail_timeout": 300,
    "smb_enabled": True,
    "smb_port": 4450,
    "smb_shares": ["Finance", "HR", "Backups"],
    "beacon_enabled": True,
    "beacon_port": 8888,
    "beacon_base_url": "",
    "cloud_decoy_enabled": True,
    "cloud_decoy_port": 9000,
    # v2.3 — recon interruption
    "banner_per_connection": True,
    "tarpit_enabled": True,
    "tarpit_ports": [2223, 3391, 4451],
    "tarpit_drip_interval": 2.0,
    "tarpit_max_session_sec": 120.0,
    "dns_canary_enabled": True,
    "dns_canary_port": 5353,
    "dns_canary_names": [
        "dev-db-admin.internal.local",
        "backup-vault.local",
        "payroll-sql.internal.local",
        "vpn-gateway-mgmt.local",
        "ad-backup.corp.local",
    ],
    "profiler_enabled": True,
    "sentinel_integration": True,
    "sentinel_firewall_drop": False,  # OFF unless ROE allows active response
    "guardrails_enabled": True,
    "rate_limit_per_source": 30,
    "rate_limit_window_sec": 60,
    "circuit_breaker_threshold": 500,
    "circuit_breaker_window_sec": 60,
    "cosmetics": {},
    "canary_base_dir": str(Path.home() / ".mirage" / "decoys"),
    "alert_cooldown_seconds": 300,
    "alert_recipients": "",
    "alert_channel": "console",
    "report_cadence": "weekly",
    "evidence_policy": "on_request",
}

CONFIG_PATH = Path.home() / ".mirage" / "config.json"


def ensure_data_dir() -> Path:
    data_dir = Path(DEFAULT_CONFIG["data_dir"])
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(exist_ok=True)
    (data_dir / "reports").mkdir(exist_ok=True)
    (data_dir / "decoys").mkdir(exist_ok=True)
    (data_dir / "evidence").mkdir(exist_ok=True)
    return data_dir


def load_config() -> Dict[str, Any]:
    ensure_data_dir()
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user = json.load(f)
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(user)
        if isinstance(user.get("ports"), dict):
            ports = dict(DEFAULT_CONFIG["ports"])
            ports.update(user["ports"])
            cfg["ports"] = ports
        return cfg
    return DEFAULT_CONFIG.copy()


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_data_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
