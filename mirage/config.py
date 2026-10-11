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
    "ports": {
        "ssh": 2222,
        "http": 8080,
        "https": 8443,
        "mysql": 3307,
        "ftp": 2121,
        "rdp": 3389,
    },
    "ssh_jail_enabled": True,
    "ssh_jail_timeout": 300,
    "smb_enabled": True,
    "smb_port": 4450,
    "smb_shares": ["Finance", "HR", "Backups"],
    "beacon_enabled": True,
    "beacon_port": 8888,
    "beacon_base_url": "",
    # Feature 15 — cloud decoy bucket
    "cloud_decoy_enabled": True,
    "cloud_decoy_port": 9000,
    "guardrails_enabled": True,
    "rate_limit_per_source": 30,
    "rate_limit_window_sec": 60,
    "circuit_breaker_threshold": 500,
    "circuit_breaker_window_sec": 60,
    "cosmetics": {},
    "canary_base_dir": str(Path.home() / ".mirage" / "decoys"),
    "alert_cooldown_seconds": 300,
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
        return cfg
    return DEFAULT_CONFIG.copy()


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_data_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
