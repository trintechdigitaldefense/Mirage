import json
import os
from pathlib import Path
from typing import Any, Dict

# Default data dir — overridable via MIRAGE_DATA_DIR or config
_DEFAULT_DATA = Path(os.environ.get("MIRAGE_DATA_DIR", str(Path.home() / ".mirage")))

DEFAULT_CONFIG: Dict[str, Any] = {
    "data_dir": str(_DEFAULT_DATA),
    "organization_name": "",
    "authorization_ref": "",
    "sector": "general",
    "site_id": "",
    "webhook_url": None,
    "enable_console_alerts": True,
    # v2.5: loopback by default — external bind requires allow_external_bind=true
    "listen_address": "127.0.0.1",
    "allow_external_bind": False,
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
    "https_enabled": False,  # disabled until real TLS implemented
    "ssh_jail_enabled": True,
    "ssh_jail_timeout": 300,
    "telnet_jail_enabled": True,
    "telnet_jail_port": 2323,
    "web_api_enabled": True,
    "dashboard_enabled": False,
    "dashboard_port": 8787,
    "web_api_port": 8081,
    "smb_enabled": True,
    "smb_port": 4450,
    "smb_shares": ["Finance", "HR", "Backups"],
    "beacon_enabled": True,
    "beacon_port": 8888,
    "beacon_base_url": "",
    "cloud_decoy_enabled": True,
    "cloud_decoy_port": 9000,
    "banner_per_connection": True,
    "tarpit_enabled": True,
    "tarpit_ports": [2223, 3391, 4451],
    "tarpit_drip_interval": 2.0,
    "tarpit_max_session_sec": 120.0,
    "sinkhole_enabled": True,
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
    "mitre_siem_stream": True,
    "sentinel_integration": True,
    "sentinel_firewall_drop": False,
    "guardrails_enabled": True,
    "rate_limit_per_source": 30,
    "rate_limit_window_sec": 60,
    "circuit_breaker_threshold": 500,
    "circuit_breaker_window_sec": 60,
    "max_concurrent_global": 200,
    "max_concurrent_per_service": 50,
    "max_per_source_sessions": 20,
    "event_retention_days": 90,
    "cosmetics": {},
    "canary_base_dir": str(_DEFAULT_DATA / "decoys"),
    "alert_cooldown_seconds": 300,
    "alert_recipients": "",
    "alert_channel": "console",
    "report_cadence": "weekly",
    "evidence_policy": "on_request",
}

CONFIG_PATH = Path(os.environ.get("MIRAGE_CONFIG", str(_DEFAULT_DATA / "config.json")))


def data_dir_path(cfg: Dict[str, Any] = None) -> Path:
    """Resolve the active data directory from config or default."""
    if cfg is None:
        # Avoid recursion: only use env/default when loading
        return Path(os.environ.get("MIRAGE_DATA_DIR", str(_DEFAULT_DATA)))
    return Path(cfg.get("data_dir") or _DEFAULT_DATA)


def ensure_data_dir(cfg: Dict[str, Any] = None) -> Path:
    path = data_dir_path(cfg)
    path.mkdir(parents=True, exist_ok=True)
    for sub in ("logs", "reports", "decoys", "evidence"):
        (path / sub).mkdir(exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def validate_listen_address(cfg: Dict[str, Any]) -> str:
    """Return safe bind address; refuse 0.0.0.0 unless allow_external_bind."""
    addr = (cfg.get("listen_address") or "127.0.0.1").strip()
    external = addr in ("0.0.0.0", "::", "*")
    if external and not cfg.get("allow_external_bind", False):
        return "127.0.0.1"
    return addr


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
        # Keep canary path under data_dir if not customised
        if not user.get("canary_base_dir"):
            cfg["canary_base_dir"] = str(data_dir_path(cfg) / "decoys")
        ensure_data_dir(cfg)
        return cfg
    return DEFAULT_CONFIG.copy()


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_data_dir(cfg)
    path = CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
