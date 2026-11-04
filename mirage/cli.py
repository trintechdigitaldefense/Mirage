#!/usr/bin/env python3
"""Mirage v2.4 — Active Deception Platform CLI"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .config import load_config, save_config, ensure_data_dir
from .db import init_db, log_auth, get_all_events
from .services import ServiceManager
from .canaries import CanaryManager
from .smb import SMBManager
from .beacons import BeaconListener
from .cloud_decoy import CloudDecoy
from .tarpit import TarpitManager
from .dns_canary import DNSCanary
from .telnet_jail import TelnetJail
from .web_api import WebAPIDecoy
from .alerts import emit
from .report import generate_report
from .intent import classify_event
from . import guardrails
from .coverage import render_coverage_text
from .evidence import export_evidence
from .mesh import register_site, render_mesh_text, group_report_text
from .rotation import rotate, render_rotation_status
from .health import health_report
from .packs import list_packs, pack_share_names

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("mirage")

_service_mgr = None
_canary_mgr = None
_smb_mgr = None
_beacon_listener = None
_cloud_decoy = None
_tarpit_mgr = None
_dns_canary = None
_telnet_jail = None
_web_api = None

CHECKLIST_TEXT = """
Mirage Client Deployment Checklist
==================================
[ ] 1. Signed ROE  [ ] 2. Port map  [ ] 3. init  [ ] 4. deploy+probe  [ ] 5. agree
""".strip()


def _on_event(event_type: str, source_ip: str = "", details: dict = None):
    emit(event_type, source_ip, details or {}, severity="high")


def cmd_init(args):
    ensure_data_dir()
    init_db()
    cfg = load_config()
    if args.org:
        cfg["organization_name"] = args.org
    if args.auth_ref:
        cfg["authorization_ref"] = args.auth_ref
    if getattr(args, "sector", None):
        cfg["sector"] = args.sector
        cfg["smb_shares"] = pack_share_names(args.sector)
    if getattr(args, "beacon_url", None):
        cfg["beacon_base_url"] = args.beacon_url
    save_config(cfg)
    log_auth("init", cfg.get("authorization_ref", ""), "Mirage initialized")
    print(f"[+] Mirage {__version__} initialized")
    print(f"    Organization : {cfg.get('organization_name') or '(not set)'}")
    print(f"    Sector/pack  : {cfg.get('sector') or 'general'}")
    print(f"    Auth ref     : {cfg.get('authorization_ref') or '(not set)'}")


def cmd_agree(args):
    cfg = load_config()
    if args.recipients:
        cfg["alert_recipients"] = args.recipients
    if args.channel:
        cfg["alert_channel"] = args.channel
    if args.cadence:
        cfg["report_cadence"] = args.cadence
    if args.evidence:
        cfg["evidence_policy"] = args.evidence
    if args.webhook:
        cfg["webhook_url"] = args.webhook
        if cfg.get("alert_channel") == "console":
            cfg["alert_channel"] = "both"
    save_config(cfg)
    print("[+] Alert & report agreement saved")


def cmd_checklist(_args):
    print(CHECKLIST_TEXT)
    cfg = load_config()
    print(f"  Org={cfg.get('organization_name')} ROE={cfg.get('authorization_ref')}")
    print(f"  Telnet={cfg.get('telnet_jail_enabled')} WebAPI={cfg.get('web_api_enabled')} SIEM={cfg.get('mitre_siem_stream')}")


def cmd_deploy(args):
    global _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy
    global _tarpit_mgr, _dns_canary, _telnet_jail, _web_api
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref", "")
    if not auth_ref and not args.force:
        print("[!] No authorization_ref set. Use: mirage init --auth-ref ROE-XXXX")
        return

    if cfg.get("guardrails_enabled", True):
        guardrails.configure(
            rate_limit=int(cfg.get("rate_limit_per_source", 30)),
            rate_window=int(cfg.get("rate_limit_window_sec", 60)),
            breaker_threshold=int(cfg.get("circuit_breaker_threshold", 500)),
            breaker_window=int(cfg.get("circuit_breaker_window_sec", 60)),
            enabled=True,
        )

    org = cfg.get("organization_name") or "Company"
    sector = cfg.get("sector") or "general"
    beacon_base = cfg.get("beacon_base_url") or ""
    if not beacon_base and cfg.get("beacon_enabled", True):
        beacon_base = f"http://127.0.0.1:{cfg.get('beacon_port', 8888)}"

    print(f"[*] Deploying Mirage {__version__}")
    print(f"    Org={org} sector={sector} ROE={auth_ref or 'NONE'}")
    print()

    print("[*] Fake services + SSH jail...")
    _service_mgr = ServiceManager(
        ports=cfg.get("ports", {}),
        listen_addr=cfg.get("listen_address", "0.0.0.0"),
        on_connect=_on_event,
        ssh_jail=cfg.get("ssh_jail_enabled", True),
        ssh_jail_timeout=int(cfg.get("ssh_jail_timeout", 300)),
    )
    _service_mgr.deploy()
    for s in _service_mgr.status():
        print(f"       {s.get('name', '?'):12} port {s.get('port')}")

    if cfg.get("telnet_jail_enabled", True):
        print("[*] Telnet command sandbox...")
        _telnet_jail = TelnetJail(
            port=int(cfg.get("telnet_jail_port", 2323)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            on_event=_on_event,
        )
        if _telnet_jail.start():
            print(f"       telnet_jail port {cfg.get('telnet_jail_port', 2323)}")

    if cfg.get("web_api_enabled", True):
        print("[*] Decoy web API endpoints...")
        _web_api = WebAPIDecoy(
            port=int(cfg.get("web_api_port", 8081)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            on_event=_on_event,
        )
        if _web_api.start():
            print(f"       web_api    port {cfg.get('web_api_port', 8081)} (/.env /wp-login /api/v1/auth)")

    if cfg.get("tarpit_enabled", True):
        print("[*] TCP tarpit / sinkhole...")
        _tarpit_mgr = TarpitManager(
            ports=list(cfg.get("tarpit_ports") or [2223, 3391, 4451]),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            drip_interval=float(cfg.get("tarpit_drip_interval", 2.0)),
            max_session_sec=float(cfg.get("tarpit_max_session_sec", 120.0)),
            on_event=_on_event,
        )
        _tarpit_mgr.deploy()
        for s in _tarpit_mgr.status():
            print(f"       tarpit      port {s['port']}")

    if cfg.get("dns_canary_enabled", True):
        print("[*] DNS canary...")
        _dns_canary = DNSCanary(
            port=int(cfg.get("dns_canary_port", 5353)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            canary_names=list(cfg.get("dns_canary_names") or []),
            on_event=_on_event,
        )
        if _dns_canary.start():
            print(f"       dns canary  port {cfg.get('dns_canary_port', 5353)}")

    print("[*] Canaries / credentials / doc web-bugs...")
    _canary_mgr = CanaryManager(
        base_dir=cfg.get("canary_base_dir"),
        on_alert=_on_event,
        organization=org,
        sector=sector,
        beacon_base=beacon_base,
    )
    _canary_mgr.deploy()
    print(f"       {len(_canary_mgr.status())} decoy files deployed")

    if cfg.get("smb_enabled", True):
        print("[*] Decoy SMB...")
        shares = cfg.get("smb_shares") or pack_share_names(sector)
        _smb_mgr = SMBManager(
            port=int(cfg.get("smb_port", 4450)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            share_names=shares,
            on_connect=_on_event,
        )
        _smb_mgr.deploy()

    if cfg.get("beacon_enabled", True):
        print("[*] Beacon listener...")
        known = set(_canary_mgr.beacon_token_ids) if _canary_mgr else set()
        _beacon_listener = BeaconListener(
            host=cfg.get("listen_address", "0.0.0.0"),
            port=int(cfg.get("beacon_port", 8888)),
            on_beacon=_on_event,
            known_ids=known,
        )
        _beacon_listener.start()
        print(f"       beacon port {cfg.get('beacon_port', 8888)}")

    if cfg.get("cloud_decoy_enabled", True):
        print("[*] Cloud decoy...")
        _cloud_decoy = CloudDecoy(
            org=org,
            port=int(cfg.get("cloud_decoy_port", 9000)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            on_event=_on_event,
        )
        if _cloud_decoy.start():
            print(f"       cloud port {cfg.get('cloud_decoy_port', 9000)}")

    try:
        site = register_site()
        print(f"[+] Mesh site {site.get('site_id')}")
    except Exception as e:
        logger.warning("Mesh register failed: %s", e)

    log_auth("deploy", auth_ref, f"v{__version__} deploy")
    print("\n[+] Mirage live.")
    print("    Probe: curl :8080 :8081/.env :9000 ; dig @127.0.0.1 -p 5353 backup-vault.local")
    print("    Ctrl+C to stop.\n")

    def _shutdown(sig, frame):
        print("\n[*] Stopping...")
        for mgr in (
            _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy,
            _tarpit_mgr, _dns_canary, _telnet_jail, _web_api,
        ):
            if mgr:
                try:
                    if hasattr(mgr, "stop_all"):
                        mgr.stop_all()
                    elif hasattr(mgr, "stop"):
                        mgr.stop()
                except Exception:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown(None, None)


def cmd_status(_args):
    cfg = load_config()
    print("Mirage Status")
    print("=" * 50)
    print(f"Version        : {__version__}")
    print(f"Organization   : {cfg.get('organization_name') or '(not set)'}")
    print(f"ROE            : {cfg.get('authorization_ref') or '(not set)'}")
    print(f"SSH / Telnet   : {cfg.get('ssh_jail_enabled', True)} / {cfg.get('telnet_jail_enabled', True)}")
    print(f"Web API        : {cfg.get('web_api_enabled', True)} port {cfg.get('web_api_port', 8081)}")
    print(f"Tarpit / DNS   : {cfg.get('tarpit_enabled', True)} / {cfg.get('dns_canary_enabled', True)}")
    print(f"MITRE SIEM     : {cfg.get('mitre_siem_stream', True)} → ~/.mirage/siem_events.jsonl")
    print(f"Sentinel fw    : {cfg.get('sentinel_firewall_drop', False)} (default OFF)")


def cmd_alerts(args):
    events = get_all_events(limit=args.recent or 20)
    if not events:
        print("No deception events recorded yet.")
        return
    for e in events:
        cls = classify_event(e)
        print(f"  [{e['timestamp']}] {e['event_type']:25} src={e.get('source_ip') or 'n/a':15} intent={cls.get('intent', '?')}")


def cmd_report(args):
    hours = 24 if args.daily else (args.hours or 24)
    story = getattr(args, "story", False) or args.client
    print(generate_report(hours=hours, client_mode=args.client, story=story))


def cmd_bait(args):
    cfg = load_config()
    org = args.org or cfg.get("organization_name") or "Company"
    sector = args.sector or cfg.get("sector") or "general"
    beacon_base = cfg.get("beacon_base_url") or f"http://127.0.0.1:{cfg.get('beacon_port', 8888)}"
    mgr = CanaryManager(base_dir=cfg.get("canary_base_dir"), organization=org, sector=sector, beacon_base=beacon_base)
    baits = mgr.generate_baits(org=org, sector=sector)
    for b in baits:
        print(f"  {b['name']:24} → {b['relpath']}")
    if args.write:
        mgr.deploy(baits)
        print("[+] Written")


def cmd_coverage(_args):
    print(render_coverage_text())


def cmd_evidence(args):
    print(f"[+] {export_evidence(hours=args.hours or 24, engagement_id=args.engagement or '')}")


def cmd_mesh(args):
    if args.action == "register":
        print(register_site())
    elif args.action == "group":
        print(group_report_text())
    else:
        print(render_mesh_text())


def cmd_rotate(args):
    if args.status:
        print(render_rotation_status())
        return
    entry = rotate(force=True)
    print(f"[+] Rotated → {entry.get('http_server')}")


def cmd_health(_args):
    print(health_report())


def cmd_packs(_args):
    for p in list_packs():
        print(f"  {p['id']:<14} {p['label']}")


def cmd_killswitch(args):
    if args.reset:
        guardrails.reset_breaker()
        print("[+] reset")
        return
    for _ in range(guardrails.CIRCUIT_BREAKER_THRESHOLD + 5):
        guardrails.check_source("killswitch")
    print("[!] breaker tripped")


def cmd_stop(_args):
    print("[*] Ctrl+C on deploy process")


def cmd_clean(args):
    cfg = load_config()
    base = Path(cfg.get("canary_base_dir", ""))
    if base.exists():
        import shutil
        shutil.rmtree(base, ignore_errors=True)
        print("[+] cleaned")


def main():
    parser = argparse.ArgumentParser(description=f"Mirage {__version__}")
    parser.add_argument("--version", action="version", version=f"Mirage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init"); p.add_argument("--org"); p.add_argument("--auth-ref"); p.add_argument("--sector"); p.add_argument("--beacon-url"); p.set_defaults(func=cmd_init)
    p = sub.add_parser("agree"); p.add_argument("--recipients"); p.add_argument("--channel", choices=["console", "webhook", "both"]); p.add_argument("--cadence", choices=["weekly", "monthly", "per_critical_event"]); p.add_argument("--evidence", choices=["on_request", "per_critical", "monthly"]); p.add_argument("--webhook"); p.set_defaults(func=cmd_agree)
    p = sub.add_parser("checklist"); p.set_defaults(func=cmd_checklist)
    p = sub.add_parser("deploy"); p.add_argument("--force", action="store_true"); p.set_defaults(func=cmd_deploy)
    p = sub.add_parser("status"); p.set_defaults(func=cmd_status)
    p = sub.add_parser("alerts"); p.add_argument("--recent", "-r", type=int, default=20); p.set_defaults(func=cmd_alerts)
    p = sub.add_parser("report"); p.add_argument("--daily", action="store_true"); p.add_argument("--hours", type=int); p.add_argument("--client", action="store_true"); p.add_argument("--story", action="store_true"); p.set_defaults(func=cmd_report)
    p = sub.add_parser("bait"); p.add_argument("--org"); p.add_argument("--sector"); p.add_argument("--write", action="store_true"); p.set_defaults(func=cmd_bait)
    p = sub.add_parser("coverage"); p.set_defaults(func=cmd_coverage)
    p = sub.add_parser("evidence"); p.add_argument("--hours", type=int, default=24); p.add_argument("--engagement"); p.set_defaults(func=cmd_evidence)
    p = sub.add_parser("mesh"); p.add_argument("action", nargs="?", default="status", choices=["status", "register", "group"]); p.set_defaults(func=cmd_mesh)
    p = sub.add_parser("rotate"); p.add_argument("--status", action="store_true"); p.set_defaults(func=cmd_rotate)
    p = sub.add_parser("health"); p.set_defaults(func=cmd_health)
    p = sub.add_parser("packs"); p.set_defaults(func=cmd_packs)
    p = sub.add_parser("killswitch"); p.add_argument("--reset", action="store_true"); p.set_defaults(func=cmd_killswitch)
    p = sub.add_parser("stop"); p.set_defaults(func=cmd_stop)
    p = sub.add_parser("clean"); p.set_defaults(func=cmd_clean)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
