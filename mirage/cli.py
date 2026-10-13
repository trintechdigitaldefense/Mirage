#!/usr/bin/env python3
"""Mirage v2.2 — Active Deception Platform CLI"""

from __future__ import annotations

import argparse
import signal
import sys
import time
import logging
from pathlib import Path

from . import __version__
from .config import load_config, save_config, ensure_data_dir
from .db import init_db, log_auth, get_all_events
from .services import ServiceManager
from .canaries import CanaryManager
from .smb import SMBManager
from .beacons import BeaconListener
from .cloud_decoy import CloudDecoy
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

CHECKLIST_TEXT = """
Mirage Client Deployment Checklist
==================================
See full templates in the repo: docs/ROE_TEMPLATE.md, docs/PORT_MAP_TEMPLATE.md,
docs/DEPLOYMENT_CHECKLIST.md

[ ] 1. Signed ROE (scope + ports + no-attack-back)
[ ] 2. Written port map (avoid real SSH 22 / RDP 3389 / SMB 445)
[ ] 3. mirage init --org ... --auth-ref ROE-... --sector ...
[ ] 4. mirage deploy → health + coverage + live probe (curl/ssh)
[ ] 5. mirage agree — who gets alerts & report cadence

Quick path:
  mirage init --org "Client" --auth-ref ROE-2026-001 --sector clinic
  mirage agree --recipients "ops@client.tt" --channel webhook --cadence weekly
  mirage deploy
  mirage health && mirage coverage
  curl -s http://127.0.0.1:8080/ >/dev/null
  curl -s http://127.0.0.1:9000/ >/dev/null
  mirage alerts
  mirage report --story
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
    print(f"    SMB shares   : {', '.join(cfg.get('smb_shares') or [])}")
    print(f"    RDP decoy    : port {cfg.get('ports', {}).get('rdp', 33890)} (non-standard by default)")
    if not cfg.get("authorization_ref"):
        print("    [!] Set --auth-ref to the signed ROE reference before deploy.")
    print("    Next: mirage agree ...  then  mirage deploy")
    print("    Checklist: mirage checklist")


def cmd_agree(args):
    """Record who gets alerts and how often story reports are delivered."""
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
    log_auth("agree", cfg.get("authorization_ref", ""), "alert/report agreement set")
    print("[+] Alert & report agreement saved")
    print(f"    Recipients   : {cfg.get('alert_recipients') or '(not set)'}")
    print(f"    Channel      : {cfg.get('alert_channel') or 'console'}")
    print(f"    Report cadence: {cfg.get('report_cadence') or 'weekly'}")
    print(f"    Evidence     : {cfg.get('evidence_policy') or 'on_request'}")
    print(f"    Webhook      : {cfg.get('webhook_url') or 'none'}")


def cmd_checklist(_args):
    print(CHECKLIST_TEXT)
    cfg = load_config()
    print("\nCurrent config snapshot")
    print("-" * 40)
    print(f"  Org        : {cfg.get('organization_name') or '(not set)'}")
    print(f"  ROE ref    : {cfg.get('authorization_ref') or '(not set)'}")
    print(f"  Sector     : {cfg.get('sector') or 'general'}")
    print(f"  Recipients : {cfg.get('alert_recipients') or '(not set)'}")
    print(f"  Cadence    : {cfg.get('report_cadence') or 'weekly'}")
    print(f"  Docs       : docs/ROE_TEMPLATE.md | PORT_MAP_TEMPLATE.md | DEPLOYMENT_CHECKLIST.md")


def cmd_deploy(args):
    global _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref", "")
    if not auth_ref and not args.force:
        print("[!] No authorization_ref set. Use: mirage init --auth-ref ROE-XXXX")
        print("    Complete docs/ROE_TEMPLATE.md and pass the ROE reference.")
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

    jail_on = cfg.get("ssh_jail_enabled", True)
    jail_timeout = int(cfg.get("ssh_jail_timeout", 300))

    print(f"[*] Deploying Mirage {__version__}")
    print(f"    Org={org} sector={sector} ROE={auth_ref or 'NONE'} jail={'ON' if jail_on else 'OFF'}")
    if cfg.get("alert_recipients"):
        print(f"    Alerts → {cfg.get('alert_recipients')} ({cfg.get('alert_channel')}) cadence={cfg.get('report_cadence')}")
    print()

    print("[*] Fake services + SSH jail...")
    _service_mgr = ServiceManager(
        ports=cfg.get("ports", {}),
        listen_addr=cfg.get("listen_address", "0.0.0.0"),
        on_connect=_on_event,
        ssh_jail=jail_on,
        ssh_jail_timeout=jail_timeout,
    )
    _service_mgr.deploy()
    for s in _service_mgr.status():
        print(f"       {s.get('name', '?'):12} port {s.get('port')}")

    print("[*] Canaries / trails / tokens / email canaries / AD decoys...")
    _canary_mgr = CanaryManager(
        base_dir=cfg.get("canary_base_dir"),
        on_alert=_on_event,
        organization=org,
        sector=sector,
        beacon_base=beacon_base,
    )
    _canary_mgr.deploy()
    print(f"       {len(_canary_mgr.status())} decoy files deployed")

    shares = cfg.get("smb_shares") or pack_share_names(sector)
    if cfg.get("smb_enabled", True):
        print("[*] Decoy SMB shares...")
        _smb_mgr = SMBManager(
            port=int(cfg.get("smb_port", 4450)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            share_names=shares,
            on_connect=_on_event,
        )
        _smb_mgr.deploy()
        for s in _smb_mgr.status():
            print(f"       smb port {s['port']} shares={s['shares']}")

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
        print(f"       beacon port {cfg.get('beacon_port', 8888)} tokens={len(known)}")

    if cfg.get("cloud_decoy_enabled", True):
        print("[*] Cloud decoy bucket...")
        _cloud_decoy = CloudDecoy(
            org=org,
            port=int(cfg.get("cloud_decoy_port", 9000)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            on_event=_on_event,
        )
        if _cloud_decoy.start():
            print(f"       cloud decoy port {cfg.get('cloud_decoy_port', 9000)}")

    try:
        site = register_site()
        print(f"[+] Mesh site {site.get('site_id')} coverage={site.get('coverage_score')}%")
    except Exception as e:
        logger.warning("Mesh register failed: %s", e)

    log_auth("deploy", auth_ref, f"v2.2 deploy sector={sector}")
    print("\n[+] Mirage live. Confirm with: mirage health")
    print("    Live probe: curl :8080 and :9000, then ssh -p 2222 ubuntu@host")
    print("    Ctrl+C to stop.\n")

    def _shutdown(sig, frame):
        print("\n[*] Stopping...")
        for mgr in (_service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy):
            if mgr:
                try:
                    if hasattr(mgr, "stop_all"):
                        mgr.stop_all()
                    elif hasattr(mgr, "stop"):
                        mgr.stop()
                except Exception:
                    pass
        log_auth("stop", auth_ref, "manual stop")
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
    print(f"Sector         : {cfg.get('sector') or 'general'}")
    print(f"Site ID        : {cfg.get('site_id') or '(not registered)'}")
    print(f"ROE / auth ref : {cfg.get('authorization_ref') or '(not set)'}")
    print(f"SSH jail       : {'ON' if cfg.get('ssh_jail_enabled', True) else 'OFF'}")
    print(f"SMB / Beacon / Cloud : "
          f"{cfg.get('smb_enabled', True)} / {cfg.get('beacon_enabled', True)} / {cfg.get('cloud_decoy_enabled', True)}")
    print(f"Guardrails     : {'ON' if cfg.get('guardrails_enabled', True) else 'OFF'}")
    print(f"Alert to       : {cfg.get('alert_recipients') or '(not set)'} via {cfg.get('alert_channel') or 'console'}")
    print(f"Report cadence : {cfg.get('report_cadence') or 'weekly'}")
    print(f"Evidence policy: {cfg.get('evidence_policy') or 'on_request'}")
    ports = cfg.get("ports") or {}
    print(f"Key ports      : ssh={ports.get('ssh')} http={ports.get('http')} rdp={ports.get('rdp')} smb={cfg.get('smb_port')}")
    gb = guardrails.status()
    if gb.get("circuit_breaker", {}).get("tripped"):
        print(f"Circuit breaker: TRIPPED — {gb['circuit_breaker'].get('reason')}")


def cmd_alerts(args):
    events = get_all_events(limit=args.recent or 20)
    if not events:
        print("No deception events recorded yet.")
        return
    print(f"=== Recent Mirage Events (last {len(events)}) ===")
    for e in events:
        cls = classify_event(e)
        print(
            f"  [{e['timestamp']}] {e['event_type']:25} "
            f"src={e.get('source_ip') or 'n/a':15} intent={cls.get('intent', '?')}"
        )


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
    print(f"=== Decoy Factory — {org} ({sector}) ===\n")
    for b in baits:
        print(f"  {b['name']:24} → {b['relpath']}")
    if args.write:
        mgr.deploy(baits)
        print("[+] Written to disk")
    else:
        print("\nPass --write to create files.")


def cmd_coverage(_args):
    print(render_coverage_text())


def cmd_evidence(args):
    path = export_evidence(hours=args.hours or 24, engagement_id=args.engagement or "")
    print(f"[+] Evidence bundle: {path}")


def cmd_mesh(args):
    if args.action == "register":
        site = register_site()
        print(f"[+] Registered {site['site_id']} events_24h={site.get('events_24h')}")
    elif args.action == "group":
        print(group_report_text())
    else:
        print(render_mesh_text())


def cmd_rotate(args):
    if args.status:
        print(render_rotation_status())
        return
    entry = rotate(force=True)
    print(f"[+] Rotated SSH={entry['ssh_banner'][:40]}... HTTP={entry['http_server']}")
    print("    Redeploy to apply banners to live listeners.")


def cmd_health(_args):
    print(health_report())


def cmd_packs(_args):
    print("Industry decoy packs:\n")
    for p in list_packs():
        print(f"  {p['id']:<14} {p['label']}")
    print("\nUse: mirage init --sector <id>")


def cmd_killswitch(args):
    if args.reset:
        guardrails.reset_breaker()
        print("[+] Circuit breaker reset")
        return
    for _ in range(guardrails.CIRCUIT_BREAKER_THRESHOLD + 5):
        guardrails.check_source("killswitch")
    st = guardrails.status()
    print("[!] Circuit breaker TRIPPED" if st["circuit_breaker"]["tripped"] else "[?] Trip may have failed")
    print(f"    {st['circuit_breaker'].get('reason')}")
    print("    Alerts are suppressed until: mirage killswitch --reset")


def cmd_stop(_args):
    print("[*] Stop with Ctrl+C on the deploy process (or systemctl stop mirage)")


def cmd_clean(args):
    cfg = load_config()
    base = Path(cfg.get("canary_base_dir", ""))
    if base.exists():
        import shutil
        shutil.rmtree(base, ignore_errors=True)
        print("[+] Canaries removed")
    else:
        print("[*] Nothing to clean")
    log_auth("clean", cfg.get("authorization_ref", ""), "canaries cleaned")


def main():
    parser = argparse.ArgumentParser(
        description=f"Mirage {__version__} — TrinTech Digital Defense",
        epilog="Authorized defensive use only. Complete ROE before client deploy.",
    )
    parser.add_argument("--version", action="version", version=f"Mirage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Initialize with org, ROE ref, sector")
    p.add_argument("--org")
    p.add_argument("--auth-ref", help="Signed ROE reference")
    p.add_argument("--sector", help="general|clinic|retail|legal|finance|hospitality")
    p.add_argument("--beacon-url")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("agree", help="Who gets alerts + report cadence")
    p.add_argument("--recipients", help="Names or emails for alerts")
    p.add_argument("--channel", choices=["console", "webhook", "both"])
    p.add_argument("--cadence", choices=["weekly", "monthly", "per_critical_event"])
    p.add_argument("--evidence", choices=["on_request", "per_critical", "monthly"])
    p.add_argument("--webhook", help="Webhook URL for alerts")
    p.set_defaults(func=cmd_agree)

    p = sub.add_parser("checklist", help="Pilot deployment checklist")
    p.set_defaults(func=cmd_checklist)

    p = sub.add_parser("deploy", help="Deploy full stack")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("status"); p.set_defaults(func=cmd_status)
    p = sub.add_parser("alerts"); p.add_argument("--recent", "-r", type=int, default=20); p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("report")
    p.add_argument("--daily", action="store_true")
    p.add_argument("--hours", type=int)
    p.add_argument("--client", action="store_true")
    p.add_argument("--story", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("bait")
    p.add_argument("--org"); p.add_argument("--sector"); p.add_argument("--write", action="store_true")
    p.set_defaults(func=cmd_bait)

    p = sub.add_parser("coverage"); p.set_defaults(func=cmd_coverage)
    p = sub.add_parser("evidence")
    p.add_argument("--hours", type=int, default=24); p.add_argument("--engagement")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("mesh")
    p.add_argument("action", nargs="?", default="status", choices=["status", "register", "group"])
    p.set_defaults(func=cmd_mesh)

    p = sub.add_parser("rotate"); p.add_argument("--status", action="store_true"); p.set_defaults(func=cmd_rotate)
    p = sub.add_parser("health"); p.set_defaults(func=cmd_health)
    p = sub.add_parser("packs"); p.set_defaults(func=cmd_packs)

    p = sub.add_parser("killswitch", help="Trip or reset circuit breaker")
    p.add_argument("--reset", action="store_true")
    p.set_defaults(func=cmd_killswitch)

    p = sub.add_parser("stop"); p.set_defaults(func=cmd_stop)
    p = sub.add_parser("clean"); p.set_defaults(func=cmd_clean)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
