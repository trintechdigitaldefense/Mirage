#!/usr/bin/env python3
"""Mirage v2.1 — Active Deception Platform CLI

The Trap That Talks.
"""

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
from .alerts import emit
from .report import generate_report
from .intent import classify_event

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("mirage")

_service_mgr = None
_canary_mgr = None
_smb_mgr = None
_beacon_listener = None


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
    if getattr(args, "beacon_url", None):
        cfg["beacon_base_url"] = args.beacon_url
    save_config(cfg)
    log_auth("init", cfg.get("authorization_ref", ""), "Mirage initialized")
    print(f"[+] Mirage {__version__} initialized")
    print(f"    Data dir     : {cfg['data_dir']}")
    print(f"    Organization : {cfg.get('organization_name') or '(not set)'}")
    print(f"    Sector       : {cfg.get('sector') or 'general'}")
    print(f"    Auth ref     : {cfg.get('authorization_ref') or '(not set)'}")
    print(f"    Beacon URL   : {cfg.get('beacon_base_url') or '(local listener)'}")
    print(f"    SSH jail     : {'ON' if cfg.get('ssh_jail_enabled', True) else 'OFF'} "
          f"(timeout {cfg.get('ssh_jail_timeout', 300)}s)")
    print("    Next: mirage deploy")


def cmd_deploy(args):
    global _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener
    cfg = load_config()
    auth_ref = cfg.get("authorization_ref", "")
    if not auth_ref and not args.force:
        print("[!] No authorization_ref set. Use: mirage init --auth-ref ROE-XXXX")
        print("    Or pass --force to override (not recommended for client work).")
        return

    org = cfg.get("organization_name") or "Company"
    sector = cfg.get("sector") or "general"
    beacon_base = cfg.get("beacon_base_url") or ""
    if not beacon_base and cfg.get("beacon_enabled", True):
        beacon_base = f"http://127.0.0.1:{cfg.get('beacon_port', 8888)}"

    jail_on = cfg.get("ssh_jail_enabled", True)
    jail_timeout = int(cfg.get("ssh_jail_timeout", 300))

    print(f"[*] Deploying Mirage {__version__} — The Trap That Talks")
    print(f"    Organization : {org}")
    print(f"    Sector       : {sector}")
    print(f"    Auth ref     : {auth_ref or 'NONE (forced)'}")
    print(f"    SSH jail     : {'ON' if jail_on else 'OFF'} (cap {jail_timeout}s)")
    print()

    step = 1
    total = 2 + (1 if cfg.get("smb_enabled", True) else 0) + (1 if cfg.get("beacon_enabled", True) else 0)

    # 1. Fake services (+ SSH jail replaces banner SSH when enabled)
    print(f"[{step}/{total}] Starting fake services" + (" + SSH jail..." if jail_on else "..."))
    step += 1
    _service_mgr = ServiceManager(
        ports=cfg.get("ports", {}),
        listen_addr=cfg.get("listen_address", "0.0.0.0"),
        on_connect=_on_event,
        ssh_jail=jail_on,
        ssh_jail_timeout=jail_timeout,
    )
    _service_mgr.deploy()
    for s in _service_mgr.status():
        label = s.get("name", "?")
        extra = ""
        if label == "ssh_jail":
            extra = f"  [JAIL timeout={s.get('session_timeout', jail_timeout)}s]"
        print(f"       {label:10} on port {s.get('port')}{extra}")

    # 2. Canaries + trails + beacon tokens
    print(f"[{step}/{total}] Deploying canaries, breadcrumb trails & honey tokens...")
    step += 1
    _canary_mgr = CanaryManager(
        base_dir=cfg.get("canary_base_dir"),
        on_alert=_on_event,
        organization=org,
        sector=sector,
        beacon_base=beacon_base,
    )
    _canary_mgr.deploy()
    for c in _canary_mgr.status():
        trail = f" [trail:{c['trail_node']}]" if c.get("trail_node") else ""
        print(f"       {c['name']:22} → {c['path']}{trail}")

    # 3. SMB decoys
    if cfg.get("smb_enabled", True):
        print(f"[{step}/{total}] Starting decoy SMB shares...")
        step += 1
        _smb_mgr = SMBManager(
            port=int(cfg.get("smb_port", 4450)),
            listen_addr=cfg.get("listen_address", "0.0.0.0"),
            share_names=cfg.get("smb_shares") or ["Finance", "HR", "Backups"],
            on_connect=_on_event,
        )
        _smb_mgr.deploy()
        for s in _smb_mgr.status():
            print(f"       smb        on port {s['port']} shares={s['shares']}")

    # 4. Beacon listener
    if cfg.get("beacon_enabled", True):
        print(f"[{step}/{total}] Starting beacon listener...")
        known = set(_canary_mgr.beacon_token_ids) if _canary_mgr else set()
        _beacon_listener = BeaconListener(
            host=cfg.get("listen_address", "0.0.0.0"),
            port=int(cfg.get("beacon_port", 8888)),
            on_beacon=_on_event,
            known_ids=known,
        )
        _beacon_listener.start()
        st = _beacon_listener.status()
        print(f"       beacon     on port {st['port']} (known tokens: {st['known_tokens']})")

    log_auth("deploy", auth_ref, f"full depth deploy incl SSH jail (sector={sector})")
    print()
    print("[+] Mirage is live.")
    if jail_on:
        print("    SSH jail is armed — any login + commands will be captured.")
    print("    Commands: mirage status | mirage alerts | mirage report --story")
    print("    Stop with Ctrl+C")
    print()

    def _shutdown(sig, frame):
        print("\n[*] Stopping Mirage...")
        if _service_mgr:
            _service_mgr.stop_all()
        if _canary_mgr:
            _canary_mgr.stop()
        if _smb_mgr:
            _smb_mgr.stop()
        if _beacon_listener:
            _beacon_listener.stop()
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
    print(f"Auth ref       : {cfg.get('authorization_ref') or '(not set)'}")
    print(f"Data dir       : {cfg['data_dir']}")
    print(f"SSH jail       : {'ON' if cfg.get('ssh_jail_enabled', True) else 'OFF'} "
          f"(timeout {cfg.get('ssh_jail_timeout', 300)}s, port {cfg.get('ports', {}).get('ssh', 2222)})")
    print(f"SMB enabled    : {cfg.get('smb_enabled', True)} (port {cfg.get('smb_port', 4450)})")
    print(f"Beacon enabled : {cfg.get('beacon_enabled', True)} (port {cfg.get('beacon_port', 8888)})")
    print(f"Beacon URL     : {cfg.get('beacon_base_url') or '(local)'}")
    print(f"Webhook        : {'configured' if cfg.get('webhook_url') else 'none'}")
    print("Note: Live service status is available while 'mirage deploy' is running.")


def cmd_alerts(args):
    events = get_all_events(limit=args.recent or 20)
    if not events:
        print("No deception events recorded yet.")
        return
    print(f"=== Recent Mirage Events (last {len(events)}) ===")
    for e in events:
        cls = classify_event(e)
        intent = cls.get("intent", "?")
        details = e.get("details", "")
        # Highlight commands from the jail
        extra = ""
        if e.get("event_type") == "ssh_jail_command":
            try:
                import json
                d = json.loads(details) if isinstance(details, str) else details
                extra = f" cmd={d.get('command', '')!r}"
            except Exception:
                pass
        print(
            f"  [{e['timestamp']}] {e['event_type']:25} "
            f"src={e.get('source_ip') or 'n/a':15} "
            f"intent={intent:22}{extra} {str(details)[:40]}"
        )


def cmd_report(args):
    hours = 24 if args.daily else (args.hours or 24)
    story = getattr(args, "story", False) or args.client
    text = generate_report(hours=hours, client_mode=args.client, story=story)
    print(text)


def cmd_bait(args):
    cfg = load_config()
    org = args.org or cfg.get("organization_name") or "Company"
    sector = args.sector or cfg.get("sector") or "general"
    beacon_base = cfg.get("beacon_base_url") or f"http://127.0.0.1:{cfg.get('beacon_port', 8888)}"
    mgr = CanaryManager(
        base_dir=cfg.get("canary_base_dir"),
        organization=org,
        sector=sector,
        beacon_base=beacon_base,
    )
    baits = mgr.generate_baits(org=org, sector=sector)
    print(f"=== Decoy Document Factory — {org} ({sector}) ===")
    print()
    for b in baits:
        print(f"  {b['name']:22} → {b['relpath']}")
        preview = b["content"].strip().splitlines()[0][:70]
        print(f"    preview: {preview}...")
    print()
    if args.write:
        mgr.deploy(baits)
        print("[+] Bait + trail files written to disk.")
    else:
        print("Pass --write to actually create the files on disk.")


def cmd_stop(_args):
    print("[*] Stop is handled by Ctrl+C on the running deploy process.")
    print("    If you started it under systemd, use: systemctl stop mirage")


def cmd_clean(args):
    cfg = load_config()
    base = Path(cfg.get("canary_base_dir", ""))
    if base.exists():
        import shutil
        shutil.rmtree(base, ignore_errors=True)
        print("[+] Canary / trail files removed")
    else:
        print("[*] No canary directory found")
    log_auth("clean", cfg.get("authorization_ref", ""), "canaries cleaned")


def main():
    parser = argparse.ArgumentParser(
        description=f"Mirage {__version__} — Active Deception Platform by TrinTech Digital Defense",
        epilog="Authorized defensive use only. Obtain written permission before deployment.",
    )
    parser.add_argument("--version", action="version", version=f"Mirage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Initialize config and database")
    p.add_argument("--org", help="Organization / client name")
    p.add_argument("--auth-ref", help="Authorization / ROE reference")
    p.add_argument("--sector", help="Industry sector (general|clinic|retail|legal)")
    p.add_argument("--beacon-url", help="Public beacon base URL for honey tokens")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("deploy", help="Deploy services, SSH jail, canaries, trails, SMB, beacons")
    p.add_argument("--force", action="store_true", help="Deploy without auth-ref")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("status", help="Show status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("alerts", help="Show recent deception events (with intent)")
    p.add_argument("--recent", "-r", type=int, default=20)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("report", help="Generate report")
    p.add_argument("--daily", action="store_true")
    p.add_argument("--hours", type=int)
    p.add_argument("--client", action="store_true", help="Client-facing format (alias for --story)")
    p.add_argument("--story", action="store_true", help="'We Caught Them' narrative report")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("bait", help="Preview / generate tailored decoy documents")
    p.add_argument("--org", help="Override organization name")
    p.add_argument("--sector", help="Override sector")
    p.add_argument("--write", action="store_true", help="Actually write the files")
    p.set_defaults(func=cmd_bait)

    p = sub.add_parser("stop", help="Stop guidance")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("clean", help="Remove canary files")
    p.set_defaults(func=cmd_clean)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
