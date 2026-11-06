#!/usr/bin/env python3
"""Mirage v2.5 — Active Deception Platform CLI"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from . import __version__
from .config import load_config, save_config, ensure_data_dir, validate_listen_address, data_dir_path
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
from .registry import REGISTRY, ServiceState
from .probe import probe_registry_rows, probe_summary

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


def _pid_path() -> Path:
    return ensure_data_dir() / "mirage.pid"


def _on_event(event_type: str, source_ip: str = "", details: dict = None):
    emit(event_type, source_ip, details or {}, severity="high")


def _stop_all_managers():
    global _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy
    global _tarpit_mgr, _dns_canary, _telnet_jail, _web_api
    for mgr in (
        _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy,
        _tarpit_mgr, _dns_canary, _telnet_jail, _web_api,
    ):
        if not mgr:
            continue
        try:
            if hasattr(mgr, "stop_all"):
                mgr.stop_all()
            elif hasattr(mgr, "stop"):
                mgr.stop()
            elif hasattr(mgr, "cleanup"):
                mgr.cleanup()
        except Exception as e:
            logger.debug("stop error: %s", e)
    try:
        REGISTRY.stop_all()
    except Exception:
        pass


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
    print(f"    Listen       : {validate_listen_address(cfg)} (external={cfg.get('allow_external_bind')})")


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
    print(f"  Bind={validate_listen_address(cfg)} external_ok={cfg.get('allow_external_bind')}")


def cmd_deploy(args):
    global _service_mgr, _canary_mgr, _smb_mgr, _beacon_listener, _cloud_decoy
    global _tarpit_mgr, _dns_canary, _telnet_jail, _web_api
    cfg = load_config()
    init_db()
    auth_ref = cfg.get("authorization_ref", "")
    if not auth_ref and not args.force:
        print("[!] No authorization_ref set. Use: mirage init --auth-ref ROE-XXXX")
        return

    listen = validate_listen_address(cfg)
    if listen == "127.0.0.1" and cfg.get("listen_address") in ("0.0.0.0", "::"):
        print("[!] External bind requested but allow_external_bind is false — forcing 127.0.0.1")
    if listen in ("0.0.0.0", "::"):
        print("[!] WARNING: binding externally. Ensure ROE + firewall segmentation.")

    if cfg.get("guardrails_enabled", True):
        guardrails.configure(
            rate_limit=int(cfg.get("rate_limit_per_source", 30)),
            rate_window=int(cfg.get("rate_limit_window_sec", 60)),
            breaker_threshold=int(cfg.get("circuit_breaker_threshold", 500)),
            breaker_window=int(cfg.get("circuit_breaker_window_sec", 60)),
            max_global=int(cfg.get("max_concurrent_global", 200)),
            max_per_service=int(cfg.get("max_concurrent_per_service", 50)),
            max_per_source=int(cfg.get("max_per_source_sessions", 20)),
            enabled=True,
        )

    REGISTRY.clear()
    org = cfg.get("organization_name") or "Company"
    sector = cfg.get("sector") or "general"
    beacon_base = cfg.get("beacon_base_url") or ""
    if not beacon_base and cfg.get("beacon_enabled", True):
        beacon_base = f"http://127.0.0.1:{cfg.get('beacon_port', 8888)}"

    print(f"[*] Deploying Mirage {__version__}")
    print(f"    Org={org} sector={sector} ROE={auth_ref or 'NONE'} bind={listen}")
    print()

    print("[*] Fake services + SSH jail...")
    _service_mgr = ServiceManager(
        ports=cfg.get("ports", {}),
        listen_addr=listen,
        on_connect=_on_event,
        ssh_jail=cfg.get("ssh_jail_enabled", True),
        ssh_jail_timeout=int(cfg.get("ssh_jail_timeout", 300)),
        https_enabled=bool(cfg.get("https_enabled", False)),
    )
    _service_mgr.deploy()
    for s in _service_mgr.status():
        print(f"       {s.get('name', '?'):12} port {s.get('port')}")

    if cfg.get("telnet_jail_enabled", True):
        print("[*] Telnet command sandbox...")
        _telnet_jail = TelnetJail(port=int(cfg.get("telnet_jail_port", 2323)), listen_addr=listen, on_event=_on_event)
        if _telnet_jail.start():
            REGISTRY.register("telnet_jail", port=int(cfg.get("telnet_jail_port", 2323)), state=ServiceState.RUNNING, stop_fn=_telnet_jail.stop)
            print(f"       telnet_jail port {cfg.get('telnet_jail_port', 2323)}")
        else:
            REGISTRY.register("telnet_jail", port=int(cfg.get("telnet_jail_port", 2323)), state=ServiceState.FAILED, error="bind failed")

    if cfg.get("web_api_enabled", True):
        print("[*] Decoy web API endpoints...")
        _web_api = WebAPIDecoy(port=int(cfg.get("web_api_port", 8081)), listen_addr=listen, on_event=_on_event)
        if _web_api.start():
            REGISTRY.register("web_api", port=int(cfg.get("web_api_port", 8081)), state=ServiceState.RUNNING, stop_fn=_web_api.stop)
            print(f"       web_api    port {cfg.get('web_api_port', 8081)}")
        else:
            REGISTRY.register("web_api", port=int(cfg.get("web_api_port", 8081)), state=ServiceState.FAILED, error="bind failed")

    if cfg.get("tarpit_enabled", True):
        print("[*] TCP tarpit / sinkhole...")
        _tarpit_mgr = TarpitManager(
            ports=list(cfg.get("tarpit_ports") or [2223, 3391, 4451]),
            listen_addr=listen,
            drip_interval=float(cfg.get("tarpit_drip_interval", 2.0)),
            max_session_sec=float(cfg.get("tarpit_max_session_sec", 120.0)),
            on_event=_on_event,
        )
        _tarpit_mgr.deploy()
        for s in _tarpit_mgr.status():
            REGISTRY.register("tarpit", port=s["port"], state=ServiceState.RUNNING)
            print(f"       tarpit      port {s['port']}")

    if cfg.get("dns_canary_enabled", True):
        print("[*] DNS canary...")
        _dns_canary = DNSCanary(
            port=int(cfg.get("dns_canary_port", 5353)),
            listen_addr=listen,
            canary_names=list(cfg.get("dns_canary_names") or []),
            on_event=_on_event,
        )
        if _dns_canary.start():
            REGISTRY.register("dns_canary", port=int(cfg.get("dns_canary_port", 5353)), state=ServiceState.RUNNING, stop_fn=_dns_canary.stop)
            print(f"       dns canary  port {cfg.get('dns_canary_port', 5353)}")
        else:
            REGISTRY.register("dns_canary", port=int(cfg.get("dns_canary_port", 5353)), state=ServiceState.FAILED, error="bind failed")

    print("[*] Canaries / credentials / doc web-bugs...")
    _canary_mgr = CanaryManager(
        base_dir=cfg.get("canary_base_dir"),
        on_alert=_on_event,
        organization=org,
        sector=sector,
        beacon_base=beacon_base,
    )
    _canary_mgr.deploy()
    REGISTRY.register("canaries", state=ServiceState.RUNNING, stop_fn=_canary_mgr.stop)
    print(f"       {len(_canary_mgr.status())} decoy files deployed")

    if cfg.get("smb_enabled", True):
        print("[*] Decoy SMB (low-interaction)...")
        shares = cfg.get("smb_shares") or pack_share_names(sector)
        _smb_mgr = SMBManager(
            port=int(cfg.get("smb_port", 4450)),
            listen_addr=listen,
            share_names=shares,
            on_connect=_on_event,
        )
        if _smb_mgr.deploy():
            REGISTRY.register("smb", port=int(cfg.get("smb_port", 4450)), state=ServiceState.RUNNING, stop_fn=_smb_mgr.stop)
        else:
            REGISTRY.register("smb", port=int(cfg.get("smb_port", 4450)), state=ServiceState.FAILED, error="bind failed")

    if cfg.get("beacon_enabled", True):
        print("[*] Beacon listener...")
        known = set(_canary_mgr.beacon_token_ids) if _canary_mgr else set()
        _beacon_listener = BeaconListener(
            host=listen,
            port=int(cfg.get("beacon_port", 8888)),
            on_beacon=_on_event,
            known_ids=known,
        )
        if _beacon_listener.start():
            REGISTRY.register("beacon", port=int(cfg.get("beacon_port", 8888)), state=ServiceState.RUNNING, stop_fn=_beacon_listener.stop)
            print(f"       beacon port {cfg.get('beacon_port', 8888)}")
        else:
            REGISTRY.register("beacon", port=int(cfg.get("beacon_port", 8888)), state=ServiceState.FAILED, error="bind failed")

    if cfg.get("cloud_decoy_enabled", True):
        print("[*] Cloud decoy...")
        _cloud_decoy = CloudDecoy(
            org=org,
            port=int(cfg.get("cloud_decoy_port", 9000)),
            listen_addr=listen,
            on_event=_on_event,
        )
        if _cloud_decoy.start():
            REGISTRY.register("cloud", port=int(cfg.get("cloud_decoy_port", 9000)), state=ServiceState.RUNNING, stop_fn=_cloud_decoy.stop)
            print(f"       cloud port {cfg.get('cloud_decoy_port', 9000)}")
        else:
            REGISTRY.register("cloud", port=int(cfg.get("cloud_decoy_port", 9000)), state=ServiceState.FAILED, error="bind failed")

    try:
        site = register_site()
        print(f"[+] Mesh site {site.get('site_id')}")
    except Exception as e:
        logger.warning("Mesh register failed: %s", e)

    summary = REGISTRY.summary()
    time.sleep(0.4)
    probe_host = "127.0.0.1" if listen in ("0.0.0.0", "::", "") else listen
    probed = probe_registry_rows(REGISTRY.status_list(), host=probe_host)
    psum = probe_summary(probed)
    for row in probed:
        if row.get("probe_ok") is False:
            REGISTRY.set_state(row["name"], ServiceState.DEGRADED, error=f"probe failed: {row.get('probe_detail')}", port=int(row.get("port") or 0))
            print(f"    [!] probe FAIL {row.get('name')} :{row.get('port')} — {row.get('probe_detail')}")
        elif row.get("probe_ok") is True:
            print(f"    [+] probe OK   {row.get('name')} :{row.get('port')}")
    summary = REGISTRY.summary()
    log_auth("deploy", auth_ref, f"v{__version__} deploy running={summary.get('running')} failed={summary.get('failed')} probe_ok={psum.get('ok')}")
    _pid_path().write_text(str(os.getpid()), encoding="utf-8")

    print()
    print(f"[+] Registry: {summary.get('running')} RUNNING, {summary.get('failed')} FAILED, probe {psum.get('ok')}/{psum.get('probed')} OK")
    if summary.get("failed") or psum.get("fail"):
        print("[!] Some services failed or failed post-bind probe — not fully healthy")
        for row in REGISTRY.status_list():
            if row["state"] in ("FAILED", "DEGRADED"):
                print(f"    {row['state']} {row['name']} : {row.get('error')}")
    else:
        print("[+] Mirage live (registered services OK or DISABLED by design).")
    print("    Stop:  mirage stop   or Ctrl+C\n")

    def _shutdown(sig, frame):
        print("\n[*] Stopping...")
        _stop_all_managers()
        try:
            _pid_path().unlink(missing_ok=True)
        except OSError:
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
    print(f"Listen         : {validate_listen_address(cfg)}")
    print(f"External bind  : {cfg.get('allow_external_bind', False)}")
    print(f"HTTPS          : {cfg.get('https_enabled', False)} (disabled until TLS)")
    gs = guardrails.status()
    print(f"Guardrails     : paused={gs.get('listeners_paused')} breaker={gs.get('circuit_breaker', {}).get('tripped')}")
    pidf = _pid_path()
    if pidf.exists():
        print(f"Deploy PID     : {pidf.read_text().strip()}")


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
    print()
    print("Registry + post-bind probes:")
    rows = REGISTRY.status_list() or []
    probed = probe_registry_rows(rows, host="127.0.0.1")
    for row in probed:
        probe = row.get("probe_ok")
        tag = "OK" if probe is True else ("FAIL" if probe is False else "-")
        print(f"  {row.get('state'):10} {row.get('name'):12} port={row.get('port')} probe={tag}")
    psum = probe_summary(probed)
    print(f"Probes: {psum.get('ok')}/{psum.get('probed')} OK")
    gs = guardrails.status()
    print(f"Guardrails paused={gs.get('listeners_paused')} sessions={gs.get('sessions')}")


def cmd_packs(_args):
    for p in list_packs():
        print(f"  {p['id']:<14} {p['label']}")


def cmd_killswitch(args):
    if args.reset:
        guardrails.reset_breaker()
        print("[+] circuit breaker reset — listeners may resume")
        return
    for _ in range(int(guardrails.CIRCUIT_BREAKER_THRESHOLD) + 5):
        guardrails.check_source("killswitch")
    print("[!] breaker tripped — listeners paused")


def cmd_stop(_args):
    pidf = _pid_path()
    if not pidf.exists():
        print("[*] No mirage.pid — if deploy is in foreground, use Ctrl+C")
        return
    try:
        pid = int(pidf.read_text().strip())
    except ValueError:
        print("[x] Invalid pid file")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[+] Sent SIGTERM to deploy process {pid}")
    except ProcessLookupError:
        print(f"[!] PID {pid} not running — removing stale pid file")
        pidf.unlink(missing_ok=True)
    except PermissionError:
        print(f"[x] Cannot signal PID {pid} (permission)")


def cmd_clean(args):
    cfg = load_config()
    data = data_dir_path(cfg).resolve()
    decoys = (data / "decoys").resolve()
    configured = Path(cfg.get("canary_base_dir") or decoys).resolve()
    try:
        configured.relative_to(data)
    except ValueError:
        print(f"[x] Refusing clean: {configured} is outside Mirage data dir {data}")
        return
    if configured == data or configured == Path("/") or configured == Path.home().resolve():
        print("[x] Refusing clean of data root / home")
        return
    if not configured.exists():
        print("[*] Nothing to clean")
        return
    if not args.yes:
        print(f"[!] Would delete decoys under: {configured}")
        print("    Re-run with: mirage clean --yes")
        print("    (events.db and evidence/ are never deleted by clean)")
        return
    import shutil
    shutil.rmtree(configured, ignore_errors=True)
    configured.mkdir(parents=True, exist_ok=True)
    print(f"[+] Cleaned decoys under {configured}")
    print("    events.db and evidence preserved")


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
    p = sub.add_parser("clean"); p.add_argument("--yes", action="store_true"); p.set_defaults(func=cmd_clean)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
