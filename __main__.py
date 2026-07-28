"""Mirage v1.0.0 — TrinTech Digital Defense Deception Grid.

Usage:
    python3 -m mirage deploy [--interface IFACE] [--network NETWORK/CIDR]
    python3 -m mirage status
    python3 -m mirage alerts [--recent N]
    python3 -m mirage kill
    python3 -m mirage clean

Requires: Python 3.6+, scapy, iptables, nmap (optional auto-discovery)
"""

import argparse
import ipaddress
import logging
import os
import subprocess
import sys
import json

# ─── Force import of submodules (if running as `python3 -m mirage`)
EMBEDDED = False
# We'll import from relative modules
from . import skeleton
from . import triggers
from . import alerts

logger = logging.getLogger("mirage")


# ─── Auto-discover network via `ip route` ───────────────────────────

def _discover_network(interface: str = "") -> str | None:
    """Try to discover local network from routing table."""
    try:
        cmd = ["ip", "route"]
        if interface:
            cmd = ["ip", "route", "show", "dev", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            # Look for "default via ... dev ..." or "{cidr} dev ..."
            for i, part in enumerate(parts):
                if part == "dev" and i + 1 < len(parts):
                    iface = parts[i + 1]
                try:
                    network = ipaddress.ip_network(parts[0], strict=False)
                    if network.num_addresses > 1:
                        logger.info("Auto-discovered network: %s (interface: %s)", network, iface)
                        return str(network)
                except ValueError:
                    continue
        logger.warning("Could not auto-discover network")
        return None
    except Exception as e:
        logger.warning("Auto-discovery failed: %s", e)
        return None


# ─── Alert handler ─────────────────────────────────────────────────

def _on_event(event_type: str, data: dict):
    """Central event handler — logs alerts and sends notifications."""
    evt = alerts.log_event(event_type, data)
    alert_msg = f"[MIRAGE] {event_type}: {json.dumps(data)}"
    print(f"🔴 {alert_msg}")
    # WhatApp URL is generated but NOT auto-opened (security)
    wa_url = alerts.send_whatsapp_alert(alert_msg)
    print(f"   WhatsApp link: {wa_url}")
    return evt


# ─── CLI Handlers ──────────────────────────────────────────────────

def cmd_deploy(args):
    iface = args.interface or ""
    network = args.network or _discover_network(iface)
    if not network:
        logger.error("No network specified and auto-discovery failed")
        print("ERROR: Could not determine network. Use --network 192.168.1.0/24")
        sys.exit(1)

    print(f"🚀 Mirage Deception Grid deploying on {network} (interface: {iface or 'auto'})...")
    print()

    # 1. Deploy skeleton decoys
    print("[1/3] Deploying TCP skeleton decoys...")
    ports = [22, 80, 443, 3306, 8080]
    skel_mgr = skeleton.SkeletonManager(ports=ports, interface=iface, on_connection=_on_event)
    skel_mgr.deploy()
    print(f"       Decoys active on ports: {ports}")

    # 2. Deploy file triggers
    print("[2/3] Deploying filesystem decoy triggers...")
    trigger_mgr = triggers.TriggerManager(on_alert=_on_event)
    trigger_mgr.add(triggers.Trigger(
        name="fake_db_creds",
        path="config/db_credentials.txt",
        content="admin:P@ssw0rd123! -- DO NOT USE (Decoy)",
        alert_type="DECOY_MODIFIED"
    ))
    trigger_mgr.add(triggers.Trigger(
        name="vpn_config",
        path="config/vpn.ovpn",
        content="client\ndev tun\nremote 10.0.0.1 1194\n-- DECOY FILE --",
        alert_type="DECOY_MODIFIED"
    ))
    trigger_mgr.add(triggers.Trigger(
        name="fake_financial_report",
        path="finance/q2_report.xlsx",
        content="Revenue: $2.4M (DECOY - DO NOT OPEN)",
        alert_type="DECOY_MODIFIED"
    ))
    trigger_mgr.deploy_all()
    print("       Decoys placed at: /tmp/mirage_decoys/")
    print("          - config/db_credentials.txt")
    print("          - config/vpn.ovpn")
    print("          - finance/q2_report.xlsx")

    # 3. Save managers for kill/status commands
    import __main__ as main_mod
    main_mod._skel_mgr = skel_mgr
    main_mod._trigger_mgr = trigger_mgr

    print()
    print("✅ Mirage deployed. Attackers touching decoys will trigger alerts.")
    print(f"   Check with: python3 -m mirage alerts")
    print()


def cmd_status(args):
    try:
        import __main__ as main_mod
        skel = main_mod._skel_mgr.status() if hasattr(main_mod, '_skel_mgr') else []
        trig = main_mod._trigger_mgr.status() if hasattr(main_mod, '_trigger_mgr') else {}
    except (ImportError, AttributeError):
        skel = []
        trig = {}

    print("=== Mirage Status ===")
    print(f"Skeleton decoys: {skel}")
    print(f"File triggers:    {trig.get('active_triggers', [])}")
    print(f"Watcher running:  {trig.get('watching', False)}")
    print()


def cmd_kill(args):
    try:
        import __main__ as main_mod
        if hasattr(main_mod, '_skel_mgr'):
            main_mod._skel_mgr.tear_down()
        if hasattr(main_mod, '_trigger_mgr'):
            main_mod._trigger_mgr.stop_watching()
    except (ImportError, AttributeError):
        pass
    print("Mirage stopped. All decoys torn down.")


def cmd_clean(args):
    try:
        import __main__ as main_mod
        if hasattr(main_mod, '_trigger_mgr'):
            main_mod._trigger_mgr.cleanup()
    except (ImportError, AttributeError):
        pass
    alerts.clear()
    print("Mirage cleaned. All artifacts removed.")


def cmd_alerts(args):
    recent = getattr(args, 'recent', 10)
    if recent:
        items = alerts.get_recent(recent)
    else:
        items = alerts.get_all()
    if not items:
        print("No alerts yet.")
        return
    print(f"=== Recent Alerts (last {len(items)}) ===")
    for item in items:
        print(f"  [{item['timestamp']}] {item['type']}: {item['data']}")
    print()


# ─── Main parser ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="python3 -m mirage",
        description="Mirage Deception Grid — TrinTech Digital Defense",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # deploy
    p_deploy = sub.add_parser("deploy", help="Deploy deception grid")
    p_deploy.add_argument("--interface", "-i", default="", help="Network interface (e.g. eth0)")
    p_deploy.add_argument("--network", "-n", default="", help="Network CIDR (e.g. 192.168.1.0/24)")
    p_deploy.set_defaults(func=cmd_deploy)

    # status
    p_status = sub.add_parser("status", help="Show current deception status")
    p_status.set_defaults(func=cmd_status)

    # alerts
    p_alerts = sub.add_parser("alerts", help="Show recent alerts")
    p_alerts.add_argument("--recent", "-r", type=int, default=10, help="Number of recent alerts to show")
    p_alerts.set_defaults(func=cmd_alerts)

    # kill
    p_kill = sub.add_parser("kill", help="Stop all decoys")
    p_kill.set_defaults(func=cmd_kill)

    # clean
    p_clean = sub.add_parser("clean", help="Remove all decoy artifacts")
    p_clean.set_defaults(func=cmd_clean)

    # alerts-all convenience
    p_alerts_all = sub.add_parser("alerts-all", help="Show all alerts ever")
    p_alerts_all.set_defaults(func=cmd_alerts, recent=None)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    main()
