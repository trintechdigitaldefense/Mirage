#!/bin/bash
set -e

# ─── Mirage: TrinTech Deception Grid ──────────────────────────────────
# Creates all files in ~/trintech-mirage/
# Run: bash ~/trintech-mirage/save_mirage.sh
# Then: cd ~/trintech-mirage && sudo python3 -m mirage deploy
# ────────────────────────────────────────────────────────────────────────

DEST=~/trintech-mirage

# ─── 1. skeleton / __init__.py ─────────────────────────────────────
mkdir -p "$DEST/skeleton"

cat > "$DEST/skeleton/__init__.py" << 'EOF'
"""Mirage skeleton decoys — lightweight TCP listeners."""

import socket
import threading
import logging
import time
import random
import struct

logger = logging.getLogger("mirage.skeleton")

BANNERS = {
    22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n<html><body><h1>Welcome</h1></body></html>",
    443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><body><h1>Secure Portal</h1></body></html>",
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f",
    8080: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><body><h1>Dashboard</h1><p>Unauthorized</p></body></html>"
}


class SkeletonService:
    """Manages a single decoy TCP listener on a port."""

    def __init__(self, port: int, interface: str = "", on_connection=None):
        self.port = port
        self.interface = interface
        self.on_connection = on_connection
        self._server = None
        self._thread = None
        self._running = False

    def _handle(self, conn, addr):
        logger.info("DECOY_CONNECTED port=%d from=%s", self.port, addr)
        if self.on_connection:
            self.on_connection("decoy_connect", {
                "port": self.port, "source_ip": addr[0],
                "source_port": addr[1], "protocol": "tcp"
            })
        try:
            banner = BANNERS.get(self.port, b"\n")
            if isinstance(banner, str):
                banner = banner.encode()
            conn.sendall(banner)
            time.sleep(random.uniform(0.3, 2.0))
        except OSError:
            pass
        finally:
            conn.close()

    def start(self):
        if self._running:
            return
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_addr = self.interface or "0.0.0.0"
        self._server.bind((bind_addr, self.port))
        self._server.listen(5)
        self._server.settimeout(1.0)

        def serve():
            while self._running:
                try:
                    conn, addr = self._server.accept()
                    t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            self._server.close()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        logger.info("Decoy on port %d started", self.port)

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        logger.info("Decoy on port %d stopped", self.port)


class SkeletonManager:
    """Manages all decoy skeleton services."""

    def __init__(self, ports: list | None = None, interface: str = "", on_connection=None):
        self.ports = ports or [22, 80, 443, 3306, 8080]
        self.interface = interface
        self.on_connection = on_connection
        self.services: list[SkeletonService] = []

    def deploy(self, ports: list | None = None):
        if ports:
            self.ports = ports
        for p in self.ports:
            srv = SkeletonService(p, self.interface, self.on_connection)
            srv.start()
            self.services.append(srv)
        logger.info("Skeleton decoys deployed on ports: %s", self.ports)

    def tear_down(self):
        for srv in self.services:
            srv.stop()
        self.services.clear()
        logger.info("All skeleton decoys stopped")

    def status(self) -> list:
        return [srv.port for srv in self.services if srv._running]
EOF

# ─── 2. triggers / __init__.py ─────────────────────────────────────
mkdir -p "$DEST/triggers"

cat > "$DEST/triggers/__init__.py" << 'EOF'
"""Mirage triggers — alert/persistence layer."""

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger("mirage.triggers")


class Trigger:
    """A single decoy artifact that triggers an alert when interacted with."""

    def __init__(self, name: str, path: str = "", content: str = "", alert_type: str = "decoy_touched"):
        self.name = name
        self.path = path
        self.content = content
        self.alert_type = alert_type
        self.checksum = hashlib.sha256(content.encode()).hexdigest() if content else ""
        self._persisted = False

    def deploy(self, base_dir: str = "/tmp/mirage_decoys") -> str:
        os.makedirs(base_dir, exist_ok=True)
        file_path = os.path.join(base_dir, self.path or self.name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(self.content)
        self.checksum = hashlib.sha256(self.content.encode()).hexdigest()
        self._persisted = True
        logger.info("Trigger deployed: %s at %s", self.name, file_path)
        return file_path

    def verify(self) -> bool:
        if not self._persisted:
            return False
        file_path = os.path.join("/tmp/mirage_decoys", self.path or self.name)
        if not os.path.exists(file_path):
            return False
        with open(file_path) as f:
            current = f.read()
        return hashlib.sha256(current.encode()).hexdigest() == self.checksum

    def check(self, base_dir: str = "/tmp/mirage_decoys") -> dict | None:
        """Returns alert dict if tampered, else None."""
        file_path = os.path.join(base_dir, self.path or self.name)
        if not os.path.exists(file_path):
            return {"type": self.alert_type, "trigger": self.name, "event": "deleted"}
        with open(file_path) as f:
            content = f.read()
        if hashlib.sha256(content.encode()).hexdigest() != self.checksum:
            return {"type": self.alert_type, "trigger": self.name, "event": "modified"}
        return None


class TriggerManager:
    """Manages a set of decoy triggers with optional persistence watcher."""

    def __init__(self, base_dir: str = "/tmp/mirage_decoys", on_alert=None):
        self.base_dir = base_dir
        self.on_alert = on_alert
        self.triggers: list[Trigger] = []
        self._watcher_thread = None
        self._watching = False

    def add(self, trigger: Trigger):
        self.triggers.append(trigger)

    def deploy_all(self):
        out = []
        for t in self.triggers:
            p = t.deploy(self.base_dir)
            out.append(p)
        logger.info("All triggers deployed (%d total)", len(self.triggers))
        return out

    def check_all(self) -> list[dict]:
        current_state_path = os.path.join(self.base_dir, ".mirage_check_state.json")
        if os.path.exists(current_state_path):
            try:
                with open(current_state_path) as f:
                    _ = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        alerts = []
        for t in self.triggers:
            result = t.check(self.base_dir)
            if result:
                alerts.append(result)
                if self.on_alert:
                    self.on_alert("trigger_alert", result)
        return alerts

    def watch(self, interval: float = 5.0):
        """Continuously check triggers in a background thread."""

        def loop():
            while self._watching:
                alerts = self.check_all()
                if alerts:
                    logger.warning("Trigger alerts detected: %s", alerts)
                time.sleep(interval)

        self._watching = True
        self._watcher_thread = threading.Thread(target=loop, daemon=True)
        self._watcher_thread.start()
        logger.info("Trigger watcher started (interval=%ss)", interval)

    def stop_watching(self):
        self._watching = False
        logger.info("Trigger watcher stopped")

    def cleanup(self):
        import shutil
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)
            logger.info("All trigger artifacts cleaned up")

    def status(self) -> dict:
        return {
            "total_triggers": len(self.triggers),
            "active_triggers": [t.name for t in self.triggers],
            "watching": self._watching,
        }
EOF

# ─── 3. alerts / __init__.py ───────────────────────────────────────
mkdir -p "$DEST/alerts"

cat > "$DEST/alerts/__init__.py" << 'EOF'
"""Mirage alerts — multiple output channels."""

import json
import logging
import smtplib
import subprocess
import time
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("mirage.alerts")

ALERT_LOG = Path("/tmp/mirage_alerts.json")


def _ensure_log():
    if not ALERT_LOG.exists():
        ALERT_LOG.write_text("[]\n")


def _read_alerts() -> list:
    _ensure_log()
    try:
        return json.loads(ALERT_LOG.read_text())
    except (json.JSONDecodeError, ValueError):
        return []


def _write_alerts(alerts: list):
    ALERT_LOG.write_text(json.dumps(alerts, indent=2))


def log_event(event_type: str, data: dict):
    """Log an alert to the persistent JSON log."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": event_type,
        "data": data,
    }
    alerts = _read_alerts()
    alerts.append(entry)
    _write_alerts(alerts)
    logger.warning("Alert logged: %s %s", event_type, data)

    # Also write to stdout in a parseable format
    msg = json.dumps(entry)
    print(f"[MIRAGE_ALERT] {msg}")

    return entry


def get_recent(count: int = 10) -> list:
    """Return the most recent alerts."""
    alerts = _read_alerts()
    return alerts[-count:]


def get_all() -> list:
    return _read_alerts()


def clear():
    _write_alerts([])
    logger.info("All alerts cleared")


# ─── Send Alert via WhatsApp (via WhatsApp Web link) ──────────────

def send_whatsapp_alert(alert_msg: str, phone_number: str = ""):
    """Send alert by opening a WhatsApp link (works on desktop/phone)."""
    import urllib.parse
    if phone_number:
        url = f"https://wa.me/{phone_number}?text={urllib.parse.quote(alert_msg)}"
    else:
        url = f"https://web.whatsapp.com/send?text={urllib.parse.quote(alert_msg)}"
    logger.info("WhatsApp alert URL: %s", url)
    return url


# ─── Send Alert via Email ─────────────────────────────────────────

def send_email_alert(
    alert_msg: str,
    smtp_server: str = "",
    smtp_port: int = 587,
    sender: str = "",
    password: str = "",
    recipient: str = "",
):
    """Send email alert via SMTP."""
    if not all([smtp_server, sender, password, recipient]):
        logger.warning("Email alert skipped — missing credentials")
        return False
    try:
        msg = MIMEText(alert_msg)
        msg["Subject"] = "[MIRAGE] Deception Alert"
        msg["From"] = sender
        msg["To"] = recipient
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
        logger.info("Email alert sent to %s", recipient)
        return True
    except Exception as e:
        logger.error("Email alert failed: %s", e)
        return False


# ─── Command-line helper ──────────────────────────────────────────

def print_recent():
    alerts = get_recent()
    if not alerts:
        print("No alerts yet.")
        return
    for a in alerts:
        print(f"[{a['timestamp']}] {a['type']}: {json.dumps(a['data'])}")
EOF

# ─── 4. __main__.py (CLI entry point) ───────────────────────────────

cat > "$DEST/__main__.py" << 'EOF'
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
EOF

# ─── 5. requirements.txt ──────────────────────────────────────────

cat > "$DEST/requirements.txt" << 'EOF'
scapy>=2.4.5
argparse  # stdlib (note for clarity)
EOF

# ─── 6. setup.py (optional, for pip install) ───────────────────────

cat > "$DEST/setup.py" << 'EOF'
from setuptools import setup, find_packages

setup(
    name="mirage",
    version="1.0.0",
    description="Mirage Deception Grid — TrinTech Digital Defense",
    author="Jason Junior Ramdharry",
    author_email="trintechdigitaldefense@gmail.com",
    url="https://trintechdigitaldefense.github.io",
    packages=find_packages(),
    install_requires=["scapy>=2.4.5"],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "mirage=mirage.__main__:main"
        ]
    },
)
EOF

# ─── 7. MANIFEST.in ───────────────────────────────────────────────

cat > "$DEST/MANIFEST.in" << 'EOF'
include requirements.txt
recursive-include skeleton *.py
recursive-include triggers *.py
recursive-include alerts *.py
EOF

# ─── 8. .gitignore ────────────────────────────────────────────────

cat > "$DEST/.gitignore" << 'EOF'
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
.eggs/
dist/
build/
.venv/
env/
venv/
*.swp
*.swo
*~
.DS_Store
EOF

echo ""
echo "============================================="
echo "  ✅ MIRAGE created at: $DEST"
echo "============================================="
echo ""
echo "  To deploy:"
echo "    cd $DEST"
echo "    python3 -m mirage deploy"
echo ""
echo "  To check status:"
echo "    python3 -m mirage status"
echo ""
echo "  To view alerts:"
echo "    python3 -m mirage alerts"
echo ""
echo "  To stop all decoys:"
echo "    python3 -m mirage kill"
echo ""
echo "  To clean all artifacts:"
echo "    python3 -m mirage clean"
echo ""
echo "============================================="
