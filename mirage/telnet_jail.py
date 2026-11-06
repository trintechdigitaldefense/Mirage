"""Synthetic Telnet shell — command sandbox (v2.5 guardrails)."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional

from . import guardrails
from .redaction import fingerprint

logger = logging.getLogger("mirage.telnet_jail")

FAKE_RESPONSES = {
    "whoami": "root\r\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "pwd": "/root\r\n",
    "uname": "Linux decoy-host 5.15.0-91-generic #101 SMP x86_64 GNU/Linux\r\n",
    "uname -a": "Linux decoy-host 5.15.0-91-generic #101 SMP x86_64 GNU/Linux\r\n",
    "hostname": "decoy-host\r\n",
    "ls": "bin  boot  etc  home  root  tmp  usr  var\r\n",
    "ls -la": (
        "total 48\r\ndrwxr-xr-x  1 root root  4096 Jan  1 00:00 .\r\n"
        "drwxr-xr-x  1 root root  4096 Jan  1 00:00 ..\r\n"
        "-rw-------  1 root root   128 Jan  1 00:00 .bash_history\r\n"
    ),
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\r\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n"
    ),
    "cat /etc/shadow": "Permission denied\r\n",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING>  inet 10.0.0.15\r\n",
    "ip a": "1: lo: <LOOPBACK,UP>\n2: eth0: <BROADCAST,UP> inet 10.0.0.15/24\r\n",
    "ps": "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 systemd\r\n",
    "ps aux": "USER       PID %CPU %MEM COMMAND\r\nroot         1  0.0  0.1 systemd\r\n",
    "help": "Available: ls, whoami, id, pwd, uname, cat, ifconfig, ps, exit\r\n",
}


def _respond(cmd: str) -> str:
    c = cmd.strip()
    if not c:
        return ""
    low = c.lower()
    if low in FAKE_RESPONSES:
        return FAKE_RESPONSES[low]
    if low.startswith("cat "):
        return FAKE_RESPONSES.get(low, "No such file or directory\r\n")
    if low.startswith("cd "):
        return ""
    if low.startswith("wget") or low.startswith("curl"):
        return "Connecting... failed: Connection refused\r\n"
    if low in ("exit", "quit", "logout"):
        return "__EXIT__"
    return f"bash: {c.split()[0]}: command not found\r\n"


class TelnetJail:
    def __init__(
        self,
        port: int = 2323,
        listen_addr: str = "127.0.0.1",
        session_timeout: int = 180,
        on_event: Optional[Callable] = None,
    ):
        self.port = port
        self.listen_addr = listen_addr
        self.session_timeout = session_timeout
        self.on_event = on_event
        self._sock: Optional[socket.socket] = None
        self._running = False

    def _emit(self, et: str, source_ip: str, details: dict):
        if self.on_event:
            try:
                self.on_event(event_type=et, source_ip=source_ip, details=details)
            except Exception:
                pass

    def _session(self, conn: socket.socket, addr):
        source_ip = addr[0]
        allowed, reason = guardrails.accept_allowed("telnet_jail", source_ip)
        if not allowed:
            try:
                conn.close()
            except OSError:
                pass
            return
        commands: List[str] = []
        try:
            self._emit("telnet_jail_connect", source_ip, {"service": "telnet_jail", "port": self.port})
            conn.settimeout(self.session_timeout)
            conn.sendall(b"\r\nUbuntu 22.04.3 LTS\r\ndecoy-host login: ")
            user = b""
            while not user.endswith(b"\n") and not user.endswith(b"\r"):
                chunk = conn.recv(1)
                if not chunk:
                    return
                user += chunk
            username = user.decode("utf-8", errors="replace").strip() or "root"
            conn.sendall(b"Password: ")
            pw = b""
            while not pw.endswith(b"\n") and not pw.endswith(b"\r"):
                chunk = conn.recv(1)
                if not chunk:
                    return
                pw += chunk
            # Password discarded after length/fingerprint — never emitted
            pw_text = pw.decode("utf-8", errors="replace").strip("\r\n")
            self._emit(
                "telnet_jail_login",
                source_ip,
                {
                    "service": "telnet_jail",
                    "username": username,
                    "port": self.port,
                    "password_present": bool(pw_text),
                    "password_length": len(pw_text),
                    "password_fingerprint": fingerprint(pw_text) if pw_text else "",
                },
            )
            del pw, pw_text
            conn.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n")
            prompt = f"{username}@decoy-host:~$ ".encode()
            conn.sendall(prompt)
            buf = b""
            start = time.time()
            while time.time() - start < self.session_timeout:
                if guardrails.listeners_paused():
                    break
                try:
                    data = conn.recv(256)
                except socket.timeout:
                    break
                if not data:
                    break
                buf += data
                while b"\n" in buf or b"\r" in buf:
                    if b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                    else:
                        line, buf = buf.split(b"\r", 1)
                    cmd = line.decode("utf-8", errors="replace").strip("\r\n")
                    if not cmd:
                        conn.sendall(prompt)
                        continue
                    commands.append(cmd)
                    self._emit(
                        "telnet_jail_command",
                        source_ip,
                        {
                            "service": "telnet_jail",
                            "username": username,
                            "command": cmd[:200],
                            "port": self.port,
                        },
                    )
                    resp = _respond(cmd)
                    if resp == "__EXIT__":
                        conn.sendall(b"logout\r\n")
                        self._emit(
                            "telnet_jail_session_end",
                            source_ip,
                            {
                                "service": "telnet_jail",
                                "username": username,
                                "commands_count": len(commands),
                                "commands": commands[:50],
                            },
                        )
                        return
                    conn.sendall(resp.encode() if isinstance(resp, str) else resp)
                    conn.sendall(prompt)
        except OSError:
            pass
        finally:
            guardrails.session_release("telnet_jail", source_ip)
            if commands:
                self._emit(
                    "telnet_jail_session_end",
                    source_ip,
                    {"service": "telnet_jail", "commands_count": len(commands), "commands": commands[:50]},
                )
            try:
                conn.close()
            except OSError:
                pass

    def start(self) -> bool:
        if self._running:
            return True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_addr, self.port))
        except OSError as e:
            logger.error("Telnet jail bind failed: %s", e)
            return False
        self._sock.listen(8)
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                if guardrails.listeners_paused():
                    time.sleep(0.5)
                    continue
                try:
                    conn, addr = self._sock.accept()
                    threading.Thread(target=self._session, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            try:
                self._sock.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        logger.info("Telnet jail on %s:%d", self.listen_addr, self.port)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> Dict:
        return {"name": "telnet_jail", "port": self.port, "running": self._running}
