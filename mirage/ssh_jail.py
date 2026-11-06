"""Credential-harvesting SSH jail — Feature 06 (v2.5: secrets redacted at source).

Accepts any username/password once, drops attacker into FakeShell, logs commands.
Never stores plaintext passwords. Guardrails at accept time.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import guardrails
from .redaction import fingerprint

logger = logging.getLogger("mirage.ssh_jail")

try:
    import paramiko
    from paramiko import ServerInterface, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED
    PARAMIKO_AVAILABLE = True
except ImportError:
    paramiko = None  # type: ignore
    ServerInterface = object  # type: ignore
    AUTH_SUCCESSFUL = 0
    AUTH_FAILED = 1
    OPEN_SUCCEEDED = 0
    PARAMIKO_AVAILABLE = False

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
backup:x:1001:1001:Backup Service:/home/backup:/bin/bash
admin:x:1002:1002:Admin:/home/admin:/bin/bash
"""

FAKE_HOSTS = """127.0.0.1 localhost
10.0.0.15 db-prod
10.0.0.20 fileserver
10.0.0.25 nas-backup
10.0.0.30 backup-01
"""

FAKE_HOME_LS = """total 28
drwxr-xr-x  5 ubuntu ubuntu 4096 Sep 12 09:14 .
drwxr-xr-x  3 root   root   4096 Jan  1  2024 ..
-rw-------  1 ubuntu ubuntu  220 Sep 12 09:14 .bash_history
-rw-r--r--  1 ubuntu ubuntu 3771 Jan  1  2024 .bashrc
drwx------  2 ubuntu ubuntu 4096 Sep 10 11:02 .ssh
-rw-r--r--  1 ubuntu ubuntu   18 Sep  1 08:00 notes.txt
drwxr-xr-x  2 ubuntu ubuntu 4096 Aug 20 14:33 Documents
"""

FAKE_SSH_DIR = """total 16
drwx------ 2 ubuntu ubuntu 4096 Sep 10 11:02 .
drwxr-xr-x 5 ubuntu ubuntu 4096 Sep 12 09:14 ..
-rw------- 1 ubuntu ubuntu  411 Sep 10 11:02 id_rsa
-rw-r--r-- 1 ubuntu ubuntu   99 Sep 10 11:02 id_rsa.pub
-rw-r--r-- 1 ubuntu ubuntu  222 Sep 10 11:02 known_hosts
"""

FAKE_MOTD = """Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com

Last login: from internal
"""


class FakeShell:
    def __init__(self, username: str = "ubuntu", source_ip: str = "", on_command: Optional[Callable] = None, session_timeout: int = 300):
        self.username = username or "ubuntu"
        self.source_ip = source_ip
        self.on_command = on_command
        self.session_timeout = session_timeout
        self.cwd = f"/home/{self.username}"
        self.hostname = "prod-app-01"
        self.started = time.time()
        self.commands: List[Dict[str, Any]] = []
        self._closed = False

    def prompt(self) -> str:
        short = self.cwd.replace(f"/home/{self.username}", "~")
        return f"{self.username}@{self.hostname}:{short}$ "

    def expired(self) -> bool:
        return (time.time() - self.started) >= self.session_timeout

    def _log(self, command: str, output: str):
        self.commands.append({"ts": datetime.utcnow().isoformat() + "Z", "command": command, "cwd": self.cwd, "output_preview": output[:200]})
        if self.on_command:
            try:
                self.on_command(event_type="ssh_jail_command", source_ip=self.source_ip, details={"service": "ssh_jail", "username": self.username, "command": command, "cwd": self.cwd, "session_age_sec": int(time.time() - self.started)})
            except Exception as e:
                logger.warning("on_command failed: %s", e)

    def execute(self, line: str) -> Tuple[str, bool]:
        if self._closed:
            return ("", True)
        if self.expired():
            self._closed = True
            return ("\r\n*** Session timed out (policy limit). Connection closed.\r\n", True)
        line = (line or "").strip()
        if not line:
            return ("", False)
        if line.startswith("\x00") or line.startswith("\x1b"):
            return ("", False)
        cmd = line.split()[0] if line.split() else line
        args = line.split()[1:] if len(line.split()) > 1 else []
        output = self._dispatch(cmd, args, line)
        self._log(line, output)
        if cmd in ("exit", "logout", "quit"):
            self._closed = True
            return (output + "logout\r\n", True)
        return (output, False)

    def _dispatch(self, cmd: str, args: List[str], full: str) -> str:
        if cmd in ("exit", "logout", "quit"):
            return ""
        if cmd == "whoami":
            return self.username + "\r\n"
        if cmd == "id":
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\r\n"
        if cmd == "pwd":
            return self.cwd + "\r\n"
        if cmd == "uname":
            return "Linux prod-app-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n" if "-a" in args else "Linux\r\n"
        if cmd == "hostname":
            return self.hostname + "\r\n"
        if cmd in ("ls", "dir"):
            return self._ls(args)
        if cmd == "cd":
            return self._cd(args)
        if cmd == "cat":
            return self._cat(args)
        if cmd == "echo":
            return (" ".join(args) + "\r\n") if args else "\r\n"
        if cmd in ("env", "printenv"):
            return f"USER={self.username}\r\nHOME=/home/{self.username}\r\nSHELL=/bin/bash\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nPWD={self.cwd}\r\n"
        if cmd == "history":
            lines = [f" {i}  {c['command']}" for i, c in enumerate(self.commands[-20:], 1)]
            return "\r\n".join(lines) + ("\r\n" if lines else "")
        if cmd in ("ps", "top"):
            return f"  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:00 bash\r\n {1000 + len(self.commands)} pts/0    00:00:00 {cmd}\r\n"
        if cmd in ("netstat", "ss"):
            return "Active Internet connections (servers)\r\ntcp 0 0 0.0.0.0:22 LISTEN\r\ntcp 0 0 0.0.0.0:80 LISTEN\r\n"
        if cmd in ("ifconfig", "ip"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.42  netmask 255.255.255.0\r\n"
        if cmd == "find":
            return "/home/ubuntu/Documents\r\n/home/ubuntu/notes.txt\r\n/var/www/html\r\n"
        if cmd in ("wget", "curl"):
            return f"{cmd}: (fake) connection timed out\r\n"
        if cmd == "sudo":
            return f"[sudo] password for {self.username}: \r\nSorry, try again.\r\n"
        if cmd in ("help", "?"):
            return "Available: ls cd pwd cat whoami id uname env ps history exit\r\n"
        return f"{cmd}: command not found\r\n"

    def _ls(self, args: List[str]) -> str:
        target = args[-1] if args and not args[-1].startswith("-") else self.cwd
        if target in (".", self.cwd, f"/home/{self.username}", "~"):
            return FAKE_HOME_LS
        if ".ssh" in target:
            return FAKE_SSH_DIR
        if target in ("/", "/home"):
            return f"total 12\r\ndrwxr-xr-x  3 root root 4096 Jan  1  2024 .\r\ndrwxr-xr-x 18 root root 4096 Jan  1  2024 ..\r\ndrwxr-xr-x  5 {self.username} {self.username} 4096 Sep 12 09:14 {self.username}\r\n"
        if "Documents" in target:
            return "total 8\r\n-rw-r--r-- 1 ubuntu ubuntu  128 Aug 20 14:33 todo.txt\r\n"
        return f"ls: cannot access '{target}': No such file or directory\r\n"

    def _cd(self, args: List[str]) -> str:
        if not args or args[0] in ("~", f"/home/{self.username}"):
            self.cwd = f"/home/{self.username}"
            return ""
        target = args[0]
        if target == "..":
            if self.cwd != "/":
                self.cwd = "/".join(self.cwd.rstrip("/").split("/")[:-1]) or "/"
            return ""
        if target == "/":
            self.cwd = "/"
            return ""
        if target.startswith("/"):
            if target in ("/home", f"/home/{self.username}", f"/home/{self.username}/.ssh", f"/home/{self.username}/Documents", "/tmp", "/var", "/etc"):
                self.cwd = target
                return ""
            return f"bash: cd: {target}: No such file or directory\r\n"
        if target in (".ssh", "Documents") and self.cwd == f"/home/{self.username}":
            self.cwd = self.cwd.rstrip("/") + "/" + target
            return ""
        return f"bash: cd: {target}: No such file or directory\r\n"

    def _cat(self, args: List[str]) -> str:
        if not args:
            return ""
        path = args[0]
        if path.endswith("passwd") or path == "/etc/passwd":
            return FAKE_PASSWD.replace("\n", "\r\n")
        if path.endswith("shadow") or path == "/etc/shadow":
            return "cat: /etc/shadow: Permission denied\r\n"
        if path.endswith("hosts") or path == "/etc/hosts":
            return FAKE_HOSTS.replace("\n", "\r\n")
        if path.endswith("notes.txt"):
            return "TODO: rotate backup credentials\r\ncheck nas-backup share\r\n"
        if path.endswith("todo.txt"):
            return "- renew SSL certs\r\n- audit firewall rules\r\n"
        if path.endswith("id_rsa") or path.endswith("id_rsa.pub"):
            return "cat: Permission denied\r\n"
        if path.endswith(".bashrc"):
            return "# .bashrc\r\nexport PATH=$PATH:$HOME/bin\r\n"
        return f"cat: {path}: No such file or directory\r\n"


class JailServerInterface(ServerInterface):
    def __init__(self, source_ip: str, on_event: Optional[Callable], session_timeout: int):
        super().__init__()
        self.source_ip = source_ip
        self.on_event = on_event
        self.session_timeout = session_timeout
        self.username = ""
        self.password = ""
        self.auth_method = ""

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.password = ""  # never retain plaintext
        self.auth_method = "password"
        logger.info("SSH jail auth: user=%s from=%s (password redacted)", username, self.source_ip)
        if self.on_event:
            self.on_event(
                event_type="ssh_jail_login",
                source_ip=self.source_ip,
                details={
                    "service": "ssh_jail",
                    "username": username,
                    "password_present": bool(password),
                    "password_length": len(password or ""),
                    "password_fingerprint": fingerprint(password) if password else "",
                    "auth_method": "password",
                },
            )
        return AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key) -> int:
        self.username = username
        self.auth_method = "publickey"
        if self.on_event:
            self.on_event(
                event_type="ssh_jail_login",
                source_ip=self.source_ip,
                details={"service": "ssh_jail", "username": username, "auth_method": "publickey", "key_type": key.get_name() if key else "unknown"},
            )
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED if PARAMIKO_AVAILABLE else 1

    def check_channel_shell_request(self, channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"


def _run_shell_session(channel, username: str, source_ip: str, on_event: Optional[Callable], session_timeout: int):
    shell = FakeShell(username=username or "ubuntu", source_ip=source_ip, on_command=on_event, session_timeout=session_timeout)
    try:
        channel.send(FAKE_MOTD.replace("\n", "\r\n"))
        channel.send(shell.prompt())
        buf = ""
        while not shell._closed and not shell.expired():
            if not channel.recv_ready():
                if shell.expired():
                    channel.send("\r\n*** Session timed out (policy limit). Connection closed.\r\n")
                    break
                time.sleep(0.05)
                continue
            data = channel.recv(1024)
            if not data:
                break
            text = data.decode("utf-8", errors="replace")
            for ch in text:
                if ch in ("\r", "\n"):
                    channel.send("\r\n")
                    out, should_exit = shell.execute(buf)
                    if out:
                        channel.send(out)
                    buf = ""
                    if should_exit:
                        break
                    channel.send(shell.prompt())
                elif ch == "\x03":
                    channel.send("^C\r\n")
                    buf = ""
                    channel.send(shell.prompt())
                elif ch == "\x04":
                    break
                elif ch in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        channel.send("\b \b")
                elif ord(ch) >= 32:
                    buf += ch
                    channel.send(ch)
            else:
                continue
            break
    except Exception as e:
        logger.debug("Shell session ended: %s", e)
    finally:
        if on_event:
            on_event(event_type="ssh_jail_session_end", source_ip=source_ip, details={"service": "ssh_jail", "username": username, "commands_count": len(shell.commands), "commands": [c["command"] for c in shell.commands], "duration_sec": int(time.time() - shell.started)})
        try:
            channel.close()
        except Exception:
            pass


def _handle_client(client: socket.socket, addr, host_key, on_event: Optional[Callable], session_timeout: int):
    source_ip = addr[0]
    allowed, reason = guardrails.accept_allowed("ssh_jail", source_ip)
    if not allowed:
        try:
            client.close()
        except OSError:
            pass
        return
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = JailServerInterface(source_ip, on_event, session_timeout)
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return
        channel.settimeout(30)
        time.sleep(0.3)
        username = server.username or "ubuntu"
        _run_shell_session(channel, username, source_ip, on_event, session_timeout)
    except Exception as e:
        logger.info("SSH jail session from %s ended: %s", source_ip, e)
        if on_event:
            on_event(event_type="ssh_jail_connect", source_ip=source_ip, details={"service": "ssh_jail", "error": str(e)[:120]})
    finally:
        guardrails.session_release("ssh_jail", source_ip)
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


class SSHJail:
    def __init__(self, port: int = 2222, listen_addr: str = "127.0.0.1", on_event: Optional[Callable] = None, session_timeout: int = 300):
        self.port = port
        self.listen_addr = listen_addr
        self.on_event = on_event
        self.session_timeout = session_timeout
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._host_key = None

    def _ensure_host_key(self):
        if PARAMIKO_AVAILABLE:
            self._host_key = paramiko.RSAKey.generate(2048)

    def start(self) -> bool:
        if not PARAMIKO_AVAILABLE:
            logger.error("paramiko not installed — SSH jail cannot start")
            return False
        if self._running:
            return True
        self._ensure_host_key()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_addr, self.port))
        except OSError as e:
            logger.error("Cannot bind SSH jail on %s:%d: %s", self.listen_addr, self.port, e)
            return False
        self._sock.listen(10)
        self._sock.settimeout(1.0)
        self._running = True

        def serve():
            while self._running:
                if guardrails.listeners_paused():
                    time.sleep(0.5)
                    continue
                try:
                    client, addr = self._sock.accept()
                    if self.on_event:
                        self.on_event(event_type="ssh_jail_connect", source_ip=addr[0], details={"service": "ssh_jail", "port": self.port})
                    threading.Thread(target=_handle_client, args=(client, addr, self._host_key, self.on_event, self.session_timeout), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
            try:
                self._sock.close()
            except OSError:
                pass

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        logger.info("SSH jail on %s:%d", self.listen_addr, self.port)
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> Dict[str, Any]:
        return {"name": "ssh_jail", "port": self.port, "running": self._running, "paramiko": PARAMIKO_AVAILABLE, "session_timeout": self.session_timeout}
