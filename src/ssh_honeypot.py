#!/usr/bin/env python3
#
# src/ssh_honeypot.py
#
import socket
import threading
import paramiko
import os
import time
import sys
import logging
from src.core import get_interface_from_ip, grab_time

logging.getLogger("paramiko").handlers.clear()
logging.getLogger("paramiko").propagate = False
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

logging.getLogger("paramiko.transport").handlers.clear()
logging.getLogger("paramiko.transport").propagate = False
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import write_log, write_console, warn_the_good_guys, ban, is_whitelisted_ip, read_config
    import src.metrics as metrics
    import src.globals as globals
except ImportError:
    pass

HOST_KEY_PATH = os.path.join(getattr(globals, 'g_apppath', '/var/artillery'), 'ssl/ssh_host_key')

SSH_PORT = 22

def _get_ssh_banner_from_personality() -> str:
    """
    Pull SSH banner from src.honeypot SERVICE_PERSONALITY if available.
    Returns realistic OpenSSH banner string without CRLF.
    """
    fallback = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    try:
        # Import lazily to avoid circular import at module load
        import src.honeypot as hp
        p = getattr(hp, "SERVICE_PERSONALITY", None)
        if not p:
            return fallback
        b = p.get("ssh")
        if not b:
            return fallback
        if isinstance(b, bytes):
            s = b.decode("utf-8", errors="ignore")
        else:
            s = str(b)
        # Strip CRLF and whitespace
        s = s.replace("\r", "").replace("\n", "").strip()
        if not s.startswith("SSH-"):
            return fallback
        return s
    except Exception:
        return fallback

def _ssh_ctx(client_sock):
    """Return (local_ip, iface) for log formatting."""
    try:
        local_ip = client_sock.getsockname()[0]
    except Exception:
        local_ip = "0.0.0.0"
    try:
        iface = get_interface_from_ip(local_ip)
    except Exception:
        iface = "unknown"
    return local_ip, iface

def _cmd_reply(cmd: str) -> str:
    c = cmd.strip()

    if c in ("ls", "ls -l", "ls -la", "ls -al"):
        if c == "ls":
            return "bin  boot  dev  etc  home  lib  root  tmp  usr  var"
        return (
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 bin\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 boot\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 dev\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 etc\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 home\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 lib\n"
            "drwx------  2 root root 4096 Jan 01 00:00 root\n"
            "drwxrwxrwt  2 root root 4096 Jan 01 00:00 tmp\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 usr\n"
            "drwxr-xr-x  2 root root 4096 Jan 01 00:00 var"
        )

    if c in ("whoami",):
        return "root"

    if c in ("id", "id -a"):
        return "uid=0(root) gid=0(root) groups=0(root)"

    if c == "id -u":
        return "0"

    if c in ("pwd",):
        return "/root"

    if c in ("uname", "uname -a"):
        return "Linux ubuntu-srv 5.15.0-generic #1 SMP x86_64 GNU/Linux"

    if c in ("cat /etc/passwd", "head /etc/passwd"):
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
        )

    if c in ("ps", "ps aux", "ps -ef"):
        return (
            "root         1  0.0  0.1  16800  1200 ?        Ss   00:00   0:00 /sbin/init\n"
            "root       512  0.0  0.3  42000  3200 ?        Ss   00:00   0:00 /usr/sbin/sshd -D\n"
            "root       777  0.0  0.1  20000  1100 pts/0    Ss   00:00   0:00 -bash"
        )

    if c in ("ip a", "ip addr", "ifconfig"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "    inet 10.10.7.27  netmask 255.255.255.0  broadcast 10.10.7.255\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "    inet 127.0.0.1  netmask 255.0.0.0"
        )

    if c in ("df -h",):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        40G  3.2G   35G   9% /\n"
            "tmpfs           1.9G     0  1.9G   0% /dev/shm"
        )

    if c in ("free -m",):
        return (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:           4096         312        3200          12         584        3600\n"
            "Swap:             0           0           0"
        )

    if c.startswith("cd "):
        return ""

    return f"-bash: {c.split()[0]}: command not found"

def _ssh_log_connect(ip, local_ip, iface):
    return f"detected attack on the SSH honeypot from {ip} on port {SSH_PORT} ({iface}: {local_ip})"

def _ssh_log_login(ip, user, passwd, local_ip, iface):
    return f"detected login attempt (Username: {user}, Password: {passwd}) on the SSH honeypot from {ip} on port {SSH_PORT} ({iface}: {local_ip})"

def generate_host_key():
    if not os.path.exists(HOST_KEY_PATH):
        ssl_dir = os.path.dirname(HOST_KEY_PATH)
        if not os.path.isdir(ssl_dir): os.makedirs(ssl_dir)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, local_ip, iface):
        self.client_ip = client_ip
        self.local_ip = local_ip
        self.iface = iface
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        msg = _ssh_log_login(self.client_ip, username, password, self.local_ip, self.iface)
        write_log(msg, 1)
        warn_the_good_guys("Artillery Alert", msg, custom_timestamp=grab_time(), force_buffer=True)

        log_path = os.path.join(getattr(globals, 'g_apppath', '/var/artillery'), "logs/ssh_auth.log")
        with open(log_path, "a") as f:
            f.write(f"{time.ctime()} | {self.client_ip} | {username} | {password}\n")
        
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session': return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def get_allowed_auths(self, username):
        return 'password'

def handle_ssh_session(client, addr):
    client_ip = addr[0]

    if is_whitelisted_ip(client_ip):
        client.close()
        return

    local_ip, iface = _ssh_ctx(client)
    msg = _ssh_log_connect(client_ip, local_ip, iface)

    write_log(msg, 1)
    warn_the_good_guys("Artillery Alert", msg, custom_timestamp=grab_time(), force_buffer=True)

    try:
        client.setblocking(False)
        try:
            peek = client.recv(4, socket.MSG_PEEK)
            # If client already sent something and it's not SSH-, drop it
            if peek and not peek.startswith(b"SSH-"):
                client.close()
                return
        except BlockingIOError:
            pass
    finally:
        try:
            client.setblocking(True)
        except Exception:
            pass

    client.settimeout(5)
    try:
        transport = paramiko.Transport(client)
        transport.local_version = _get_ssh_banner_from_personality()
        transport.banner_timeout = 5

        generate_host_key()
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        transport.add_server_key(host_key)

        local_ip, iface = _ssh_ctx(client)
        server = FakeSSHServer(client_ip, local_ip, iface)

        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError):
            transport.close()
            return

        chan = transport.accept(20)
        if chan is None:
            transport.close()
            return

        server.event.wait(10)
        if not server.event.is_set():
            transport.close()
            return

        prompt = "root@ubuntu-srv:~# "
        chan.send(f"\r\nWelcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n{prompt}")

        command_buffer = ""

        while True:
            try:
                chunk = chan.recv(1024)
            except Exception:
                break
            if not chunk:
                break

            text = chunk.decode("utf-8", errors="ignore")
            # Normalize CRLF -> LF
            text = text.replace("\r", "")

            for ch in text:
                if ch == "\n":
                    cmd = command_buffer.strip()
                    if cmd == "exit":
                        transport.close()
                        return

                    if cmd:
                        local_ip, iface = _ssh_ctx(client)
                        log_entry = f"detected command on the SSH Honeypot from {client_ip} on port {SSH_PORT} ({iface}: {local_ip}): {cmd}"
                        write_log(log_entry, 1)
                        warn_the_good_guys("Artillery Alert", log_entry, custom_timestamp=grab_time(), force_buffer=True)

                        cmd_log = os.path.join(getattr(globals, 'g_apppath', '/var/artillery'), "logs/ssh_commands.log")
                        with open(cmd_log, "a") as f:
                            f.write(f"{time.ctime()} | {client_ip} | {cmd}\n")

                        reply = _cmd_reply(cmd)
                        if reply:
                            chan.send("\r\n" + reply + "\r\n")

                    chan.send(f"\r\n{prompt}")
                    command_buffer = ""

                elif ch == "\x7f":  # Backspace
                    if command_buffer:
                        command_buffer = command_buffer[:-1]
                        chan.send("\b \b")
                else:
                    command_buffer += ch
                    chan.send(ch)

    except Exception:
        pass
    finally:
        client.close()

def start_ssh_honeypot():
    port = 22 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', port))
        except socket.error as e:
            if e.errno == 98:
                write_log("SSH Honeypot: CRITICAL - Port 22 is already occupied. Trap disabled.", 2)
                return
            raise e

        sock.listen(100)
        write_console(f"[*] SSH Honeypot (Trap) active on port {port}")

        while True:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_ssh_session, args=(client, addr))
            t.daemon = True
            t.start()
    except Exception as e:
        write_log(f"SSH Honeypot Error: {e}", 2)

if __name__ == "__main__":
    start_ssh_honeypot()