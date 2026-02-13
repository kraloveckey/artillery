#!/usr/bin/env python3
#
# src/honeypot.py
#
import socket
import sys
import re
import subprocess
import time
import socketserver
import os
import random
import datetime
import threading
import traceback
import ssl
import json

# Ensure project root is in path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import *
    import src.metrics as metrics
    import src.globals as globals
except ImportError:
    pass

# Load configurations from core.py
tcpports = read_config("TCPPORTS")
udpports = read_config("UDPPORTS")
honeypot_ban = is_config_enabled("HONEYPOT_BAN")
honeypot_autoaccept = is_config_enabled("HONEYPOT_AUTOACCEPT")
zip_bomb_enable = is_config_enabled("ZIP_BOMB_ENABLE") 
dynamic_fingerprint = is_config_enabled("DYNAMIC_FINGERPRINT")
log4j_detector = is_config_enabled("LOG4J_DETECTOR")

# Detect OS emulation mode
try:
    os_mode = read_config("OS_EMULATION").upper()
    IS_WINDOWS = (os_mode == "WINDOWS")
except:
    IS_WINDOWS = False

SPOOF_PRESETS = {
    "WINDOWS": [
        {
            "name": "Windows Server 2012 R2 / IIS",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 Microsoft ESMTP MAIL Service ready\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_7.7\r\n",
            "http": "Microsoft-IIS/8.5"
        },
        {
            "name": "Windows Server 2016 / IIS",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 Microsoft ESMTP MAIL Service ready\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n",
            "http": "Microsoft-IIS/10.0"
        },
        {
            "name": "Windows Server 2019 / IIS",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 Microsoft ESMTP MAIL Service ready\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_8.6\r\n",
            "http": "Microsoft-IIS/10.0"
        },
        {
            "name": "Windows Server 2022 / IIS",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 mail.corp.local Microsoft ESMTP\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_9.2\r\n",
            "http": "Microsoft-IIS/10.0"
        },
        {
            "name": "Windows / Exchange Frontend",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 EXCH01.corp.local Microsoft ESMTP MAIL Service ready\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_8.9\r\n",
            "http": "Microsoft-IIS/10.0"
        },
        {
            "name": "Windows / MSSQL App Host (IIS)",
            "ftp": b"220 Microsoft FTP Service\r\n",
            "smtp": b"220 smtp.corp.local Microsoft ESMTP\r\n",
            "ssh": b"SSH-2.0-OpenSSH_for_Windows_8.4\r\n",
            "http": "Microsoft-IIS/10.0"
        },
    ],

    "LINUX": [
        {
            "name": "Ubuntu 20.04 / Nginx",
            "ftp": b"220 (vsFTPd 3.0.3)\r\n",
            "smtp": b"220 mail.server.local ESMTP Postfix (Ubuntu)\r\n",
            "ssh": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.10\r\n",
            "http": "nginx/1.18.0 (Ubuntu)"
        },
        {
            "name": "Ubuntu 22.04 / Nginx",
            "ftp": b"220 (vsFTPd 3.0.5)\r\n",
            "smtp": b"220 mail.server.local ESMTP Postfix (Ubuntu)\r\n",
            "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            "http": "nginx/1.18.0 (Ubuntu)"
        },
        {
            "name": "Debian 11 / Apache",
            "ftp": b"220 ProFTPD Server (Debian) [::ffff:127.0.0.1]\r\n",
            "smtp": b"220 mx.internal ESMTP Exim 4.94.2\r\n",
            "ssh": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n",
            "http": "Apache/2.4.54 (Debian)"
        },
        {
            "name": "CentOS 7 / Apache",
            "ftp": b"220 FTP Server Ready\r\n",
            "smtp": b"220 Welcome to CentOS ESMTP Server\r\n",
            "ssh": b"SSH-2.0-OpenSSH_7.4\r\n",
            "http": "Apache/2.4.6 (CentOS)"
        },
        {
            "name": "FreeBSD / FileZilla+Exim",
            "ftp": b"220-FileZilla Server 1.7.2\r\n220 Please enter your name\r\n",
            "smtp": b"220 Exim 4.94.2 FreeBSD #2\r\n",
            "ssh": b"SSH-2.0-OpenSSH_8.4p1 FreeBSD-20201201\r\n",
            "http": "Apache/2.4.46 (FreeBSD)"
        },
        {
            "name": "Synology NAS",
            "ftp": b"220 Synology FTP server ready\r\n",
            "smtp": b"220 Synology-DS ESMTP\r\n",
            "ssh": b"SSH-2.0-OpenSSH_8.2p1-Synology\r\n",
            "http": "nginx"
        },
    ],
}

def get_deceptive_banner(port):
    global SERVICE_PERSONALITY

    if dynamic_fingerprint and _fp_lock_enabled():
        try:
            os_family = "WINDOWS" if IS_WINDOWS else "LINUX"
            st = _load_fp_state() or {}
            cur = st.get(os_family, {})
            exp = int(cur.get("expires_at", 0))
            now = int(time.time())
            if exp and now >= exp:
                SERVICE_PERSONALITY = _select_service_personality()
        except Exception:
            pass

    # When lock is OFF and dynamic fingerprinting is ON:
    # rotate personality based on TTL even without restart.
    if dynamic_fingerprint and not _fp_lock_enabled():
        now = int(time.time())
        ttl = _fp_ttl_seconds()

        # Init state if missing
        if not hasattr(get_deceptive_banner, "_next_rotate"):
            get_deceptive_banner._next_rotate = 0

        if now >= get_deceptive_banner._next_rotate:
            SERVICE_PERSONALITY = _select_service_personality()
            get_deceptive_banner._next_rotate = now + ttl

    personality = SERVICE_PERSONALITY
    if not personality:
        return os.urandom(64)
    if port == 21:
        return personality["ftp"]
    elif port == 25:
        return personality["smtp"]
    elif port == 22:
        return personality["ssh"]
    elif port in (80, 443, 8080):
        srv_hdr = personality["http"]
        return (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {srv_hdr}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    else:
        return os.urandom(random.randint(16, 256))

def _fingerprint_state_path():
    app_path = getattr(globals, "g_apppath", "/var/artillery")
    db_dir = os.path.join(app_path, "database")
    if not os.path.isdir(db_dir):
        try: os.makedirs(db_dir, exist_ok=True)
        except: pass
    return os.path.join(db_dir, "fingerprint_state.json")

def _fp_ttl_seconds():
    try:
        v = int(read_config("FINGERPRINT_TTL"))
        return v if v > 0 else 86400
    except:
        return 86400

def _fp_lock_enabled():
    # Default ON if key missing
    try:
        return read_config("FINGERPRINT_LOCK").lower() in ("on", "yes", "true", "1", "")
    except:
        return True

def _load_fp_state():
    p = _fingerprint_state_path()
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", errors="ignore") as f:
            return json.load(f)
    except:
        return None

def _save_fp_state(state: dict):
    p = _fingerprint_state_path()
    try:
        with open(p, "w") as f:
            json.dump(state, f)
    except:
        pass

def _select_service_personality():
    """Pick or reuse a stable personality for the service within TTL."""
    os_family = "WINDOWS" if IS_WINDOWS else "LINUX"
    presets = SPOOF_PRESETS.get(os_family, [])
    if not presets:
        return None

    now = int(time.time())
    ttl = _fp_ttl_seconds()

    # If locking disabled: behave as old (but still OS-family bound)
    if not _fp_lock_enabled():
        return random.choice(presets) if dynamic_fingerprint else presets[0]

    # Load persisted state
    state = _load_fp_state() or {}
    current = state.get(os_family)

    if current and isinstance(current, dict):
        exp = int(current.get("expires_at", 0))
        idx = current.get("index", None)
        if exp > now and isinstance(idx, int) and 0 <= idx < len(presets):
            return presets[idx]

    idx = random.randrange(len(presets)) if dynamic_fingerprint else 0
    state[os_family] = {
        "index": idx,
        "chosen_at": now,
        "expires_at": now + ttl,
        "name": presets[idx].get("name", "")
    }
    _save_fp_state(state)
    return presets[idx]

SERVICE_PERSONALITY = _select_service_personality()
if SERVICE_PERSONALITY:
    write_console(f"[*] Fingerprint locked for 24h: {SERVICE_PERSONALITY.get('name','(unknown)')}")

class BanPolicy:
    """ Handles attack hit counting and banning thresholds """
    def __init__(self):
        self.hits = {}
        try:
            tol = int(read_config("HONEYPOT_BAN_TOLERANCE"))
            self.tolerance = tol if tol > 0 else 1
        except:
            self.tolerance = 1
            
    def check_and_ban(self, ip, port):
        if not honeypot_ban: return False
        if ip not in self.hits: self.hits[ip] = 0
        self.hits[ip] += 1
        if self.hits[ip] >= self.tolerance:
            ban(ip, port=port)
            metrics.update_ban_count()
            if ip in self.hits: del self.hits[ip]
            return True
        return False

ban_policy = BanPolicy()

class LogAggregator:
    def __init__(self):
        self.buffer = {}
        self.lock = threading.Lock()
        try:
            cfg_freq = read_config("HONEYPOT_AGGREGATE_INTERVAL")
            self.interval = int(cfg_freq) if cfg_freq and int(cfg_freq) > 0 else 60
        except:
            self.interval = 60
        write_console(f"[*] Honeypot Aggregator initialized (Interval: {self.interval}s)")

    def add(self, ip, port, iface, local_ip):
        key = (ip, port, iface, local_ip)
        now = time.time()
        with self.lock:
            if key not in self.buffer:
                self.buffer[key] = [1, now, now]
            else:
                self.buffer[key][0] += 1
                self.buffer[key][2] = now

    def flush_loop(self):
        while True:
            time.sleep(self.interval)
            self.flush()

    def flush(self):
        with self.lock:
            if not self.buffer: return
            sorted_keys = sorted(self.buffer.keys(), key=lambda k: self.buffer[k][1])
            to_process = {k: self.buffer[k] for k in sorted_keys}
            self.buffer.clear()

        for key in sorted_keys:
            data = to_process[key]
            ip, port, iface, local_ip = key
            count, start_ts, end_ts = data
            
            dt_start = datetime.datetime.fromtimestamp(start_ts)
            t_start_fmt = dt_start.strftime('%b %d %H:%M:%S')

            alert_line = format_alert(ip, port, iface, local_ip)
            if count == 1:
                warn_the_good_guys(
                    f"[!] Artillery: Attack from {ip}",
                    alert_line,
                    custom_timestamp=t_start_fmt
                )
            else:
                dt_end = datetime.datetime.fromtimestamp(end_ts)
                t_end_fmt = dt_end.strftime('%H:%M:%S')
                time_range = f"{t_start_fmt} – {t_end_fmt}"

                msg_body = f"detected {count}x attack from {ip} on port {port} ({iface}: {local_ip})"

                warn_the_good_guys(
                    f"[!] Artillery: {count}x Attack from {ip}",
                    msg_body,
                    custom_timestamp=time_range
                )

            ban_policy.check_and_ban(ip, port)

aggregator = LogAggregator()
t_ag = threading.Thread(target=aggregator.flush_loop)
t_ag.daemon = True
t_ag.start()

bomb_cooldown = {} 

class SocketListener(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            ip = self.client_address[0]
            port = self.server.server_address[1]

            if is_valid_ipv4(ip) and is_whitelisted_ip(ip):
                metrics.record_whitelist_hit(ip)
                return

            banner = get_deceptive_banner(port)
            self.request.sendall(banner)

            local_ip = self.request.getsockname()[0]
            iface = get_interface_from_ip(local_ip)

            log_msg = format_alert(ip, port, iface, local_ip)
            write_log(log_msg, 1)

            aggregator.add(ip, port, iface, local_ip)

            if port == 443:
                app_path = getattr(globals, 'g_apppath', '/var/artillery')
                cert_file = os.path.join(app_path, "ssl", "cert.pem")
                key_file = os.path.join(app_path, "ssl", "key.pem")
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(cert_file, key_file)
                        self.request = context.wrap_socket(self.request, server_side=True)
                    except: return
            
            if port in [80, 8080, 443, 8000]:
                try:
                    self.request.settimeout(3)
                    
                    raw = b""
                    max_total = 8192
                    while len(raw) < max_total:
                        chunk = self.request.recv(1024)
                        if not chunk:
                            break
                        raw += chunk

                        if b"\r\n\r\n" in raw or b"\n\n" in raw:
                            break
                    
                    client_data = raw.decode("utf-8", "ignore")

                    cd_lower = client_data.lower()
                    
                    is_log4j = (
                        "${" in client_data or
                        "%24%7b" in cd_lower or
                        ("%7b" in cd_lower and "jndi" in cd_lower) or
                        "jndi:" in cd_lower
                    )

                    if client_data:
                        # Detect Log4j Exploit attempt
                        if log4j_detector and is_log4j:
                            payload = client_data.strip()
                        
                            if len(payload) > 1200:
                                payload = payload[:1200] + "\n[...]"
                        
                            alert_msg = (
                                f"log4j exploit attempt detected from {ip} on port {port}! Payload snippet:\n"
                                f"{payload}"
                            )
                        
                            write_log(alert_msg, 2)
                            warn_the_good_guys("log4j exploit attempt detected", alert_msg, force_buffer=True)
                            metrics.record_notification("log4j", "detected")
                        
                            ban(ip)
                            return

                        # Standard Zip Bomb / Robots.txt logic
                        if zip_bomb_enable:
                            if "GET /robots.txt" in client_data:
                                robots = "User-agent: *\r\nDisallow: /backup.zip\r\nDisallow: /env.zip\r\nDisallow: /database.zip\r\n"
                                self.request.send(f"HTTP/1.1 200 OK\r\nContent-Length: {len(robots)}\r\n\r\n{robots}".encode())
                                return 

                            trap_file = None
                            if "GET /backup.zip" in client_data: trap_file = "backup.zip"
                            elif "GET /env.zip" in client_data:  trap_file = "env.zip"
                            elif "GET /database.zip" in client_data: trap_file = "database.zip"

                            if trap_file:
                                app_path = getattr(globals, 'g_apppath', '/var/artillery')
                                fpath = os.path.join(app_path, "honeyfiles", trap_file)
                                if os.path.exists(fpath):
                                    now = time.time()
                            
                                    cd_key = (ip, trap_file, port)
                            
                                    bomb_msg = f"detected download zip-bomb ({trap_file}) from {ip} on port {port}"
                            
                                    write_log(bomb_msg, 1)
                            
                                    # Throttle notifications only (not logging)
                                    if cd_key not in bomb_cooldown or (now - bomb_cooldown[cd_key] > 10):
                                        bomb_cooldown[cd_key] = now
                                        warn_the_good_guys("zip-bomb download detected", bomb_msg, force_buffer=True)
                            
                                    self.request.settimeout(60)
                                    header = (
                                        "HTTP/1.1 200 OK\r\n"
                                        "Content-Type: application/zip\r\n"
                                        f"Content-Length: {os.path.getsize(fpath)}\r\n"
                                        "Connection: close\r\n"
                                        "\r\n"
                                    )
                                    self.request.send(header.encode())
                            
                                    with open(fpath, "rb") as f:
                                        while True:
                                            chunk = f.read(65536)
                                            if not chunk:
                                                break
                                            self.request.sendall(chunk)
                            
                                    ban(ip)
                                    return
                except: pass

            # Fallback to Aggregator and Deceptive Banners
            metrics.record_attack(port, iface, "tcp")
            
            #try:
            #    self.request.sendall(banner)
            #except Exception as e:
            #    write_log(f"banner sendall failed on port {port}: {e}", 2)
            #    return
            
            try:
                self.request.settimeout(1.5)
                _ = self.request.recv(64)
            except Exception:
                pass
        except Exception as e:
            try:
                write_log(f"SocketListener error on port {port}: {e}\n{traceback.format_exc()}", 2)
            except:
                pass

        finally:
            try: self.request.close()
            except: pass

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            ip = self.client_address[0]
            port = self.server.server_address[1]
            if is_valid_ipv4(ip) and is_whitelisted_ip(ip): return
            local_ip = self.request[1].getsockname()[0]
            iface = get_interface_from_ip(local_ip)

            write_log(f"detected UDP attack from {ip} on port {port} ({iface})", 1)

            aggregator.add(ip, port, iface, local_ip)
            metrics.record_attack(port, iface, "udp")
            self.request[1].sendto(os.urandom(int(random.randint(5, 64))), self.client_address)
        except: pass

def open_sesame(porttype, port):
    if honeypot_autoaccept and is_posix():
        try:
            execOScmd(f"iptables -D ARTILLERY -p {porttype} --dport {port} -j ACCEPT -w 3")
            execOScmd(f"iptables -A ARTILLERY -p {porttype} --dport {port} -j ACCEPT -w 3")
        except: pass

def listentcp_server(tcpport, bind_interface):
    try:
        host = bind_interface if bind_interface else ''
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer((host, int(tcpport)), SocketListener)
        open_sesame("tcp", tcpport)
        server.serve_forever()
    except Exception as e:
        write_log(f"Error binding TCP {tcpport}: {e}", 2)

def listenudp_server(udpport, bind_interface):
    try:
        host = bind_interface if bind_interface else ''
        socketserver.UDPServer.allow_reuse_address = True
        server = socketserver.ThreadingUDPServer((host, int(udpport)), UDPHandler)
        open_sesame("udp", udpport)
        server.serve_forever()
    except Exception as e:
        write_log(f"Error binding UDP {udpport}: {e}", 2)

def main_honeypot(tcpports, udpports):
    bind_param = read_config("BIND_INTERFACE")
    bind_ips = [ip.strip() for ip in bind_param.split(",") if ip.strip()] if bind_param else [""]
    if tcpports:
        for tport in tcpports.split(","):
            if tport.strip():
                for ip in bind_ips:
                    start_thread(listentcp_server, (tport.strip(), ip))
    if udpports:
        for uport in udpports.split(","):
            if uport.strip():
                for ip in bind_ips:
                    start_thread(listenudp_server, (uport.strip(), ip))

main_honeypot(tcpports, udpports)