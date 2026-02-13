#!/usr/bin/env python3
#
# src/core.py
#
import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import urllib.request
import os
import re
import subprocess
import socket
import sys
import time
import shutil
import datetime
import logging
import logging.handlers
import threading

LOG_MESSAGE_ALERT = "Artillery detected attack from %ip% on port %port% (%iface%: %localip%)"
LOG_MESSAGE_BAN = "Artillery blocked %ip% on port %port%"

# Helper to verify if the operating system is POSIX (Linux/Unix)
def is_posix(): return os.name == "posix"

# Import global variables and metrics modules
try: import src.globals as globals
except: from . import globals
import src.metrics as metrics

def init_globals(manual_root=None):
    """ Initializes the application paths and global file locations """
    if manual_root: globals.g_apppath = manual_root
    else: globals.g_apppath = "/var/artillery"

    globals.g_appfile = os.path.join(globals.g_apppath, "artillery.py")
    globals.g_configfile = os.path.join(globals.g_apppath, "config")
    globals.g_banlist = os.path.join(globals.g_apppath, "banlist.txt")
    globals.g_localbanlist = os.path.join(globals.g_apppath, "localbanlist.txt")
    globals.g_sslpath = os.path.join(globals.g_apppath, "ssl")

def gethostname(): return socket.gethostname()
def grab_time(): return datetime.datetime.now().strftime('%b %d %H:%M:%S')

def start_thread(target_func, args=()):
    """ Utility to launch a function in a background daemon thread. """
    t = threading.Thread(target=target_func, args=args)
    t.daemon = True
    t.start()

def get_interface_from_ip(ip_addr):
    """ Detects the specific network interface name for a given local IP """
    if ip_addr in ("127.0.0.1", "localhost", "0.0.0.0"): return "lo"
    try:
        cmd = f"ip -o addr | grep {ip_addr}"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        if output: return output.split()[1]
    except: pass
    return "unknown"

def get_system_stats():
    """ 
    Collects detailed system metrics: Hostname, IPs, Time, 
    Uptime, Active Honeypot Ports (TCP/UDP), and Resource Usage.
    """
    try:
        if is_posix():
            # Host and Network Information
            host = socket.gethostname()
            # Fetch all IPv4 addresses excluding loopback
            ips_cmd = "ip -4 addr show | grep inet | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1"
            ips = subprocess.check_output(ips_cmd, shell=True).decode().strip().replace('\n', ', ')
            
            # Time formatting: e.g., Wed Jan 28 05:20:05 PM EET 2026
            current_time = datetime.datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')
            
            # Disk and Memory usage
            disk_header = "Filesystem      Size  Used Avail Use% Mounted on"
            disk_data = subprocess.check_output("df -h / | grep -v Filesystem", shell=True).decode().strip()
            mem_data = subprocess.check_output("free -m", shell=True).decode().strip()
            
            # Check active listening ports used by Artillery (python3)
            try:
                # Get TCP ports
                tcp_cmd = "ss -lntp | grep python3 | awk '{print $4}' | cut -d: -f2 | sort -n -u"
                tcp_ports = subprocess.check_output(tcp_cmd, shell=True).decode().strip().replace('\n', ', ')
                # Get UDP ports
                udp_cmd = "ss -lup | grep python3 | awk '{print $4}' | cut -d: -f2 | sort -n -u"
                udp_ports = subprocess.check_output(udp_cmd, shell=True).decode().strip().replace('\n', ', ')
                
                if not tcp_ports: tcp_ports = "None"
                if not udp_ports: udp_ports = "None"
            except:
                tcp_ports = udp_ports = "Error retrieving ports"

            # System Uptime
            uptime = subprocess.check_output("uptime -p", shell=True).decode().strip()

            stats = (
                f"Host: {host}\n"
                f"Addr: {ips}\n"
                f"Time: {current_time}\n"
                f"Uptime: {uptime}\n\n"
                f"Active TCP Honeypots: {tcp_ports}\n"
                f"Active UDP Honeypots: {udp_ports}\n\n"
                f"Disk usage:\n{disk_header}\n{disk_data}\n\n"
                f"{mem_data}"
            )
            return stats
            
    except Exception as e:
        return f"Stats unavailable: {str(e)}"
    return "Stats unavailable"

def check_config():
    """ Ensures the configuration file exists and contains all required parameters """
    configdefaults = {}
    configdefaults["OS_EMULATION"] = ["LINUX", "OS TO EMULATE (WINDOWS/LINUX)"]
    configdefaults["SERVER_NAME"] = ["", "DISPLAY NAME FOR SERVER"]
    configdefaults["CONSOLE_LOGGING"] = ["ON", "PRINT LOGS TO CONSOLE (ON/OFF)"]
    configdefaults["UPDATE_NOTIFY"] = ["OFF", "AUTO NOTIFY UPDATE: ON=Enable, OFF=Disable"]
    configdefaults["METRICS"] = ["ON", "SEND PROMETHEUS METRICS (ON/OFF)"]
    configdefaults["BIND_INTERFACE"] = ["", "BIND IP(s) (EMPTY=ALL)"]
    configdefaults["TCPPORTS"] = ["21,22,23,25,80,110,111,135,139,389,443,445,631,636,993,995,1433,1723,2049,2082,2083,2086,2087,2222,2483,2484,3128,3306,3389,4444,5000,5432,5601,5900,5985,6379,7001,7002,8000,8008,8080,8081,8443,8888,9000,9200,9300,10000,11211,27017", "OPEN TCP PORTS"]
    configdefaults["UDPPORTS"] = ["69,161,3478,3702,5060,5061", "OPEN UDP PORTS"]
    configdefaults["HONEYPOT_AGGREGATE_INTERVAL"] = ["60", "HONEYPOT EVENT AGGREGATION WINDOW (SEC)"]
    configdefaults["DYNAMIC_FINGERPRINT"] = ["ON", "DYNAMICALLY CHANGE SERVER BANNERS (ON/OFF)"]
    configdefaults["FINGERPRINT_TTL"] = ["86400", "FINGERPRINT PROFILE TTL (SEC)"]
    configdefaults["FINGERPRINT_LOCK"] = ["ON", "LOCK PROFILE PER SERVICE (ON/OFF)"]
    configdefaults["HONEYPOT_BAN"] = ["OFF", "BAN ATTACKERS ON HONEYPOT (ON/OFF)"]
    configdefaults["HONEYPOT_BAN_TOLERANCE"] = ["1", "ATTEMPTS BEFORE BAN (1=INSTANT)"]
    configdefaults["HONEYPOT_AUTOACCEPT"] = ["ON", "OPEN PORTS AUTOMATICALLY (ON/OFF)"]
    configdefaults["ZIP_BOMB_ENABLE"] = ["ON", "ENABLE ZIP BOMB TRAPS (ON/OFF)"]
    configdefaults["LOG4J_DETECTOR"] = ["OFF", "DETECT LOG4J (CVE-2021-44228) EXPLOIT ATTEMPTS (ON/OFF)"]
    configdefaults["HONEYPOT_BAN_CLASSC"] = ["OFF", "BAN ENTIRE CLASS C SUBNET (ON/OFF)"]
    configdefaults["HONEYPOT_BAN_LOG_PREFIX"] = ["ARTILLERY_BLOCK: ", "IPTABLES LOG PREFIX"]
    configdefaults["WHITELIST_IP"] = ["127.0.0.1,localhost", "IP WHITELIST (COMMA SEPARATED)"]
    configdefaults["GW_ALERTS"] = ["OFF", "GOOGLE CHAT ALERTS (ON/OFF)"]
    configdefaults["GW_WEBHOOK"] = ["", "GOOGLE CHAT WEBHOOK URL"]
    configdefaults["LOGO_IMAGE_URL"] = ["", "LOGO URL (EMPTY = NINJA EMOJI)"]
    configdefaults["EMAIL_ALERTS"] = ["OFF", "EMAIL ALERTS (ON/OFF)"]
    configdefaults["SMTP_USERNAME"] = ["", "SMTP USER"]
    configdefaults["SMTP_PASSWORD"] = ["", "SMTP PASS"]
    configdefaults["SMTP_FROM"] = ["Artillery@localhost", "FROM EMAIL"]
    configdefaults["SMTP_FROM_NAME"] = ["Artillery Honeypot", "FROM NAME (DISPLAY)"]
    configdefaults["ALERT_USER_EMAIL"] = ["user@localhost", "TO EMAIL"]
    configdefaults["SMTP_ADDRESS"] = ["smtp.gmail.com", "SMTP HOST"]
    configdefaults["SMTP_PORT"] = ["587", "SMTP PORT"]
    configdefaults["EMAIL_TIMER"] = ["ON", "BUFFER EMAILS TO PREVENT SPAM (ON/OFF)"]
    configdefaults["EMAIL_FREQUENCY"] = ["600", "BUFFER FREQUENCY IN SECONDS"]
    configdefaults["TELEGRAM_ALERTS"] = ["OFF", "TELEGRAM ALERTS (ON/OFF)"]
    configdefaults["TELEGRAM_TOKEN"] = ["", "TELEGRAM BOT TOKEN"]
    configdefaults["TELEGRAM_CHAT_ID"] = ["", "TELEGRAM CHAT ID"]
    configdefaults["SSH_BRUTE_MONITOR"] = ["ON", "MONITOR AUTH LOGS (ON/OFF)"]
    configdefaults["SSH_BRUTE_ATTEMPTS"] = ["3", "MAX ATTEMPTS BEFORE BAN"]
    configdefaults["SSH_TRAP"] = ["OFF", "ENABLE INTERACTIVE SSH TRAP – REQUIRES PORT 22 TO BE FREE (ON/OFF)"]
    configdefaults["WEB_MONITOR"] = ["OFF", "MONITOR WEB LOGS (ON/OFF)"]
    configdefaults["WEB_ACCESS_LOG"] = ["/var/log/nginx/*access.log", "ACCESS LOG PATH"]
    configdefaults["WEB_ERROR_LOG"] = ["/var/log/nginx/*error.log", "ERROR LOG PATH"]
    configdefaults["MONITOR"] = ["OFF", "FILE INTEGRITY MONITOR (ON/OFF)"]
    configdefaults["MONITOR_FOLDERS"] = ["\"/var/www\",\"/opt/\"", "FOLDERS TO CHECK"]
    configdefaults["MONITOR_FREQUENCY"] = ["60", "CHECK FREQUENCY (SEC)"]
    configdefaults["EXCLUDE"] = ["", "EXCLUDE PATHS"]
    configdefaults["THREAT_INTELLIGENCE_FEED"] = ["OFF", "USE EXTERNAL BLOCKLISTS (ON/OFF)"]
    configdefaults["THREAT_BLOCKLIST_URLS"] = ["", "BLOCKLIST URLS (RAW TEXT)"]
    configdefaults["THREAT_WHITELIST_URLS"] = ["", "WHITELIST URLS (RAW TEXT)"]
    configdefaults["THREAT_GITHUB_TOKEN"] = ["", "GITHUB TOKEN (OPTIONAL)"]
    configdefaults["THREAT_BLACKLIST_IPSET_NAME"] = ["artillery_black", "IPSET NAME FOR BLACKLIST"]
    configdefaults["THREAT_WHITELIST_IPSET_NAME"] = ["artillery_white", "IPSET NAME FOR WHITELIST"]
    configdefaults["ARTILLERY_REFRESH"] = ["86400", "FEED REFRESH RATE (SEC)"]
    configdefaults["SYSTEM_HARDENING"] = ["ON", "STARTUP SECURITY CHECK (ON/OFF)"]
    configdefaults["SSH_DEFAULT_PORT_CHECK"] = ["ON", "WARN ON SSH PORT 22 (ON/OFF)"]
    configdefaults["ROOT_CHECK"] = ["ON", "WARN ON ROOT LOGIN (ON/OFF)"]
    configdefaults["SYSLOG_TYPE"] = ["FILE", "SYSLOG TYPE (LOCAL/FILE/REMOTE)"]
    configdefaults["SYSLOG_REMOTE_HOST"] = ["192.168.0.1", "REMOTE SYSLOG IP"]
    configdefaults["SYSLOG_REMOTE_PORT"] = ["514", "REMOTE SYSLOG PORT"]

    keyorder = list(configdefaults.keys())
    configpath = globals.g_configfile
    if os.path.exists(configpath):
        write_console(f"Checking existing config file '{configpath}'")
        for configkey in configdefaults:
            if config_exists(configkey):
                currentcomment = configdefaults[configkey][1]
                currentvalue = read_config(configkey)
                configdefaults[configkey] = [currentvalue, currentcomment]
            else:
                write_console(f"    Adding new config key '{configkey}'")
    
    create_config(globals.g_configfile, configdefaults, keyorder)

def create_config(configpath, configdefaults, keyorder):
    """ Writes the dictionary of configurations to the config file on disk """
    with open(configpath, "w") as configfile:
        configfile.write("#############################################################################################\n# Artillery Configuration\n#############################################################################################\n")
        for configkey in keyorder:
            configfile.write(f"\n# {configdefaults[configkey][1]}\n{configkey}=\"{configdefaults[configkey][0]}\"\n")

def config_exists(param):
    """ Checks if a specific parameter exists in the config file """
    try:
        with open(globals.g_configfile, "r") as f:
            for line in f:
                if not line.startswith("#") and re.search(r"^" + param + r"\s*=", line): return True
    except: return False
    return False

def read_config(param):
    """ Reads and returns the value of a specific parameter from the config file """
    try:
        with open(globals.g_configfile, "r") as f:
            for line in f:
                if not line.startswith("#") and re.search(r"^" + param + r"\s*=", line):
                    return line.split("=", 1)[1].strip().replace('"', "")
    except: return ""
    return ""

def is_config_enabled(param): return read_config(param).lower() in ("on", "yes")

def format_alert(ip, port, iface, local_ip):
    return (LOG_MESSAGE_ALERT
            .replace("%ip%", str(ip))
            .replace("%port%", str(port))
            .replace("%iface%", str(iface))
            .replace("%localip%", str(local_ip)))

def format_ban(ip, port):
    return (LOG_MESSAGE_BAN
            .replace("%ip%", str(ip))
            .replace("%port%", str(port)))

def send_google_chat(subject, message_text):
    """ Sends a notification to a Google Chat Webhook """
    if not is_config_enabled("GW_ALERTS"):
        return

    webhook = read_config("GW_WEBHOOK")
    if not webhook:
        return

    logo_url = read_config("LOGO_IMAGE_URL")
    headers = {'Content-Type': 'application/json; charset=UTF-8'}

    header_payload = {"title": subject, "subtitle": "Follow the white rabbit... 🐇"}
    if logo_url:
        header_payload["imageType"] = "CIRCLE"
        header_payload["imageUrl"] = logo_url

    def _gc_escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Before building widgets list (payload size protection)
    raw_text = str(message_text).strip()
    max_bytes = 50 * 1024  # 50KB safety cap
    raw_bytes = len(raw_text.encode("utf-8", errors="ignore"))

    if raw_bytes > max_bytes:
        # Fallback to MASSIVE warning (small, always delivered)
        widgets = [{
            "decoratedText": {
                "startIcon": {"materialIcon": {"name": "warning"}},
                "text": _gc_escape(
                    "⚠️  MASSIVE ATTACK DETECTED  ⚠️\n\n"
                    "The alert buffer exceeded the safety limit (50KB).\n"
                    f"Current Buffer Size: {round(raw_bytes/1024, 2)} KB\n"
                    "Directly review logs at: /var/artillery/logs/email_alerts.old"
                ),
                "wrapText": True
            }
        }]
    else:
        widgets = []
        for line in raw_text.split('\n'):
            if not line:
                continue
            icon = "info"
            if "attack" in line.lower():
                icon = "warning"
            widgets.append({
                "decoratedText": {
                    "startIcon": {"materialIcon": {"name": icon}},
                    "text": _gc_escape(line),
                    "wrapText": True
                }
            })

    card_data = {
        "cardsV2": [{
            "cardId": "artillery",
            "card": {
                "header": header_payload,
                "sections": [{"widgets": widgets}]
            }
        }]
    }

    try:
        req = urllib.request.Request(webhook, json.dumps(card_data).encode('utf-8'), headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            pass
    except Exception as e:
        write_log(f"Chat Alert Error: {e}", 2)

def send_mail(subject, text_body, html_body=None):
    """ Sends an email alert via the configured SMTP server """
    if not is_config_enabled("EMAIL_ALERTS"): return
    try:
        msg = MIMEMultipart('alternative')
        from_email = read_config("SMTP_FROM")
        from_name = read_config("SMTP_FROM_NAME")
        sender = f"{from_name} <{from_email}>" if from_name else from_email
        
        msg['From'] = sender
        msg['To'] = read_config("ALERT_USER_EMAIL")
        msg['Subject'] = subject
        msg.attach(MIMEText(text_body, 'plain'))
        if html_body: msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(read_config("SMTP_ADDRESS"), int(read_config("SMTP_PORT")), timeout=10)
        server.ehlo()
        server.starttls()
        server.login(read_config("SMTP_USERNAME"), read_config("SMTP_PASSWORD"))
        server.sendmail(read_config("SMTP_FROM"), read_config("ALERT_USER_EMAIL"), msg.as_string())
        server.quit()
    except Exception as e:
        write_log(f"Email Error: {e}", 2)

def send_telegram(subject, message_text):
    """ Sends a notification via Telegram Bot API with HTML escaping and length control """
    if is_config_enabled("TELEGRAM_ALERTS"):
        token = read_config("TELEGRAM_TOKEN")
        chat_id = read_config("TELEGRAM_CHAT_ID")
        if not token or not chat_id: return

        # Escape HTML special characters to prevent "400 Bad Request"
        safe_subject = subject.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        safe_message = message_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

        # Limit message length (Telegram max is 4096)
        if len(safe_message) > 3800:
            safe_message = safe_message[:3800] + "\n\n[... Message Truncated due to length ...]"

        full_message = (
            f"<b>{safe_subject}</b>\n"
            f"━━━━━━━━━━━━━━\n"
            f"<i>Follow the white rabbit... 🐇</i>\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"<code>{safe_message}</code>"
        )
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": full_message,
            "parse_mode": "HTML"
        }
        
        try:
            headers = {'Content-Type': 'application/json'}
            req = urllib.request.Request(url, json.dumps(payload).encode('utf-8'), headers)
            with urllib.request.urlopen(req, timeout=10) as response: pass
        except Exception as e:
            write_log(f"Telegram Alert Error: {e}", 2)

def execOScmd(cmd, logmsg=""):
    """ Executes a system shell command and returns the output as a list of lines """
    if logmsg: write_log(f"execOSCmd: {logmsg}")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    return out.decode('utf-8', errors='ignore').splitlines() if out else []

def write_console(alert):
    """ Prints an alert message to the console if logging is enabled """
    if is_config_enabled("CONSOLE_LOGGING"):
        print(f"{grab_time()}: {alert}")

def write_log(alert, alerttype=0, custom_timestamp=None):
    """ Writes an alert based on SYSLOG_TYPE configuration """
    timestamp = custom_timestamp if custom_timestamp else grab_time()
    hostname = gethostname()

    # Avoid "Artillery Artillery ..."
    if isinstance(alert, str) and alert.startswith("Artillery "):
        alert = alert[len("Artillery "):]

    log_line = f"{timestamp} {hostname}: Artillery {alert}"

    syslog_type = read_config("SYSLOG_TYPE").upper()

    # LOCAL uses stdout/journald. Print once and exit to avoid duplicates.
    if is_posix() and syslog_type == "LOCAL":
        try:
            print(log_line, flush=True)
        except Exception:
            pass
        return

    # Console Logging (only if NOT LOCAL)
    if is_config_enabled("CONSOLE_LOGGING"):
        print(log_line)

    # Storage Logic
    if syslog_type == "FILE":
        log_dir = os.path.join(globals.g_apppath, "logs")
        if not os.path.isdir(log_dir):
            try:
                os.makedirs(log_dir)
            except:
                pass
        try:
            with open(os.path.join(log_dir, "alerts.log"), "a") as f:
                f.write(log_line + "\n")
        except:
            pass

    elif is_posix() and syslog_type == "REMOTE":
        try:
            remote_host = read_config("SYSLOG_REMOTE_HOST")
            remote_port = int(read_config("SYSLOG_REMOTE_PORT"))

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            syslog_msg = f"<14>{log_line}"
            sock.sendto(syslog_msg.encode("utf-8"), (remote_host, remote_port))
            sock.close()
        except Exception:
            pass

def warn_the_good_guys(subject, alert, ip=None, port=None, iface=None, local_ip=None, custom_timestamp=None, force_buffer=False):
    """ Orchestrates all configured alerts """
    ts = custom_timestamp if custom_timestamp else grab_time()
    if ip and port and not alert:
        alert = format_alert(ip, port, iface, local_ip)
        alert = re.sub(r'^Artillery\s+', '', alert)

    formatted_alert = f"{ts} {alert}"

    if is_config_enabled("EMAIL_ALERTS") or is_config_enabled("GW_ALERTS") or is_config_enabled("TELEGRAM_ALERTS"):
        if force_buffer or is_config_enabled("EMAIL_TIMER"):
            prep_email(formatted_alert)
        else:
            hostname = gethostname()
            full_subject = f"{hostname} | {subject}"
            send_mail(full_subject, formatted_alert)
            send_google_chat(full_subject, formatted_alert)
            send_telegram(full_subject, formatted_alert)

def prep_email(alert):
    """ Buffers alert messages into a temporary log file for later aggregated email sending """
    log_dir = os.path.join(globals.g_apppath, "logs")
    if not os.path.isdir(log_dir): os.makedirs(log_dir)
    log_file = os.path.join(log_dir, "email_alerts.log")

    hostname = gethostname()
    match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+(?:\s+–\s+\d+:\d+:\d+)?)\s+(.*)', str(alert), re.DOTALL)
    if match:
        timestamp_part = match.group(1)
        msg_part = match.group(2)
    else:
        timestamp_part = grab_time()
        msg_part = str(alert)

    lines = [l.rstrip("\r") for l in msg_part.splitlines()]
    with open(log_file, "a") as f:
        first = True
        for line in lines:
            line = line.rstrip()
            if first:
                if line.startswith("Artillery "):
                    line = line[len("Artillery "):]
                if line.strip():
                    f.write(f"{timestamp_part} {hostname}: Artillery {line}\n")
                    first = False
                continue
    
            if line.strip():
                f.write(f"  {line}\n")

def is_valid_ipv4(ip):
    """ Validates if a string is a proper IPv4 address or CIDR notation """
    if "/" in ip:
        try:
            parts = ip.split('/')
            socket.inet_aton(parts[0])
            mask = int(parts[1])
            return 0 <= mask <= 32
        except: return False
    try: socket.inet_aton(ip); return True
    except: return False

def is_whitelisted_ip(ip):
    """ Checks if an IP is present in the WHITELIST_IP configuration """
    ipaddr = str(ip).split('/')[0]
    whitelist = read_config("WHITELIST_IP").split(',')
    for site in whitelist:
        if site.strip() == ipaddr: return True
    return False

def check_banlist_path(): 
    """ Ensures the banlist.txt file exists and is accessible """
    if not os.path.isfile(globals.g_banlist):
        open(globals.g_banlist, 'w').close()
    return globals.g_banlist

def is_already_banned(ip):
    """ Checks if an IP address is already recorded in the global banlist file """
    if not os.path.isfile(globals.g_banlist): return False
    try:
        with open(globals.g_banlist, 'r') as f:
            if ip in f.read(): return True
    except: return False
    return False

def convert_to_classc(param):
    """ Converts a single IP address to its Class C subnet representation (/24) """
    p = param.split('.')
    if len(p) == 4: return f"{p[0]}.{p[1]}.{p[2]}.0/24"
    return param

def create_iptables_subset():
    """ 
    Initializes the Artillery iptables chain and links it to the INPUT chain.
    Ensures existing jump rules are cleared to prevent duplication.
    """
    if not is_posix(): return

    # Get the blacklist name from config with the new key
    ipset_name = read_config("THREAT_BLACKLIST_IPSET_NAME")
    if not ipset_name: ipset_name = "artillery_black"

    subprocess.call("iptables -D INPUT -j ARTILLERY", shell=True, stderr=subprocess.DEVNULL)
    subprocess.call("iptables -N ARTILLERY 2>/dev/null", shell=True)
    subprocess.call("iptables -F ARTILLERY", shell=True)

    if is_config_enabled("HONEYPOT_BAN"):
        # Create the ipset using the name from config
        subprocess.call(f"ipset create {ipset_name} hash:net -exist", shell=True)
        # Link the Artillery chain to the specific ipset
        if subprocess.call(f"iptables -C ARTILLERY -m set --match-set {ipset_name} src -j DROP", shell=True, stderr=subprocess.DEVNULL) != 0:
            subprocess.call(f"iptables -A ARTILLERY -m set --match-set {ipset_name} src -j DROP", shell=True)

    subprocess.call("iptables -I INPUT -j ARTILLERY", shell=True)

def ban(ip, port=None):
    ip = ip.strip()
    if is_whitelisted_ip(ip):
        return

    if is_config_enabled("HONEYPOT_BAN"):
        ipset_name = read_config("THREAT_BLACKLIST_IPSET_NAME") or "artillery_black"

        if is_posix():
            if is_config_enabled("HONEYPOT_BAN_CLASSC") and "/" not in ip:
                ip = convert_to_classc(ip)
            subprocess.call(f"ipset add {ipset_name} {ip} -exist", shell=True, stderr=subprocess.DEVNULL)

        if "/" not in ip and not is_already_banned(ip):
            with open(globals.g_banlist, "a") as f:
                f.write(ip + "\n")

            p = port if port is not None else "unknown"
            ban_msg = format_ban(ip, p)

            write_log(ban_msg, 1)
            warn_the_good_guys("Artillery Alert", ban_msg, force_buffer=True)

def sort_banlist(): pass 

def update():
    """
    UPDATE_NOTIFY:
      - OFF: do nothing
      - ON : notify-only (no git pull, no restart)
    Checks immediately when called; schedule is handled by updater thread.
    """
    mode = read_config("UPDATE_NOTIFY").upper().strip()
    if mode != "ON":
        return

    git_dir = os.path.join(globals.g_apppath, ".git")
    if not os.path.isdir(git_dir):
        # Repo without .git -> cannot compare
        return

    try:
        # Fetch remote
        subprocess.call(f"cd {globals.g_apppath} && git fetch", shell=True)

        local = subprocess.check_output(
            f"cd {globals.g_apppath} && git rev-parse HEAD", shell=True
        ).strip()

        # Support both origin/master and origin/main
        try:
            remote = subprocess.check_output(
                f"cd {globals.g_apppath} && git rev-parse origin/master", shell=True
            ).strip()
        except Exception:
            remote = subprocess.check_output(
                f"cd {globals.g_apppath} && git rev-parse origin/main", shell=True
            ).strip()

        if local != remote:
            # Notify-only
            warn_the_good_guys(
                "Artillery Alert",
                "Artillery detected updates.\n"
                "Check repository:\n"
                "https://github.com/kraloveckey/artillery",
                force_buffer=True
            )
            write_console("[!] Update available (UPDATE_NOTIFY=ON).")
    except:
        pass