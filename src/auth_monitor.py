#!/usr/bin/env python3
#
# src/auth_monitor.py
#

import time
import re
import threading
import os
import sys

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import *
    import src.metrics as metrics
except ImportError:
    pass

def monitor_auth_log():
    """ Main loop to tail system authentication logs """
    if not is_config_enabled("SSH_BRUTE_MONITOR"):
        return

    # Auto-detect log file location based on distribution
    log_file = "/var/log/auth.log"
    if not os.path.isfile(log_file):
        if os.path.isfile("/var/log/secure"): # CentOS/RHEL/Fedora
            log_file = "/var/log/secure"
        else:
            write_log("Auth Monitor: No system auth log found. Monitoring disabled.", 1)
            return

    write_console(f"Auth Monitor active: {log_file}")
    
    try: 
        max_attempts = int(read_config("SSH_BRUTE_ATTEMPTS"))
    except: 
        max_attempts = 4

    attempts = {}
    last_reset = time.time()
    # Simple anti-spam for sudo/su alerts
    last_alert_time = 0 

    try:
        f = open(log_file, "r", encoding='utf-8', errors='ignore')
        # Jump to the end of the file to monitor only new events
        f.seek(0, 2) 
    except Exception as e:
        write_log(f"Auth Monitor critical error: {e}", 2)
        return

    while True:
        # Prevent memory leaks by clearing the attempts dictionary every hour
        if time.time() - last_reset > 3600:
            attempts.clear()
            last_reset = time.time()

        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
            
        # SSH brute force detection
        if "Failed password" in line:
            ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                # Check whitelist and validity before counting
                if is_valid_ipv4(ip) and not is_whitelisted_ip(ip):
                    attempts[ip] = attempts.get(ip, 0) + 1
                    metrics.record_attack("22", "ssh_fail", "tcp")

                    if attempts[ip] >= max_attempts:
                        msg = f"SSH Brute Force Detected from {ip} ({attempts[ip]} attempts)"
                        warn_the_good_guys("SSH Attack Detected", msg)
                        # Call global ban function
                        ban(ip, port=22)
                        metrics.update_ban_count()
                        # Reset counter for this specific IP after ban
                        attempts[ip] = 0

        # sudo abuse (with 5-second rate limit to prevent spam)
        if "sudo" in line and ("authentication failure" in line or "NOT in sudoers" in line):
            if time.time() - last_alert_time > 5:
                msg = f"Security Alert: Suspicious SUDO activity!\nLog: {line.strip()}"
                warn_the_good_guys("Sudo Violation", msg)
                metrics.record_notification("sudo_alert", "sent")
                last_alert_time = time.time()

        # su (switch user) failures
        if "su[" in line and "authentication failure" in line:
            if time.time() - last_alert_time > 5:
                msg = f"Security Alert: Suspicious SU (Switch User) failure!\nLog: {line.strip()}"
                warn_the_good_guys("SU Violation", msg)
                metrics.record_notification("su_alert", "sent")
                last_alert_time = time.time()

# Execution entry point
if is_posix():
    # Only start if on a supported OS
    t = threading.Thread(target=monitor_auth_log)
    t.daemon = True
    t.start()