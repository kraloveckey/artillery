#!/usr/bin/env python3
#
# src/harden.py
#
import re
import os
import threading
import subprocess
import sys

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import *
    import src.globals as globals
except ImportError:
    pass

def check_file_perms(path, max_perm_octal):
    """ Checks if file permissions exceed the recommended octal limit """
    if os.path.exists(path):
        try:
            # Extract only the last 3 octal digits
            mode = os.stat(path).st_mode & 0o777
            if mode > max_perm_octal:
                return f"[!] Insecure permissions on {path}: {mode:o} (Recommended: <= {max_perm_octal:o})\n"
        except: pass
    return ""

def check_hardening():
    """ Main hardening audit logic """
    if not is_config_enabled("SYSTEM_HARDENING"): return
    
    # Wait a moment for Artillery startup to finish (avoiding firewall false positives)
    time.sleep(5)
    warning = ""
    
    # SSH configuration audit
    sshd_config = "/etc/ssh/sshd_config"
    if os.path.isfile(sshd_config):
        try:
            with open(sshd_config, "r", errors='ignore') as f:
                data = f.read()
            
            # Use regex to find active (uncommented) insecure settings
            if re.search(r"^\s*PermitRootLogin\s+yes", data, re.MULTILINE | re.IGNORECASE):
                warning += "[!] SSH: Root login is enabled. Recommend: 'no' or 'prohibit-password'.\n"
            
            if re.search(r"^\s*PasswordAuthentication\s+yes", data, re.MULTILINE | re.IGNORECASE):
                warning += "[!] SSH: Password authentication is enabled. Recommend: Use SSH keys.\n"
            
            if re.search(r"^\s*Port\s+22(\s|$)", data, re.MULTILINE) and is_config_enabled("SSH_DEFAULT_PORT_CHECK"):
                warning += "[!] SSH: Running on default port 22. Consider changing for security-by-obscurity.\n"
        except: pass

    # Critical system file permissions
    # /etc/shadow should be strictly root:root 600 or 640
    warning += check_file_perms("/etc/shadow", 0o640)
    warning += check_file_perms("/etc/passwd", 0o644)
    warning += check_file_perms("/etc/ssh/sshd_config", 0o600)
    
    # Audit Artillery's own config permissions (from globals)
    if hasattr(globals, 'g_configfile'):
        warning += check_file_perms(globals.g_configfile, 0o600)

    # Check for null/empty passwords in shadow
    try:
        with open("/etc/shadow", "r", errors='ignore') as f:
            for line in f:
                parts = line.split(":")
                # Second field is the password hash
                if len(parts) > 1 and (parts[1] == "" or parts[1] == "::"):
                    warning += f"[!!!] CRITICAL: User '{parts[0]}' has NO PASSWORD set!\n"
    except: pass

    # Web directory security check
    web_root = "/var/www"
    if os.path.isdir(web_root):
        for root, dirs, files in os.walk(web_root):
            for d in dirs:
                path = os.path.join(root, d)
                try:
                    # Bitwise check for 'Other' Write (002) permission
                    if os.stat(path).st_mode & 0o002: 
                        warning += f"[!] Potential Risk: Web directory is world-writable: {path}\n"
                except: pass

    # Basic firewall integrity check
    try:
        rules = subprocess.check_output("iptables -L -n", shell=True).decode()
        # Check if the policy is wide open and no rules are present
        if "policy ACCEPT" in rules and "ARTILLERY" not in rules:
             warning += "[!] Firewall: No Artillery rules detected in iptables. Check service health.\n"
    except: pass

    # Report findings
    if warning:
        subject = "Security Hardening Audit Report"
        # Mirror to syslog/journald so logs and notifications never diverge
        try:
            for line in warning.strip().splitlines():
                if line.strip():
                    write_log(line.strip(), 2)
        except:
            pass
        # Alert the administrator
        warn_the_good_guys(subject, warning)
    else:
        write_console("System hardening audit completed: No issues found.")

# Execute as a background thread on startup
if is_posix():
    t = threading.Thread(target=check_hardening)
    t.daemon = True
    t.start()