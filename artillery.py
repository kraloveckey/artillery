#!/usr/bin/env python3
################################################################################
#
#  Artillery - An active honeypotting tool and threat intelligence feed
#
################################################################################
import time
import sys
import threading
import os
import subprocess
import traceback
import errno
import signal
import argparse
import shutil

# Determine the root directory of the project to allow execution from any path
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import artillery core and metrics modules
try:
    import src.globals
    from src.core import *
    import src.metrics as metrics 
except ImportError as e:
    print(f"[!] Critical Error: Could not import modules from {ROOT_DIR}.\n    Details: {e}")
    sys.exit(1)

# Initialize globals with dynamic path
init_globals(ROOT_DIR)

def sync_os_emulation():
    """Auto-sync TTL, sysctl config and SSL certs when OS_EMULATION changes"""
    target_os = read_config("OS_EMULATION").upper()
    state_file = os.path.join(src.globals.g_apppath, "database", "os_emulation.state")

    prev_os = None
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            prev_os = f.read().strip()

    if prev_os == target_os:
        return

    write_console(f"[OS-EMULATION] Change detected: {prev_os} → {target_os}")

    # TTL + sysctl
    ttl = "128" if target_os == "WINDOWS" else "64"
    try:
        with open("/etc/sysctl.d/99-artillery.conf", "w") as f:
            f.write(f"net.ipv4.ip_default_ttl = {ttl}\n")
        subprocess.call("sysctl --system", shell=True, stdout=subprocess.DEVNULL)
    except Exception as e:
        write_log(f"OS sync: sysctl failed: {e}", 2)

    # SSL cert regeneration
    try:
        from setup import generate_ssl_certs
        generate_ssl_certs(target_os)
    except Exception as e:
        write_log(f"OS sync: SSL cert regen failed: {e}", 2)

    # Save state
    with open(state_file, "w") as f:
        f.write(target_os)

    write_log(f"OS emulation synced to {target_os}")

# Cleanup logic (flush)
def flush_all_rules():
    """Complete removal of all iptables rules and ipset sets created by Artillery."""
    if not is_posix():
        return

    write_console("[*] Cleaning up iptables and ipsets (Flush)...")

    SET_WHITE = "artillery_white"
    SET_BLACK = "artillery_black"

    def _del_rule_loop(cmd_del: str, cmd_check: str = None):
        # delete duplicates until rule no longer exists
        while True:
            subprocess.call(cmd_del, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            if not cmd_check:
                # fallback: try once more then break if deletion likely failed
                break
            ret = subprocess.call(cmd_check, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            if ret != 0:
                break

    # Remove jump to ARTILLERY from INPUT (duplicates safe)
    _del_rule_loop(
        "iptables -D INPUT -j ARTILLERY",
        "iptables -C INPUT -j ARTILLERY"
    )

    # Remove TI rules from INPUT (duplicates safe)
    _del_rule_loop(
        f"iptables -D INPUT -m set --match-set {SET_WHITE} src -j RETURN",
        f"iptables -C INPUT -m set --match-set {SET_WHITE} src -j RETURN"
    )
    _del_rule_loop(
        f"iptables -D INPUT -m set --match-set {SET_BLACK} src -j DROP",
        f"iptables -C INPUT -m set --match-set {SET_BLACK} src -j DROP"
    )

    # Flush and delete the ARTILLERY chain
    subprocess.call("iptables -F ARTILLERY", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.call("iptables -X ARTILLERY", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # Destroy Artillery ipsets (unique list)
    for s in ["artillery_banlist", SET_WHITE, SET_BLACK]:
        subprocess.call(f"ipset flush {s}", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.call(f"ipset destroy {s}", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

# Argument parser (unban logic)
parser = argparse.ArgumentParser(description='Artillery Security Tool')
parser.add_argument("-u", "--unban", help="Unban an IP address (remove from banlist and iptables)", metavar="IP")
args = parser.parse_args()

if args.unban:
    ip_to_unban = args.unban
    if not is_valid_ipv4(ip_to_unban):
        print(f"[!] Invalid IP address: {ip_to_unban}")
        sys.exit(1)
        
    print(f"[*] Removing {ip_to_unban} from banlist...")
    
    try:
        if is_posix():
            # Remove direct DROP and LOG rules for this specific IP
            subprocess.Popen(f"iptables -D ARTILLERY -s {ip_to_unban} -j DROP", shell=True, stderr=subprocess.PIPE).wait()
            log_prefix = read_config("HONEYPOT_BAN_LOG_PREFIX")
            if log_prefix:
                subprocess.Popen(f"iptables -D ARTILLERY -s {ip_to_unban} -j LOG --log-prefix \"{log_prefix}\"", shell=True, stderr=subprocess.PIPE).wait()
            
            # Delete the IP from all relevant ipsets
            subprocess.Popen(f"ipset del artillery_banlist {ip_to_unban}", shell=True, stderr=subprocess.PIPE).wait()
            subprocess.Popen(f"ipset del artillery_black {ip_to_unban}", shell=True, stderr=subprocess.PIPE).wait()
    except Exception as e:
        print(f"[!] Error removing from iptables/ipset: {e}")

    # Remove the IP from the permanent banlist text file
    try:
        if os.path.isfile(src.globals.g_banlist):
            with open(src.globals.g_banlist, "r") as f:
                lines = f.readlines()
            
            with open(src.globals.g_banlist, "w") as f:
                found = False
                for line in lines:
                    if ip_to_unban not in line:
                        f.write(line)
                    else:
                        found = True
              
                if found:
                    print(f"[*] IP {ip_to_unban} removed from {src.globals.g_banlist}")
                else:
                    print(f"[*] IP {ip_to_unban} was not found in the banlist file.")
    except Exception as e:
        print(f"[!] Error updating banlist file: {e}")
        
    metrics.update_ban_count()
    print("[*] Done.")
    sys.exit(0)

# Path to the flag file used to distinguish between a cold start and a restart
RESTART_FLAG = os.path.join("/tmp", "artillery_is_restarting")

# Basic sanity check for the configuration file
if not os.path.isfile(src.globals.g_configfile):
    print(f"[*] Config file not found at {src.globals.g_configfile}")
    if os.path.isfile(os.path.join(ROOT_DIR, "setup.py")):
        print("[*] You might need to run setup.py first.")

# Shutdown handler
def signal_handler(sig, frame):
    """ Gracefully handles SIGTERM and SIGINT to clean up the firewall. """
    try:
        msg = "Artillery shutting down (signal received)..."
        write_console("\n" + msg)
        
        # Clean up all iptables/ipset rules before exiting
        flush_all_rules()
        
        metrics.set_service_status(False)
        prep_email(msg) 
        write_log(msg, 1) 
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def prune_stale_start_messages():
    """ Cleans up the alert log from redundant startup success messages. """
    log_file = os.path.join(src.globals.g_apppath, "logs", "email_alerts.log")
    if not os.path.isfile(log_file): return
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        # Keep only lines that aren't startup notifications
        clean_lines = [l for l in lines if "Artillery has started" not in l and "Artillery has restarted" not in l]
        with open(log_file, "w") as f:
            f.writelines(clean_lines)
    except:
        pass

# --- MAIN SYSTEM INITIALIZATION ---
if is_posix():
    # Verify root privileges before attempting firewall modifications
    if os.geteuid() != 0:
        print("[!] You must be root to run this script!\r\n")
        sys.exit(1)
        
    check_config()
    sync_os_emulation()
    # Perform a full rule flush on start to prevent duplicate entries from prior sessions
    flush_all_rules()

    # Create the internal database structure
    db_dir = os.path.join(src.globals.g_apppath, "database")
    if not os.path.isdir(db_dir): os.makedirs(db_dir)
    db_file = os.path.join(db_dir, "temp.database")
    if not os.path.isfile(db_file):
        with open(db_file, "w") as f: f.write("")

write_console("Artillery has started.\nPress Ctrl+C to exit.\nConsole logging enabled.\n")
check_banlist_path()

if is_posix():
    # Handle OS Emulation (TCP stack modification)
    try:
        desired_os = read_config("OS_EMULATION").upper()
        # Windows servers typically use a TTL of 128, Linux uses 64
        ttl_value = "128" if desired_os == "WINDOWS" else "64"
        subprocess.Popen(f"sysctl -w net.ipv4.ip_default_ttl={ttl_value}", shell=True, stdout=subprocess.DEVNULL).wait()
        write_console(f"OS Emulation: Set TTL to {ttl_value} ({desired_os})")
    except Exception as e:
        write_log(f"Error setting TTL: {e}", 2)

try:
    # Initialize background threads based on configuration
    if is_config_enabled("UPDATE_NOTIFY"):
        write_console("Launching update notify loop.")
        import src.updater as updater
        start_thread(updater.auto_update_loop)
    
    if is_config_enabled("MONITOR") and is_posix():
        # Load File Integrity Monitoring
        from src.monitor import *

    if is_posix():
        time.sleep(1)
        write_console("Creating iptables entries...")
        create_iptables_subset()
        
        if is_config_enabled("ANTI_DOS"):
            write_console("Activating anti DoS.")
            import src.anti_dos

    # Launch Honeypot listeners
    write_console("Launching honeypot.") 
    import src.honeypot

    if is_config_enabled("SSH_BRUTE_MONITOR") and is_posix():
        write_console("Launching Auth Monitor.")
        import src.auth_monitor

    if is_config_enabled("WEB_MONITOR") and is_posix():
        write_console("Launching Web Log monitor.")
        import src.web_monitor

    if is_config_enabled("SYSTEM_HARDENING") and is_posix():
        write_console("Check system hardening.")
        import src.harden

    # Launch Threat Intelligence module using the specific start function
    if is_config_enabled("THREAT_INTELLIGENCE_FEED") and is_posix():
        write_console("Launching Threat Intelligence engine.")
        from src.threats import start_threats
        start_threats()

    # SSH Trap Logic
    if is_config_enabled("SSH_TRAP") and is_posix():
        # Check if port 22 is already in use by a real SSH server
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 22))
        sock.close()

        if result == 0: # Port is busy
            write_log("SSH TRAP ALERT: Cannot start trap on port 22 because it is already in use! Change your real SSH port first.", 2)
            write_console("[!] ERROR: SSH Trap failed to start (Port 22 busy).")
        else:
            write_console("Launching SSH Honeypot (Trap) on port 22.")
            from src.ssh_honeypot import start_ssh_honeypot
            start_thread(start_ssh_honeypot)

    write_console("All set.")

    # Check the flag to see if this was a manual start or an auto-restart
    start_type = "restarted" if os.path.isfile(RESTART_FLAG) else "started"
    if os.path.isfile(RESTART_FLAG):
        try: os.remove(RESTART_FLAG)
        except: pass

    # Log successful activation
    startup_msg = f"Artillery has {start_type} successfully. All monitors are active."
    write_log(startup_msg)
    metrics.set_service_status(True)
    
    # Send startup notification
    prune_stale_start_messages()
    prep_email(startup_msg)
    
    if is_config_enabled("EMAIL_ALERTS") and is_posix():
        write_console("Launching email handler.")
        import src.email_handler
    
    # Main process keep-alive loop
    while True:
        try:
            time.sleep(100)
        except KeyboardInterrupt:
            signal_handler(None, None)

except KeyboardInterrupt:
    signal_handler(None, None)

except Exception as e:
    emsg = traceback.format_exc()
    write_log(f"Artillery CRASHED unexpectedly!\n{emsg}", 2)
    prep_email(f"Artillery CRASHED!\n{emsg}")
    metrics.set_service_status(False)
    sys.exit(1)