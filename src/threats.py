#!/usr/bin/env python3
#
# src/threats.py
#
import urllib.request
import time
import threading
import subprocess
import os
import re
import sys

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import *
except ImportError: 
    pass

# IPSet names used globally in the firewall logic
def get_set_names():
    """ Retrieves ipset names from config for Blacklist and Whitelist """
    white = read_config("THREAT_WHITELIST_IPSET_NAME")
    black = read_config("THREAT_BLACKLIST_IPSET_NAME")
    # Fallbacks if config is empty
    if not white: white = "artillery_white"
    if not black: black = "artillery_black"
    return white, black

def check_ipset_installed():
    """ Verifies if the ipset utility is available on the system """
    try:
        subprocess.check_call(["ipset", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        write_log("ERROR: 'ipset' command not found. Please install ipset.", 2)
        return False

def cleanup_ipsets():
    """ Removes all Artillery-related iptables rules and ipset lists """
    write_console("[*] Cleaning up Threat Intelligence IPsets and Rules...")
    set_white, set_black = get_set_names()
    
    while is_posix():
        # Remove rules from INPUT chain
        subprocess.call(f"iptables -D INPUT -m set --match-set {set_white} src -j RETURN", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.call(f"iptables -D INPUT -m set --match-set {set_black} src -j DROP", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # Check if rules still exist (in case of duplicates)
        ret_w = subprocess.call(f"iptables -C INPUT -m set --match-set {set_white} src -j RETURN".split(), stderr=subprocess.DEVNULL)
        ret_b = subprocess.call(f"iptables -C INPUT -m set --match-set {set_black} src -j DROP".split(), stderr=subprocess.DEVNULL)
        if ret_w != 0 and ret_b != 0:
            break
    # Destroy the sets after rules are removed
    execOScmd(f"ipset destroy {set_white}")
    execOScmd(f"ipset destroy {set_black}")

def init_ipsets():
    """ Initializes the required ipsets and attaches them to the INPUT chain """
    if not check_ipset_installed(): return
    set_white, set_black = get_set_names()
    try:
        execOScmd(f"ipset create {set_white} hash:net hashsize 1024 maxelem 200000 -exist")
        execOScmd(f"ipset create {set_black} hash:net hashsize 4096 maxelem 200000 -exist")
        
        # RETURN for Whitelist
        if subprocess.call(f"iptables -C INPUT -m set --match-set {set_white} src -j RETURN".split(), stderr=subprocess.DEVNULL) != 0:
            execOScmd(f"iptables -I INPUT 1 -m set --match-set {set_white} src -j RETURN")

        # DROP for Blacklist
        if subprocess.call(f"iptables -C INPUT -m set --match-set {set_black} src -j DROP".split(), stderr=subprocess.DEVNULL) != 0:
            execOScmd(f"iptables -I INPUT 2 -m set --match-set {set_black} src -j DROP")
            
    except Exception as e:
        write_log(f"Error initializing ipsets: {e}", 2)

def download_ips(urls, github_token):
    """ Fetches IP lists from remote URLs and parses them into a set """
    collected_ips = set()
    if not urls: return collected_ips
    
    for url in urls.split(','):
        url = url.strip()
        if not url: continue
        try:
            req = urllib.request.Request(url)
            # Add GitHub token if provided for private repos or rate limit bypass
            if github_token and "github" in url:
                req.add_header("Authorization", f"token {github_token}")
            req.add_header("User-Agent", "Artillery-Security-Bot")
            
            with urllib.request.urlopen(req, timeout=15) as response:
                data = response.read().decode('utf-8', errors='ignore')
                for line in data.splitlines():
                    line = line.strip()
                    # Skip empty lines or comments
                    if not line or line.startswith(("#", "//")): continue
                    ip_part = line.split()[0]
                    if is_valid_ipv4(ip_part):
                        collected_ips.add(ip_part)
        except Exception as e:
            write_log(f"Failed to fetch {url}: {e}", 2)
    return collected_ips

def update_set(set_name, ip_set):
    """ Performs an atomic SWAP update to refresh ipset content without downtime """
    if not ip_set: return
    
    temp_set = f"{set_name}_temp"
    try:
        # Create a temporary set to load new data
        execOScmd(f"ipset create {temp_set} hash:net hashsize 4096 maxelem 200000 -exist")
        execOScmd(f"ipset flush {temp_set}")
        
        # Use bulk restore for maximum performance
        p = subprocess.Popen(["ipset", "restore"], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
        
        # Prepare bulk commands
        data = "\n".join([f"add {temp_set} {ip} -exist" for ip in ip_set]) + "\n"
        p.communicate(input=data.encode('utf-8'))
        
        # Atomically swap the new set into place and destroy the old one
        execOScmd(f"ipset swap {temp_set} {set_name}")
        execOScmd(f"ipset destroy {temp_set}")
        write_log(f"Updated {set_name} with {len(ip_set)} IPs.")
        
    except Exception as e:
        write_log(f"Error updating set {set_name}: {e}", 2)
        try: execOScmd(f"ipset destroy {temp_set}")
        except: pass

def perform_update():
    """ Orchestrates the download and update process for all feeds """
    if not is_config_enabled("THREAT_INTELLIGENCE_FEED"):
        cleanup_ipsets()
        return False

    init_ipsets()
    # Fetch dynamic names from config
    set_white, set_black = get_set_names()
    github_token = read_config("THREAT_GITHUB_TOKEN")
    
    # Process Whitelists (Local + Remote)
    whitelist_ips = set()
    local_white = read_config("WHITELIST_IP")
    if local_white:
        for ip in local_white.split(','):
            if ip.strip(): whitelist_ips.add(ip.strip())
            
    remote_white = read_config("THREAT_WHITELIST_URLS")
    if remote_white:
        whitelist_ips.update(download_ips(remote_white, github_token))
    
    # Corrected: use local variable set_white
    update_set(set_white, whitelist_ips)
    
    # Process Blacklists (Remote)
    remote_black = read_config("THREAT_BLOCKLIST_URLS")
    if remote_black:
        blacklist_ips = download_ips(remote_black, github_token)
        # Corrected: use local variable set_black
        update_set(set_black, blacklist_ips)
    
    return True

def threat_monitor_loop():
    """ Infinite loop that refreshes threat feeds based on config interval """
    while True:
        # Run update and check if we should continue
        active = perform_update()
        if not active:
            break # Exit thread if feed is disabled in config
            
        try:
            refresh = int(read_config("ARTILLERY_REFRESH"))
            # Enforcement: Minimum 1 minute refresh rate to prevent abuse
            if refresh < 60: refresh = 86400
        except: 
            refresh = 86400
            
        time.sleep(refresh)

def start_threats():
    """ Public method to launch the threat intelligence module as a background thread """
    if is_config_enabled("THREAT_INTELLIGENCE_FEED"):
        t = threading.Thread(target=threat_monitor_loop)
        t.daemon = True
        t.start()