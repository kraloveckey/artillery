#!/usr/bin/env python3
#
# Installer for Artillery
#
import time
import subprocess
import os
import shutil
import sys
import argparse
import random
import select

# Add current path to find src modules during setup
sys.path.append(os.getcwd())

# Attempt to import core for initial configuration generation
try: 
    from src.core import check_config, init_globals, is_config_enabled
    import src.globals
    # The standard deployment path is /var/artillery
    src.globals.g_apppath = "/var/artillery"
except: 
    pass

def is_posix(): return os.name == "posix"

# Argument Parser for non-interactive automation
interactive = True 
parser = argparse.ArgumentParser()
parser.add_argument("-y", action='store_true', help="Non-interactive mode")
args = parser.parse_args()
if args.y: interactive = False

# Artillery requires root privileges for iptables and socket binding
if is_posix() and os.geteuid() != 0:
    print("[!] You must be root to run this script!")
    sys.exit(1)

print('''
===========================================================
   ARTILLERY SECURITY SUITE - INSTALLER MANAGER
===========================================================
''')

def ask_yes_no(question, default="y"):
    """ Helper for interactive user prompts with input buffer clearing """
    if not interactive: return True

    # Flush the input buffer to prevent "ghost" Enter presses from previous commands
    if is_posix():
        while select.select([sys.stdin], [], [], 0)[0]:
            sys.stdin.read(1)

    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    prompt = " [Y/n] " if default == "y" else " [y/N] "
    
    while True:
        sys.stdout.write(question + prompt)
        sys.stdout.flush()
        choice = input().lower().strip()
        if choice == "" and default is not None:
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'.\n")

# Dependencies check
def check_and_install_dependencies():
    """ Installs required system binaries and Python libraries """
    # Update package lists to ensure latest versions are found
    print("[*] Updating package lists (apt-get update)...")
    subprocess.call("apt-get update -y", shell=True)

    to_install = ["zip", "ipset", "openssl"]
    
    if is_posix():
        # Added pre-compiled python3-paramiko to prevent pip build hangs
        to_install.extend(["python3-dev", "build-essential", "libssl-dev", "libffi-dev", "python3-paramiko"])

    print(f"[*] Installing system dependencies: {', '.join(to_install)}...")
    packages = " ".join(to_install)
    # Visible install (no -qq) to monitor progress and handle potential apt locks
    subprocess.call(f"apt-get install -y {packages}", shell=True)

    # Double-check for paramiko availability in Python environment
    try:
        import paramiko
        print("[+] Paramiko dependency found.")
    except ImportError:
        print("[*] Paramiko not found via apt, attempting pip install fallback...")
        subprocess.call([sys.executable, "-m", "pip", "install", "paramiko"], stdout=subprocess.DEVNULL)

# Prometheus exporter setup
def setup_prometheus_exporter():
    """ Configures prometheus-node-exporter to read Artillery metrics via textfile collector """
    if is_config_enabled("METRICS"):
        print("[*] Metrics are ENABLED. Configuring prometheus-node-exporter...")
        
        if shutil.which("prometheus-node-exporter") is None:
            print("[*] Installing prometheus-node-exporter...")
            subprocess.call("apt-get install -y prometheus-node-exporter", shell=True)

        config_path = "/etc/default/prometheus-node-exporter"
        metrics_dir = "/var/artillery/metrics"
        
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir)

        metric_args = f'--collector.textfile.directory="{metrics_dir}"'
        
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    content = f.read()
                
                if "collector.textfile.directory" not in content:
                    if 'ARGS="' in content:
                        new_content = content.replace('ARGS="', f'ARGS="{metric_args} ')
                    else:
                        new_content = content + f'\nARGS="{metric_args}"\n'
                    
                    with open(config_path, "w") as f:
                        f.write(new_content)
                    
                    print(f"[+] Updated {config_path} with Artillery metrics path.")
                    subprocess.call("systemctl restart prometheus-node-exporter", shell=True)
            else:
                print("[!] Warning: Could not find node-exporter config. Please set collector path manually.")
        except Exception as e:
            print(f"[!] Error configuring Prometheus exporter: {e}")

# Stealth SSL cert generator
def generate_ssl_certs(target_os="LINUX"):
    """ Generates a self-signed certificate with a deceptive Subject Name """
    ssl_dir = "/var/artillery/ssl"
    if not os.path.isdir(ssl_dir): os.makedirs(ssl_dir)

    cert_path = os.path.join(ssl_dir, "cert.pem")
    key_path = os.path.join(ssl_dir, "key.pem")
    
    if os.path.exists(cert_path): os.remove(cert_path)
    if os.path.exists(key_path): os.remove(key_path)

    print(f"[*] Generating Stealth SSL Certificate in {ssl_dir}...")
    
    if target_os == "WINDOWS":
        masks = [
            "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=IIS Development/CN=WIN-IIS-SRV01",
            "/C=US/ST=New York/L=New York/O=Enterprise Corp/OU=Exchange/CN=mail.corp.local",
            "/C=GB/ST=London/L=London/O=Internal/OU=Domain Controllers/CN=DC01-AUTH",
        ]
    else:
        masks = [
            "/C=US/ST=California/L=San Jose/O=Cisco Systems/OU=Security/CN=vpn-concentrator",
            "/C=TW/ST=Taipei/L=Taipei/O=Synology Inc./CN=DiskStation-Manager",
            "/C=DE/ST=Berlin/L=Berlin/O=DevOps Team/OU=CI-CD/CN=gitlab.internal",
        ]
    
    subj = random.choice(masks)
    print(f"    -> Applying Contextual Mask: {subj.split('CN=')[1]}")

    cmd = (
        f"openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 "
        f"-keyout {key_path} -out {cert_path} "
        f"-subj '{subj}' "
        f">/dev/null 2>&1"
    )
    subprocess.call(cmd, shell=True)
    os.chmod(key_path, 0o600)

# Honeyfiles (zip-bombs) generator
def generate_honeyfiles():
    """ Creates bait files designed to crash aggressive scanners """
    honey_dir = "/var/artillery/honeyfiles"
    if not os.path.isdir(honey_dir): os.makedirs(honey_dir)

    traps = ["backup.zip", "env.zip", "database.zip"]
    missing = any(not os.path.exists(f"{honey_dir}/{t}") for t in traps)
            
    if not missing:
        print("[*] Honeyfiles already exist. Skipping generation.")
        return

    print("[*] Generating Honeyfiles (ZIP Bombs)...")
    try:
        payload_path = "/tmp/artillery_payload"
        # Create a 1GB null-byte file as base for zip bombs
        subprocess.call(f"dd if=/dev/zero of={payload_path} bs=1M count=1024 status=none", shell=True)
        
        for trap in traps:
            bait_name = f"/tmp/{trap}.tmp"
            os.rename(payload_path, bait_name) if os.path.exists(payload_path) else shutil.copy(bait_name, bait_name)
            subprocess.call(f"zip -j -9 {honey_dir}/{trap} {bait_name}", shell=True, stdout=subprocess.DEVNULL)
            if trap != traps[-1]:
                subprocess.call(f"dd if=/dev/zero of={payload_path} bs=1M count=1024 status=none", shell=True)

        print("[+] Honeyfiles generated successfully.")
    except Exception as e:
        print(f"[!] Error generating honeyfiles: {e}")

# System tuning
def apply_tuning(target_os="LINUX"):
    """ Modifies kernel parameters for better stealth and TTL spoofing """
    print(f"[*] Applying System Tuning (Target: {target_os})...")
    ttl_val = "128" if target_os == "WINDOWS" else "64"
    sysctl_content = f"net.ipv4.ip_default_ttl = {ttl_val}\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.ip_forward=1\nnet.ipv4.tcp_syncookies=1\n"
    try:
        with open("/etc/sysctl.d/99-artillery.conf", "w") as f: f.write(sysctl_content)
        subprocess.call("sysctl --system", shell=True, stdout=subprocess.DEVNULL)
    except: pass

# Uninstall
def uninstall_artillery():
    """ Clean removal of Artillery suite """
    print("\n[*] Uninstalling Artillery...")
    try:
        subprocess.call("systemctl stop artillery", shell=True, stderr=subprocess.DEVNULL)
        subprocess.call("systemctl disable artillery", shell=True, stderr=subprocess.DEVNULL)
    except: pass

    files = ["/etc/systemd/system/artillery.service", "/etc/init.d/artillery", 
             "/etc/logrotate.d/artillery", "/etc/sysctl.d/99-artillery.conf", 
             "/etc/security/limits.d/artillery.conf"]
    for f in files:
        if os.path.exists(f): os.remove(f)

    subprocess.call("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL)
    if os.path.exists("/var/artillery"): shutil.rmtree("/var/artillery")
    print("[*] Uninstallation complete.\n")

# Main execution
ACTION = None
is_installed = os.path.isdir("/var/artillery")

if interactive:
    if is_installed:
        print("[!] Artillery is ALREADY installed.\n    1) Update / Reconfigure\n    2) Uninstall\n    3) Exit")
        while True:
            c = input("\nSelect [1]: ").strip()
            if c=="" or c=="1": ACTION="UPDATE"; break
            elif c=="2": ACTION="UNINSTALL"; break
            elif c=="3": sys.exit(0)
    else:
        print("[?] Artillery is NOT installed.\n    1) Install Artillery\n    2) Exit")
        while True:
            c = input("\nSelect [1]: ").strip()
            if c=="" or c=="1": ACTION="INSTALL"; break
            elif c=="2": sys.exit(0)
else:
    ACTION = "UPDATE" if is_installed else "INSTALL"

if ACTION == "UNINSTALL":
    uninstall_artillery()
    sys.exit(0)

if ACTION == "INSTALL" or ACTION == "UPDATE":
    target_os = "LINUX"
    if interactive:
        print("\n--- OS EMULATION SETUP ---")
        print("1) Linux   (Default)\n2) Windows")
        while True:
            c = input("Select [1]: ").strip()
            if c == "" or c == "1": target_os = "LINUX"; break
            elif c == "2": target_os = "WINDOWS"; break

    print(f"\n[*] Starting {ACTION} process...")
    
    dirs = ["/var/artillery", "/var/artillery/database", "/var/artillery/src",
            "/var/artillery/logs", "/var/artillery/metrics", "/var/artillery/ssl",
            "/var/artillery/honeyfiles"]
    for d in dirs:
        if not os.path.isdir(d): os.makedirs(d)

    print("[*] Copying program files...")
    subprocess.Popen("cp -rf * /var/artillery/", shell=True).wait()
    
    if os.path.isdir(".git"):
        print("[*] Copying .git repository...")
        dest_git = "/var/artillery/.git"
        if os.path.exists(dest_git): shutil.rmtree(dest_git)
        try: shutil.copytree(".git", dest_git)
        except: pass

    check_and_install_dependencies()
    generate_ssl_certs(target_os)

    # Logrotate configuration
    with open("/etc/logrotate.d/artillery", "w") as f:
        f.write("/var/artillery/logs/*.log {\n  daily\n  rotate 14\n  compress\n  missingok\n  notifempty\n  copytruncate\n}\n")
    os.chmod("/etc/logrotate.d/artillery", 0o644)

    # Systemd service setup
    if os.path.exists("src/artillery.service"):
        shutil.copy("src/artillery.service", "/etc/systemd/system/artillery.service")
        subprocess.Popen("systemctl daemon-reload", shell=True).wait()
        subprocess.Popen("systemctl enable artillery", shell=True).wait()

    apply_tuning(target_os)
    generate_honeyfiles()

    print("[*] Generating Configuration...")
    try:
        init_globals() 
        check_config() 
        setup_prometheus_exporter() 
        
        conf_path = "/var/artillery/config"
        if os.path.exists(conf_path):
            with open(conf_path, "r") as f: lines = f.readlines()
            with open(conf_path, "w") as f:
                for line in lines:
                    if "OS_EMULATION=" in line: f.write(f'OS_EMULATION="{target_os}"\n')
                    else: f.write(line)
            os.chmod(conf_path, 0o600)
    except: pass

    # Apply global permission policy
    subprocess.call("find /var/artillery -type d -exec chmod 700 {} +", shell=True)
    subprocess.call("find /var/artillery -type f -exec chmod 600 {} +", shell=True)
    if os.path.exists("/var/artillery/metrics"):
        subprocess.call("chmod 755 /var/artillery/metrics", shell=True)
        subprocess.call("find /var/artillery/metrics -type f -name '*.prom' -exec chmod 644 {} +", shell=True)

    print(f"\n {ACTION} Complete!")
    
    # Clears buffer then asks for restart
    if ask_yes_no("[?] Restart Artillery Service now?"):
        subprocess.Popen("systemctl restart artillery", shell=True).wait()
        print("[*] Service restarted.")