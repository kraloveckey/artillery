#!/usr/bin/env python3
#
# src/metrics.py
#
import os
import time
import threading
import sys

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import src.globals as globals
except ImportError:
    pass

METRICS_DATA = {
    "attacks": {},          
    "whitelist": {},        
    "notifications": {},    
    "banned_ips": 0,
    "service_up": 1 # 1 = UP, 0 = DOWN
}

# Lock for internal dictionary updates
data_lock = threading.Lock()
# Lock for file writing
file_lock = threading.Lock()

def init_metrics_dir():
    """ Ensures the metrics directory exists based on global path """
    if not hasattr(globals, 'g_apppath') or not globals.g_apppath:
        return None
        
    metrics_dir = os.path.join(globals.g_apppath, "metrics")
    if not os.path.isdir(metrics_dir):
        try: os.makedirs(metrics_dir)
        except: pass
    return metrics_dir

def record_attack(port, interface, proto="tcp"):
    """ Increments attack counter for specific port/proto """
    key = (str(port), str(interface), str(proto))
    with data_lock:
        METRICS_DATA["attacks"][key] = METRICS_DATA["attacks"].get(key, 0) + 1

def record_whitelist_hit(ip):
    """ Increments counter for whitelisted IP activity """
    key = str(ip)
    with data_lock:
        # Limited to top hits or summarized to prevent metrics file bloat
        if len(METRICS_DATA["whitelist"]) < 100:
            METRICS_DATA["whitelist"][key] = METRICS_DATA["whitelist"].get(key, 0) + 1
    
def record_notification(ntype, status):
    """ Records status of alert deliveries (e.g. email, gchat) """
    key = (str(ntype), str(status))
    with data_lock:
        METRICS_DATA["notifications"][key] = METRICS_DATA["notifications"].get(key, 0) + 1

def update_ban_count():
    """ Syncs the metrics gauge with the actual banlist file """
    try:
        if hasattr(globals, 'g_banlist') and os.path.isfile(globals.g_banlist):
            with open(globals.g_banlist, 'r') as f:
                count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            with data_lock:
                METRICS_DATA["banned_ips"] = count
    except:
        pass

def set_service_status(is_up):
    """ Updates the service availability gauge """
    with data_lock:
        METRICS_DATA["service_up"] = 1 if is_up else 0
    write_metrics_file() # High priority, write immediately

def write_metrics_file():
    """ Writes metrics to disk in Prometheus-compatible format """
    path = init_metrics_dir()
    if not path: return 

    metrics_path = os.path.join(path, "artillery.prom")
    
    with file_lock:
        try:
            temp_path = metrics_path + ".tmp"
            
            with open(temp_path, "w") as f:
                # Attacks
                f.write("# HELP artillery_attacks_total Total detected attacks per port/proto\n")
                f.write("# TYPE artillery_attacks_total counter\n")
                with data_lock:
                    for (port, iface, proto), count in METRICS_DATA["attacks"].items():
                        f.write(f'artillery_attacks_total{{port="{port}",interface="{iface}",proto="{proto}"}} {count}\n')

                # Whitelist hits
                f.write("# HELP artillery_whitelist_hits_total Total connections ignored from whitelisted IPs\n")
                f.write("# TYPE artillery_whitelist_hits_total counter\n")
                with data_lock:
                    for ip, count in METRICS_DATA["whitelist"].items():
                        f.write(f'artillery_whitelist_hits_total{{source_ip="{ip}"}} {count}\n')

                # Notifications
                f.write("# HELP artillery_notifications_total Alert delivery success/failure counts\n")
                f.write("# TYPE artillery_notifications_total counter\n")
                with data_lock:
                    for (ntype, status), count in METRICS_DATA["notifications"].items():
                        f.write(f'artillery_notifications_total{{type="{ntype}",status="{status}"}} {count}\n')

                # Banned IPs
                f.write("# HELP artillery_banned_ips_count Current count of IPs in banlist\n")
                f.write("# TYPE artillery_banned_ips_count gauge\n")
                f.write(f'artillery_banned_ips_count {METRICS_DATA["banned_ips"]}\n')

                # Service status
                f.write("# HELP artillery_service_up Status of Artillery service (1=UP, 0=DOWN)\n")
                f.write("# TYPE artillery_service_up gauge\n")
                f.write(f'artillery_service_up {METRICS_DATA["service_up"]}\n')

                # Heartbeat
                f.write("# HELP artillery_last_update_timestamp_seconds Last metrics update timestamp\n")
                f.write("# TYPE artillery_last_update_timestamp_seconds gauge\n")
                f.write(f'artillery_last_update_timestamp_seconds {int(time.time())}\n')

            # Atomic swap
            os.replace(temp_path, metrics_path)
            
        except Exception:
            pass

def metrics_sync_loop():
    """ Background loop to periodicially sync metrics to disk (every 15s) """
    while True:
        if hasattr(globals, 'g_apppath') and globals.g_apppath:
            update_ban_count()
            write_metrics_file()
        time.sleep(15) 

# Start the sync thread
t = threading.Thread(target=metrics_sync_loop)
t.daemon = True
t.start()