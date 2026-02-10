#!/usr/bin/env python3
#
# src/web_monitor.py
#
import time
import os
import re
import threading
import glob
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import *
except ImportError:
    pass

# Aggregate per (ip + file) within this time window
AGG_WINDOW_SECONDS = 10
# Safety caps (avoid insane messages)
MAX_EVENTS_PER_KEY = 50
MAX_MSG_LEN = 3500

_pending = {} # (ip, src) -> {"t0": float, "uris": [], "matches": [], "count": int}


def _flush_key(key):
    data = _pending.get(key)
    if not data:
        return

    ip, src = key
    count = data["count"]
    uris = data["uris"]
    matches = data["matches"]

    def uniq(seq):
        seen = set()
        out = []
        for x in seq:
            if x is None:
                continue
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    uris_u = uniq(uris)[:10]
    matches_u = uniq(matches)[:10]

    parts = []
    if uris_u:
        parts.append("uris: " + ", ".join(uris_u))
    if matches_u:
        parts.append("matches: " + ", ".join(matches_u))

    extra = f" ({' | '.join(parts)})" if parts else ""

    if ip == "unknown":
        msg = f"web attack detected {count}x (ip=unknown) in {src}{extra}"
    else:
        msg = f"web attack detected {count}x from {ip} in {src}{extra}"

    if len(msg) > MAX_MSG_LEN:
        msg = msg[:MAX_MSG_LEN] + "…"

    write_log(msg, 1)
    warn_the_good_guys("web attack detected", msg)

    if ip != "unknown" and is_valid_ipv4(ip) and not is_whitelisted_ip(ip):
        ban(ip, port="web")

    del _pending[key]

def _flush_expired(now):
    for key, data in list(_pending.items()):
        if now - data["t0"] >= AGG_WINDOW_SECONDS:
            _flush_key(key)


def monitor_web_logs():
    if not is_config_enabled("WEB_MONITOR"):
        return

    raw_paths = []
    acc = read_config("WEB_ACCESS_LOG")
    if acc:
        raw_paths.extend(acc.split(","))
    err = read_config("WEB_ERROR_LOG")
    if err:
        raw_paths.extend(err.split(","))

    log_files = []
    for path in raw_paths:
        path = path.strip().replace('"', '').replace("'", "")
        if not path:
            continue
        found = glob.glob(path)
        if found:
            log_files.extend(found)
        elif os.path.isfile(path):
            log_files.append(path)

    log_files = list(set(log_files))
    if not log_files:
        write_log("web monitor: no valid log files found to watch.", 1)
        return

    write_console(f"web monitor watching: {len(log_files)} files.")

    attack_patterns = [
        r"etc/passwd", r"boot\.ini", r"union.*select", r"eval\(", r"<script>",
        r"\.\./\.\./", r"/cgi-bin/", r"cmd\.exe", r"root\.exe", r"w00tw00t",
        r"jndi:ldap", r"phpinfo", r"\.env", r"wp-config", r"config\.php",
        r"/actuator/", r"/\.git/", r"wp-admin", r"wp-login\.php"
        r"/proc/self/environ",
        r"php://(?:filter|input|stdin)",
        r"%2e%2e%2f|%2e%2e%5c", # Encoded traversal
        r"\.\.%2f|\.\.%5c", # Another encoded traversal variant
        r"xmlrpc\.php",
        r"wp-json",
        r"wp-content",
        r"wp-includes",
        r"composer\.(?:json|lock)",
        r"/phpmyadmin",
        r"/server-status",
        r"\.DS_Store",
        r"\.(?:bak|old|swp|swo)\b",
        r"client sent invalid request",
        r"invalid request line",
        r"client intended to send too large body",
        r"upstream sent too big header",
        r"buffered to a temporary file",
        r"request body is buffered"
    ]
    compiled_attack = re.compile("|".join(attack_patterns), re.IGNORECASE)
    compiled_attack_list = [re.compile(p, re.IGNORECASE) for p in attack_patterns]

    # URI extraction from access logs
    req_re = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^ \t"]+)')

    # nginx + apache IP extraction
    ip_patterns = [
        re.compile(r'\bclient:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b'), # nginx error.log
        re.compile(r'\[client\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::\d+)?\]'), # apache error.log
        re.compile(r'^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b'), # access.log
    ]

    files_handles = {}
    for log in log_files:
        try:
            f = open(log, "r", encoding="utf-8", errors="ignore")
            f.seek(0, 2)
            files_handles[log] = f
        except Exception as e:
            write_log(f"web monitor: could not open {log}: {e}", 2)

    while True:
        now = time.time()
        _flush_expired(now)

        for log_path, f in list(files_handles.items()):
            try:
                while True:
                    line = f.readline()
                    if not line:
                        break

                    if not compiled_attack.search(line):
                        continue

                    attacker_ip = None
                    for p in ip_patterns:
                        m = p.search(line)
                        if m:
                            attacker_ip = m.group(1)
                            break

                    if not attacker_ip:
                        attacker_ip = "unknown"
                    elif (not is_valid_ipv4(attacker_ip)) or is_whitelisted_ip(attacker_ip):
                        continue

                    hit = None
                    for rx in compiled_attack_list:
                        if rx.search(line):
                            hit = rx.pattern
                            break

                    uri = None
                    rm = req_re.search(line)
                    if rm:
                        uri = rm.group(1)

                    src = os.path.basename(log_path)
                    key = (attacker_ip, src)

                    if key not in _pending:
                        _pending[key] = {"t0": now, "uris": [], "matches": [], "count": 0}

                    d = _pending[key]
                    d["count"] += 1
                    if uri:
                        d["uris"].append(uri)
                    if hit:
                        d["matches"].append(hit)

                    if d["count"] >= MAX_EVENTS_PER_KEY:
                        _flush_key(key)

            except Exception:
                try:
                    f.close()
                except Exception:
                    pass
                try:
                    new_f = open(log_path, "r", encoding="utf-8", errors="ignore")
                    new_f.seek(0, 2)
                    files_handles[log_path] = new_f
                except Exception:
                    pass

        time.sleep(1)


t = threading.Thread(target=monitor_web_logs)
t.daemon = True
t.start()