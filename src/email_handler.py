#!/usr/bin/env python3
#
# src/email_handler.py
#
import shutil
import time
import threading
import os
import socket
import re
import sys

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core import read_config, send_mail, is_config_enabled, write_log, get_system_stats, init_globals
    import src.globals as globals
except ImportError as e:
    print(f"[!] Email Handler Import Error: {e}")
    pass

# Ensure globals are initialized if this module is run independently
if not hasattr(globals, 'g_apppath') or not globals.g_apppath:
    init_globals(project_root)

# Limit for email size to prevent mail server issues during heavy attacks
MAX_LOG_SIZE_BYTES = 50 * 1024

def aggregate_logs(log_data: str) -> str:
    if not log_data:
        return ""

    lines = [l.rstrip() for l in log_data.splitlines() if l.strip()]
    if not lines:
        return ""

    # Parse prefix: "Feb 06 18:17:48 test-art: Artillery <msg>"
    prefix_re = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+):\s+Artillery\s+(.*)$")

    # Extract ip/port/iface from message
    ipport_re = re.compile(r"\bfrom\s+(\d+\.\d+\.\d+\.\d+)\s+on\s+port\s+(\d+)\s+\(([^)]*)\)", re.IGNORECASE)

    def msg_type(msg_lower: str) -> str:
        # Keep these explicit (no aggregation)
        if "detected login attempt" in msg_lower:
            return "login"
        if "detected command" in msg_lower:
            return "cmd"

        # Aggregate these:
        if "detected attack on the ssh honeypot" in msg_lower:
            return "ssh_attack"
        if "detected connection attempt on the ssh honeypot" in msg_lower:
            return "ssh_attack"
        if "detected attack from" in msg_lower:
            return "attack"

        return "other"

    # Store aggregates by key, but also remember first position to preserve timeline feel
    aggregates = {}  # key -> dict
    first_pos = {}   # key -> first index
    passthrough = [] # list of tuples (idx, line) that must remain literal

    for idx, line in enumerate(lines):
        m = prefix_re.match(line)
        if not m:
            passthrough.append((idx, line))
            continue

        ts, host, msg = m.groups()
        ml = msg.lower()
        t = msg_type(ml)

        if t in ("login", "cmd", "other"):
            passthrough.append((idx, line))
            continue

        ipp = ipport_re.search(msg)
        if not ipp:
            passthrough.append((idx, line))
            continue

        ip, port, iface = ipp.groups()

        # Build normalized key
        # ssh_attack is separate type so it doesn't mix with generic port 22 scans
        if t == "ssh_attack":
            key = (t, host, ip, port)
        else:
            key = (t, host, ip, port, iface)

        if key not in aggregates:
            aggregates[key] = {
                "type": t,
                "host": host,
                "ip": ip,
                "port": port,
                "iface": iface,
                "count": 1,
                "start_ts": ts,
                "end_ts": ts,
                "first_idx": idx,
                "raw_msg": msg,
            }
            first_pos[key] = idx
        else:
            a = aggregates[key]
            a["count"] += 1
            a["end_ts"] = ts

    # Build output: place aggregated line at first occurrence index
    rendered_at = {}  # idx -> rendered line(s)
    for key, a in aggregates.items():
        start_full = a["start_ts"]
        end_full = a["end_ts"]
        end_time_only = end_full.split()[-1]
        time_display = f"{start_full} – {end_time_only}" if start_full != end_full else start_full

        if a["type"] == "ssh_attack":
            if a["count"] > 1:
                msg = f"detected {a['count']}x attack on the SSH honeypot from {a['ip']} on port {a['port']} ({a['iface']})"
            else:
                msg = f"detected attack on the SSH honeypot from {a['ip']} on port {a['port']} ({a['iface']})"
        else:
            # Keep classic attack wording
            base = a.get("raw_msg", "")
            if a["count"] > 1:
                if re.search(r"\bdetected\b", base, flags=re.IGNORECASE):
                    base = re.sub(r"\bdetected\b", f"detected {a['count']}x", base, count=1, flags=re.IGNORECASE)
                else:
                    base = f"{base} ({a['count']}x)"

            msg = base

        line_out = f"{time_display} {a['host']}: Artillery {msg}"
        rendered_at.setdefault(a["first_idx"], []).append(line_out)

    aggregated_idxs = set()
    for a in aggregates.values():
        pass

    out = []
    for idx, line in enumerate(lines):
        # If this index has aggregate(s), output them now
        if idx in rendered_at:
            out.extend(rendered_at[idx])

        # Decide whether to skip this raw line because it was aggregated
        m = prefix_re.match(line)
        if not m:
            pass

        skip = False
        if m:
            ts, host, msg = m.groups()
            ml = msg.lower()
            t = msg_type(ml)
            if t in ("attack", "ssh_attack"):
                ipp = ipport_re.search(msg)
                if ipp:
                    ip, port, iface = ipp.groups()
                    if t == "ssh_attack":
                        key = (t, host, ip, port)
                    else:
                        key = (t, host, ip, port, iface)
                    
                    if key in aggregates:
                        skip = True

        if not skip:
            # Keep literal lines (login/cmd/other) exactly as in input
            # but avoid duplicating rendered aggregates
            if m:
                # Only non-aggregated prefixed lines
                out.append(line)
            else:
                out.append(line)

    return "\n".join(out)

def normalize_file_integrity_blocks(text: str) -> str:
    lines = text.splitlines()
    out = []
    i = 0

    header_re = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+):\s+Artillery\s+File Integrity Change Detected!\s+Changed files\s+\((\d+)\):\s*$"
    )
    bullet_re = re.compile(
        r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+:\s+Artillery\s+-\s+(/.+)\s*$"
    )

    while i < len(lines):
        m = header_re.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue

        out.append(lines[i])
        i += 1

        while i < len(lines):
            bm = bullet_re.match(lines[i])
            if not bm:
                break
            out.append(f"- {bm.group(1)}")
            i += 1

    return "\n".join(out)

def sort_log_lines(log_data: str) -> str:
    lines = [l for l in log_data.splitlines() if l.strip()]
    ts_re = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
    months = {m:i for i,m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

    def key(line):
        m = ts_re.match(line)
        if not m:
            return (1, 0, 0, 0)
        mon, day, hms = m.group(1), int(m.group(2)), m.group(3)
        hh, mm, ss = map(int, hms.split(":"))
        return (0, months.get(mon, 0), day, hh*3600+mm*60+ss)

    lines.sort(key=key)
    return "\n".join(lines) + "\n"

def sort_log_blocks(log_data: str) -> str:
    """
    Sort syslog-like entries while keeping continuation lines (starting with two spaces)
    attached to the previous timestamped line.
    """
    raw_lines = [l.rstrip("\n") for l in log_data.splitlines() if l.strip()]
    if not raw_lines:
        return ""

    ts_re = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b")
    months = {m:i for i,m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

    def ts_key(line: str):
        m = ts_re.match(line)
        if not m:
            return (1, 0, 0, 0)
        mon, day, hms = m.group(1), int(m.group(2)), m.group(3)
        hh, mm, ss = map(int, hms.split(":"))
        return (0, months.get(mon, 0), day, hh*3600 + mm*60 + ss)

    blocks = []
    cur = []

    for line in raw_lines:
        if line.startswith("  "):
            if cur:
                cur.append(line)
            else:
                blocks.append([line])
            continue

        if cur:
            blocks.append(cur)
        cur = [line]

    if cur:
        blocks.append(cur)

    blocks_sorted = sorted(blocks, key=lambda b: ts_key(b[0]))

    out = []
    for b in blocks_sorted:
        out.extend(b)

    return "\n".join(out) + "\n"

def check_alert():
    """ Main loop to check for pending logs and send email reports """
    try:
        mail_time = int(read_config("EMAIL_FREQUENCY"))
    except:
        mail_time = 600

    while True:
        log_dir = os.path.join(globals.g_apppath, "logs")
        mail_log_file = os.path.join(log_dir, "email_alerts.log")
        processing_file = os.path.join(log_dir, "email_alerts.processing")
        mail_old_log_file = os.path.join(log_dir, "email_alerts.old")
        
        logo_url = read_config("LOGO_IMAGE_URL")
        logo_html = f'<img src="{logo_url}" alt="Artillery" style="width: 90px; height: auto; display: block;">' if logo_url else '<div style="font-size: 60px;">🥷</div>'

        if os.path.isfile(mail_log_file) and os.path.getsize(mail_log_file) > 0:
            try:
                # Rotate log to processing file to avoid write-conflicts during mail send
                shutil.move(mail_log_file, processing_file)
            except Exception as e:
                write_log(f"Email Handler: Error moving log: {e}", 2)

        if os.path.isfile(processing_file):
            try:
                file_size = os.path.getsize(processing_file)
                is_massive_attack = False
                alert_data = ""
                
                with open(processing_file, "r", errors='ignore') as f:
                    alert_data = f.read()

                if file_size > MAX_LOG_SIZE_BYTES:
                    is_massive_attack = True
                
                clean_logs_text = ""
                if alert_data.strip():
                    if is_massive_attack:
                        clean_logs_text = (
                            "⚠️  MASSIVE ATTACK DETECTED  ⚠️\n\n"
                            "The alert buffer exceeded the safety limit (50KB).\n"
                            f"Current Buffer Size: {round(file_size/1024, 2)} KB\n"
                            f"Directly review logs at: {mail_old_log_file}"
                        )
                    else:
                        clean_logs_text = normalize_file_integrity_blocks(
                            aggregate_logs(sort_log_blocks(alert_data))
                        )

                # Send alerts if configured and there is data to send
                if (is_config_enabled("EMAIL_ALERTS") or is_config_enabled("GW_ALERTS") or is_config_enabled("TELEGRAM_ALERTS")) and alert_data.strip():
                    sys_stats = get_system_stats()
                    server_name = read_config("SERVER_NAME") or socket.gethostname()
                    
                    subject = f"{server_name} | Artillery Alert"
                    if is_massive_attack: subject = f"{server_name} | 🚨 MASSIVE ATTACK WARNING"
                    
                    if is_config_enabled("EMAIL_ALERTS"):
                        def _html_escape(s: str) -> str:
                            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

                        clean_logs_html = _html_escape(clean_logs_text.strip())
                        html_content = f"""
                        <html>
                        <body style="background-color: #ffffff; color: #333333; font-family: 'Courier New', monospace; padding: 20px;">
                            <div style="text-align: center; border-bottom: 2px solid #0056b3;">
                                <table style="display: inline-block;">
                                    <tr>
                                        <td style="padding-right: 20px;">{logo_html}</td>
                                        <td>
                                            <div style="color: #008f11; font-size: 13px; font-weight: bold;">
                                                Wake up, Neo...<br>The Matrix has you...<br>Follow the white rabbit...<br>Knock, knock, Neo!
                                            </div>
                                        </td>
                                    </tr>
                                </table>
                            </div>
                            <div style="margin:18px 0 10px 0; padding-left:12px; border-left:5px solid #c62828; color:#c62828; font-weight:800; font-size:16px; letter-spacing:2px; font-family:'Courier New', monospace;">
                              SECURITY EVENTS LOG
                            </div>
                            <pre style="background-color: #fff0f1; border: 1px solid #fadbd8; padding: 15px; color: #842029;">{clean_logs_html}</pre>
                            <div style="margin:18px 0 10px 0; padding-left:12px; border-left:5px solid #1565c0; color:#1565c0; font-weight:800; font-size:16px; letter-spacing:2px; font-family:'Courier New', monospace;">
                              SYSTEM STATUS
                            </div>
                            <pre style="background-color: #f4f4f4; border: 1px solid #ddd; padding: 15px;">{sys_stats.strip()}</pre>
                            <hr>
                            <center style="font-size: 11px; color: #008f11;"><div><b>Binary Defense Systems | Artillery Honeypot Project</b></div><div><span style="color:#008f11;"><div><b>Edited by kraloveckey</b></div></span></div></center>
                        </body>
                        </html>
                        """
                        plain_text = (
                            f"Artillery Alerts:\n\n{clean_logs_text.strip()}\n\n"
                            f"SYSTEM STATUS:\n{sys_stats.strip()}\n\n"
                            f"Binary Defense Systems | Artillery Project\n"
                            f"Edited by kraloveckey\n"
                        )
                        send_mail(subject, plain_text, html_body=html_content)

                    if is_config_enabled("GW_ALERTS"):
                        from src.core import send_google_chat
                        send_google_chat(subject, clean_logs_text.strip())

                    if is_config_enabled("TELEGRAM_ALERTS"):
                        from src.core import send_telegram
                        send_telegram(subject, clean_logs_text.strip())

                # Archive processed logs
                with open(mail_old_log_file, "a") as archive:
                    archive.write(alert_data)
                
                os.remove(processing_file)

            except Exception as e:
                write_log(f"Email Handler execution error: {e}", 2)
        
        time.sleep(mail_time)

# Launch background alert checker
t = threading.Thread(target=check_alert)
t.daemon = True
t.start()