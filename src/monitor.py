#!/usr/bin/env python3
#
# src/monitor.py
#
import os
import re
import hashlib
import time
import subprocess
import threading
import shutil
import datetime
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

def calculate_sha512(filepath):
    """ Helper to safely calculate SHA-512 hash of a file in chunks """
    sha = hashlib.sha512()
    try:
        # Check file size – ignore extremely large files (>500MB) to prevent hangs
        if os.path.getsize(filepath) > 524288000:
            return "SKIPPED_LARGE_FILE"
            
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(65536) 
                if not data: break
                sha.update(data)
        return sha.hexdigest()
    except:
        return None

def _load_db(db_path: str) -> dict:
    """Loads 'path:hash' lines into a dict."""
    data = {}
    try:
        with open(db_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                path, h = line.rsplit(":", 1)
                path = path.strip()
                h = h.strip()
                if path:
                    data[path] = h
    except Exception:
        pass
    return data

def _summarize_changes(old_db: dict, new_db: dict):
    old_paths = set(old_db.keys())
    new_paths = set(new_db.keys())

    added = sorted(new_paths - old_paths)
    removed = sorted(old_paths - new_paths)
    changed = sorted([p for p in (old_paths & new_paths) if old_db.get(p) != new_db.get(p)])

    return added, removed, changed

def _append_integrity_detail_log(app_path: str, added, removed, changed, old_db, new_db):
    """Write detailed change info to a local file (hashes included)."""
    try:
        log_dir = os.path.join(app_path, "logs")
        os.makedirs(log_dir, exist_ok=True)
        detail_path = os.path.join(log_dir, "integrity_changes.log")

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(detail_path, "a") as f:
            f.write(f"\n[{ts}] Integrity changes detected\n")
            if added:
                f.write("ADDED:\n")
                for p in added:
                    f.write(f"  + {p} : {new_db.get(p,'')}\n")
            if removed:
                f.write("REMOVED:\n")
                for p in removed:
                    f.write(f"  - {p} : {old_db.get(p,'')}\n")
            if changed:
                f.write("CHANGED:\n")
                for p in changed:
                    f.write(f"  * {p}\n")
                    f.write(f"      old: {old_db.get(p,'')}\n")
                    f.write(f"      new: {new_db.get(p,'')}\n")
    except Exception:
        pass

def monitor_system():
    """ Scans configured directories and compares hashes against the database """
    total_compare = ""
    
    # Parse folders to monitor
    check_folders_str = read_config("MONITOR_FOLDERS")
    check_folders_str = check_folders_str.replace('"', "").strip()
    check_folders = [f.strip() for f in check_folders_str.split(",") if f.strip()]
    
    # Parse exclusions
    exclude_str = read_config("EXCLUDE")
    exclude_list = [e.strip() for e in exclude_str.split(",") if e.strip()]

    # Walk directories and calculate hashes
    for directory in check_folders:
        if os.path.isdir(directory):
            for path, subdirs, files in os.walk(directory):
                # Skip excluded directories
                if any(ex in path for ex in exclude_list):
                    continue
                    
                for name in files:
                    filename = os.path.join(path, name)
                    
                    # Skip excluded files
                    if any(ex in filename for ex in exclude_list):
                        continue
                    
                    if os.path.isfile(filename):
                        file_hash = calculate_sha512(filename)
                        if file_hash:
                            # Format: path:hash
                            total_compare += f"{filename}:{file_hash}\n"

    # Define DB paths using global application path
    app_path = getattr(globals, 'g_apppath', "/var/artillery")
    db_dir = os.path.join(app_path, "database")
    
    if not os.path.isdir(db_dir):
        os.makedirs(db_dir)
        
    temp_db = os.path.join(db_dir, "temp.database")
    integrity_db = os.path.join(db_dir, "integrity.database")

    # Write the current state to a temporary database
    with open(temp_db, "w") as f:
        f.write(total_compare)

    # Initial run: if no integrity DB exists, create it and exit
    if not os.path.isfile(integrity_db):
        write_log("File Integrity Monitor: Creating initial integrity database.")
        shutil.copy(temp_db, integrity_db)
        return

    # Compare DB hashes to detect any changes
    current_db_hash = calculate_sha512(integrity_db)
    temp_db_hash = calculate_sha512(temp_db)

    if current_db_hash != temp_db_hash:
        try:
            old_db = _load_db(integrity_db)
            new_db = _load_db(temp_db)

            added, removed, changed = _summarize_changes(old_db, new_db)

            # Save full details with hashes locally
            _append_integrity_detail_log(app_path, added, removed, changed, old_db, new_db)

            subject = "File Integrity Alert"
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            host = gethostname()

            # Build compact, channel-safe message
            changed_files = added + removed + changed
            max_list = 25
            shown = changed_files[:max_list]
            extra = len(changed_files) - len(shown)

            lines = []
            lines.append("Artillery File Integrity Change Detected!")
            lines.append(f"Time: {ts}")
            lines.append(f"Host: {host}")
            lines.append("")
            lines.append(f"Changed files ({len(changed_files)}):")
            for p in shown:
                lines.append(f" - {p}")
            if extra > 0:
                lines.append(f" - ... and {extra} more")
            lines.append("")
            lines.append("Notes:")
            lines.append(" - Integrity database updated (auto-accept enabled)")
            lines.append(f" - Details saved to: {os.path.join(app_path, 'logs', 'integrity_changes.log')}")

            body = "\n".join(lines)

            # Build compact notification (single alert)
            lines = []
            lines.append(f"Artillery File Integrity Change Detected! Changed files ({len(changed_files)}):")
            for p in changed_files:
                lines.append(f" - {p}")
            
            compact_msg = "\n".join([
            f"File Integrity Change Detected! Changed files ({len(changed_files)}):",
            *[f" - {p}" for p in changed_files]
            ])
            warn_the_good_guys("Artillery Alert", compact_msg, custom_timestamp=grab_time())

        except Exception as e:
            write_log(f"Integrity Monitor: Error building summary: {e}", 2)

        # Move temp DB to integrity DB (Accept changes)
        shutil.move(temp_db, integrity_db)

def start_monitor_loop():
    """ Execution loop for the monitor """
    if is_config_enabled("MONITOR"):
        try:
            wait_seconds = int(read_config("MONITOR_FREQUENCY"))
            if wait_seconds < 10: wait_seconds = 60
        except:
            wait_seconds = 60

        write_log(f"File Integrity Monitor active (Interval: {wait_seconds}s)")
        
        while True:
            try:
                monitor_system()
            except Exception as e:
                write_log(f"Integrity Monitor Loop Error: {e}", 2)
            
            time.sleep(wait_seconds)

# Launch monitor in a daemon thread
if is_posix():
    t = threading.Thread(target=start_monitor_loop)
    t.daemon = True
    t.start()