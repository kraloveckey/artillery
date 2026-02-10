#!/usr/bin/env python3
#
# src/updater.py
#
import time

try:
    from src.core import read_config, update, write_log
except Exception:
    read_config = None
    update = None
    write_log = None

CHECK_INTERVAL = 3600  # 1 hour

def auto_update_loop():
    """
    UPDATE_NOTIFY:
      - OFF: do nothing
      - ON : notify-only, check on startup + every hour
    """
    if not read_config or not update:
        return

    # Check immediately on startup
    try:
        if read_config("UPDATE_NOTIFY").strip().upper() == "ON":
            update()
    except Exception as e:
        if write_log:
            write_log(f"Updater error (startup): {e}", 2)

    while True:
        try:
            mode = read_config("UPDATE_NOTIFY").strip().upper()
            if mode == "ON":
                update()
        except Exception as e:
            if write_log:
                write_log(f"Updater error: {e}", 2)
        time.sleep(CHECK_INTERVAL)