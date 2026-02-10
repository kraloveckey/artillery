#!/usr/bin/env python3
#
# src/globals.py
#

# Version of the Artillery Security Suite
g_version = "2.0.0-py3"

# Root directory of the application (e.g., /var/artillery or /opt/artillery)
g_apppath = ""

# Full path to the main executable script (artillery.py)
g_appfile = ""

# Full path to the main configuration file
g_configfile = ""

# Full path to the global banlist.txt (synced with iptables)
g_banlist = ""

# Full path to the localbanlist.txt (legacy support)
g_localbanlist = ""

# Directory path where SSL certificates (cert.pem, key.pem) are stored
g_sslpath = ""