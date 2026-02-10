<h1 align="center">Artillery Honeypot</h1>
<p align="center">
  <img src=".assets/logo0.png" alt="Artillery Logo" width="200">
</p>

---

**Artillery Honeypot** is a comprehensive, active security suite that combines a high-interaction honeypot, file integrity monitoring, system hardening, and a real-time threat intelligence feed.

Originally developed by **Binary Defense Systems**, this fork is a modernized **Python 3-based** implementation enhanced with advanced deception techniques, interactive traps, robust alerting, and modern monitoring integrations.

## 🛡️ Key Features

* **TCP / UDP Honeypot**: Opens multiple deceptive network services. Unauthorized connection attempts may trigger logging, alerting, or automatic firewall bans (policy-based).
* **SSH Interactive Trap**: Optional high-interaction fake SSH environment that mimics a real Linux shell and records attacker behavior without exposing the host system.
* **Dynamic Service Fingerprinting**: Rotating banners (Nginx, Apache, IIS, vsFTPd, etc.) to mislead scanners and automated reconnaissance tools.
* **Threat Intelligence Integration**: Synchronizes external IP blocklists with the local firewall using high-performance `ipset`.
* **Decoy Archive Delivery**: Serves high-compression **decoy ZIP archives** to automated crawlers searching for backups or environment files.
* **File Integrity Monitoring (FIM)**: SHA-512–based monitoring of critical paths (e.g. `/etc`, `/var/www`) to detect unauthorized changes.
* **System Hardening Audit**: Startup security checks for common OS misconfigurations with actionable recommendations.
* **Advanced Alerting**: Real-time notifications via **Telegram**, **Google Chat**, and aggregated **Email** reports with event correlation.
* **Enterprise Monitoring**: Built-in **Prometheus** exporter with Grafana-ready metrics for attack visualization and trend analysis.

---
## 🚀 Quick Start

> **Requirements:** Linux (systemd-based), iptables, ipset, Python 3, root privileges.

Artillery must be run as **root** to manage firewall rules and bind to protected ports.

```bash
git clone https://github.com/kraloveckey/artillery.git
cd artillery
python3 setup.py
```

After installation, Artillery runs as a systemd service.
### 🧰 Service & CLI Management

Artillery runs as a systemd service:

* Start: `systemctl start artillery`
* Status: `systemctl status artillery`
* Restart: `systemctl restart artillery`

### ⚙️ Configuration

The configuration file is located at `/var/artillery/config`. Below is the comprehensive list of parameters:

| Parameter                       | Description                                                                                                                                                                                   | Default                    |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| **🌐 System & General**         |                                                                                                                                                                                               |                            |
| OS_EMULATION                    | OS to emulate (WINDOWS/LINUX) for network fingerprinting (e.g., TTL behavior) and service personality selection.                                                                              | LINUX                      |
| SERVER_NAME                     | Display name for this specific server in alerts.                                                                                                                                              | ""                         |
| CONSOLE_LOGGING                 | Print real-time logs to the console.                                                                                                                                                          | ON                         |
| UPDATE_NOTIFY                   | Automatic notify updates (ON/OFF).                                                                                                                                                            | OFF                        |
| METRICS                         | Enable Prometheus metrics exporter.                                                                                                                                                           | ON                         |
| BIND_INTERFACE                  | Bind to specific local IP address(es) (empty for all interfaces).                                                                                                                             | ""                         |
| SYSLOG_TYPE                     | System log backend (LOCAL = journald/stdout, FILE = internal log file, REMOTE = UDP syslog).                                                                                                  | LOCAL                      |
| SYSLOG_REMOTE_HOST              | Remote Syslog IP address.                                                                                                                                                                     | 192.168.0.1                |
| SYSLOG_REMOTE_PORT              | Remote Syslog port (default 514).                                                                                                                                                             | 514                        |
| **🍯 Honeypot & Deception**     |                                                                                                                                                                                               |                            |
| TCPPORTS                        | List of TCP ports to open as bait.                                                                                                                                                            | 21,22,23,25,80,110         |
| UDPPORTS                        | List of UDP ports to monitor.                                                                                                                                                                 | 69,123,161,1900            |
| HONEYPOT_AGGREGATE_INTERVAL     | Time window (seconds) used to aggregate repeated honeypot events from the same source into a single alert (to reduce notification noise).                                                     | 60                         |
| DYNAMIC_FINGERPRINT             | Enables periodic rotation of service banners ("fingerprints") for honeypot services (e.g., SSH/FTP/HTTP) to reduce reliable identification by scanners and automated recon.                   | ON                         |
| FINGERPRINT_TTL                 | Fingerprint rotation interval in seconds. Once elapsed, a new fingerprint profile may be selected/generated (when dynamic fingerprinting is enabled).                                         | 86400                      |
| FINGERPRINT_LOCK                | Locks the selected fingerprint profile per service so the banner remains consistent for that service during the TTL window (prevents changing banners on every connection / across requests). | ON                         |
| SSH_TRAP                        | Enable interactive fake SSH shell on port 22 (requires port 22 to be unused by the real SSH daemon).                                                                                          | OFF                        |
| ZIP_BOMB_ENABLE                 | Enable high-compression ZIP bomb traps.                                                                                                                                                       | ON                         |
| LOG4J_DETECTOR                  | Detects CVE-2021-44228 JNDI injection attempts in HTTP headers/POST data.                                                                                                                     | OFF                        |
| HONEYPOT_BAN                    | Automatically ban attackers via firewall (iptables/ipset), based on honeypot activity.                                                                                                        | OFF                        |
| HONEYPOT_BAN_TOLERANCE          | Attempts allowed before a ban is issued (1=Instant).                                                                                                                                          | 1                          |
| HONEYPOT_AUTOACCEPT             | Automatically open iptables for honeypot ports.                                                                                                                                               | ON                         |
| HONEYPOT_BAN_CLASSC             | Ban the entire Class C subnet of the attacker.                                                                                                                                                | OFF                        |
| HONEYPOT_BAN_LOG_PREFIX         | Prefix for iptables logging.                                                                                                                                                                  | ARTILLERY_BLOCK:           |
| WHITELIST_IP                    | IPs that will never be banned (comma separated).                                                                                                                                              | 127.0.0.1                  |
| LOGO_IMAGE_URL                  | Custom logo URL for alerts (empty = ninja emoji).                                                                                                                                             | ""                         |
| **🔔 Notifications & Alerts**   |                                                                                                                                                                                               |                            |
| TELEGRAM_ALERTS                 | Enable instant Telegram Bot notifications.                                                                                                                                                    | OFF                        |
| TELEGRAM_TOKEN                  | Your Bot API Token.                                                                                                                                                                           | ""                         |
| TELEGRAM_CHAT_ID                | Your Telegram ID.                                                                                                                                                                             | ""                         |
| GW_ALERTS                       | Enable Google Chat Webhook notifications.                                                                                                                                                     | OFF                        |
| GW_WEBHOOK                      | Google Chat Webhook URL.                                                                                                                                                                      | ""                         |
| EMAIL_ALERTS                    | Enable SMTP email alerts. **Note**: Some high-frequency events (e.g., SSH honeypot activity) are always buffered internally to prevent alert flooding, even when EMAIL_TIMER is disabled.     | OFF                        |
| SMTP_ADDRESS                    | SMTP host (e.g., smtp.gmail.com).                                                                                                                                                             | smtp.gmail.com             |
| SMTP_PORT                       | SMTP port (default 587).                                                                                                                                                                      | 587                        |
| SMTP_USERNAME                   | SMTP login user.                                                                                                                                                                              | ""                         |
| SMTP_PASSWORD                   | SMTP login password.                                                                                                                                                                          | ""                         |
| SMTP_FROM                       | Source email address for alerts.                                                                                                                                                              | Artillery@localhost        |
| SMTP_FROM_NAME                  | Display name for the sender.                                                                                                                                                                  | Artillery Honeypot         |
| ALERT_USER_EMAIL                | Destination email for alerts.                                                                                                                                                                 | user@localhost             |
| EMAIL_TIMER                     | Buffer/aggregate emails to prevent spam.                                                                                                                                                      | ON                         |
| EMAIL_FREQUENCY                 | Time interval (seconds) for aggregating logs into one email.                                                                                                                                  | 600                        |
| **🛡️ Monitoring & Hardening**  |                                                                                                                                                                                               |                            |
| MONITOR                         | Enable File Integrity Monitor (SHA-512).                                                                                                                                                      | ON                         |
| MONITOR_FOLDERS                 | List of directories to watch for integrity changes (recursive).                                                                                                                               | "/var/www","/opt/"         |
| MONITOR_FREQUENCY               | Integrity check frequency in seconds.                                                                                                                                                         | 60                         |
| EXCLUDE                         | Paths to exclude from file monitoring (supports partial path matching).                                                                                                                       | ""                         |
| SSH_BRUTE_MONITOR               | Monitor system logs for SSH brute force.                                                                                                                                                      | ON                         |
| SSH_BRUTE_ATTEMPTS              | Failed logins allowed before banning.                                                                                                                                                         | 3                          |
| WEB_MONITOR                     | Monitor web server logs for attacks (ON/OFF).                                                                                                                                                 | OFF                        |
| WEB_ACCESS_LOG                  | Path to web access logs (Nginx/Apache).                                                                                                                                                       | /var/log/nginx/*access.log |
| WEB_ERROR_LOG                   | Path to web error logs.                                                                                                                                                                       | /var/log/nginx/*error.log  |
| SYSTEM_HARDENING                | Perform security audit on startup.                                                                                                                                                            | ON                         |
| SSH_DEFAULT_PORT_CHECK          | Warn if SSH is running on standard port 22.                                                                                                                                                   | ON                         |
| ROOT_CHECK                      | Warn if root login is enabled.                                                                                                                                                                | ON                         |
| **📡 Threat Intelligence Feed** |                                                                                                                                                                                               |                            |
| THREAT_INTELLIGENCE_FEED        | Enable external global blocklists.                                                                                                                                                            | OFF                        |
| THREAT_BLOCKLIST_URLS           | Raw text URLs for external blocklists.                                                                                                                                                        | ""                         |
| THREAT_WHITELIST_URLS           | Raw text URLs for external whitelists.                                                                                                                                                        | ""                         |
| THREAT_GITHUB_TOKEN             | Token for private blocklist repos.                                                                                                                                                            | ""                         |
| THREAT_BLACKLIST_IPSET_NAME     | IPSet name for the consolidated blacklist (local + remote).                                                                                                                                   | artillery_black            |
| THREAT_WHITELIST_IPSET_NAME     | IPSet name for the consolidated whitelist (local + remote).                                                                                                                                   | artillery_white            |
| ARTILLERY_REFRESH               | Feed refresh rate in seconds.                                                                                                                                                                 | 86400                      |
## 📁 Project Structure

The project follows a modular architecture where each security function is isolated into a dedicated module.

- `artillery.py` – Main service orchestrator and command-line interface.
- `setup.py` – Automated installer (dependencies, SSL generation, exporter config).
- `src/artillery.service` – Systemd unit file for running Artillery as a service.
- `src/auth_monitor.py` – Real-time system log analyzer for brute-force detection.
- `src/core.py` – Central engine handling configuration, banning, and alert routing.
- `src/email_handler.py` – Notification aggregator and SMTP engine.
- `src/globals.py` – Shared constants / defaults / global configuration helpers used across modules.
- `src/harden.py` – OS security auditing and hardening module.
- `src/honeypot.py` – Port listeners, banner spoofing, and zip-bomb logic.
- `src/metrics.py` – Prometheus exporter for Grafana visualization.
- `src/monitor.py` – File system integrity monitor using SHA-512 hashes.
- `src/threats.py` – Global threat feed downloader and ipset manager.
- `src/ssh_honeypot.py` – Interactive SSH shell trap and keystroke logger.
- `src/updater.py` – Update notification mechanism.
- `src/web_monitor.py` – Web log monitoring logic (e.g., nginx/apache log parsing), if enabled by configuration.

All modules rely on `src/core.py` for unified configuration access, logging, alert routing, and enforcement of security policies.

## ⚠️ Security Disclaimer

Artillery is designed for defensive research, deception, and detection.
It should be deployed on isolated systems, honeypot hosts, or controlled environments.

Do not deploy on production endpoints without understanding the operational and legal implications.

## ⚖️ License & Copyright

> Artillery Project edited & enhanced by kraloveckey

This project is built upon the original vision and work of [Binary Defense Systems](https://www.binarydefense.com). Special thanks to the original authors and contributors: **sp0rus**, **bryogenic**, **Ryan Elkins**, **Larry Spohn**, **Jeff Bryner**, **Giulio Bortot**, **corelanc0d3r**, and **russhaun**. Their dedication to the original Artillery project made these enhancements possible.

## 🧠 Design Philosophy

Artillery Project is designed to favor **signal over noise**. 

Every component is engineered to capture meaningful attacker behavior while minimizing false positives, alert fatigue, and risk to the host system.

> Also note that by using this software, if you ever see the editor of Artillery in a bar, you are encouraged to give him a hug and buy him a beer 🍺. Hug duration negotiable. Editor holds the right to refuse the hug or the beer.