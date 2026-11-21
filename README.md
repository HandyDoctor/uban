# uban — Universal Ban Daemon for Linux

<p align="center">
  <img src="assets/uban.jpg" alt="UBAN Logo" width="220" />
</p>

[![Language](https://img.shields.io/badge/language-C99-blue.svg)](https://en.cppreference.com/w/c/99)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(nftables)-orange.svg)](https://netfilter.org/projects/nftables/)

> **What's New in v1.1:** Embedded ACID SQLite persistence (zero external service), on-demand `nftables` snapshots (`save_to_snapshot` / `restore_from_snapshot`), IPC daemon liveness guards, and fixed CIDR subnet whitelisting. Upgrading from v1.0? See [CHANGELOG.md](CHANGELOG.md).

**uban** (Universal Ban) is an open-source, ultra-lightweight, high-performance security daemon written in pure C99. It performs real-time log analysis and automatically enforces kernel-level IP bans using native `nftables` sets.

Designed as a modern, high-speed alternative to traditional log monitors like Fail2ban, `uban` avoids slow regex engines by using deterministic, token-based positional log matching. It operates with a minimal memory footprint and near-zero CPU overhead—making it ideal for high-traffic edge servers, cloud instances, and resource-constrained systems.

---

## Key Features

- **High Performance & Low Resource Footprint:** Steady-state memory footprint of **5–7 MB RAM** (including embedded SQLite page cache; drops to **~1 MB** when SQLite cache is reclaimed via `sync && echo 3 | sudo tee /proc/sys/vm/drop_caches`), with negligible CPU overhead under live production traffic.
- **Embedded SQLite Persistence (Zero External Dependencies):** Built-in WAL-mode SQLite database (`/var/lib/uban/uban.sqlite`) compiled directly into the `uban` binary via the SQLite C amalgamation (`sqlite3.c` / `sqlite3.h`)—no external database server or runtime library required.
- **Compile-Time Scalability & Customization:** Centralized system limits in `include/uban.h` (`MAX_JAILS`, `MAX_APPS`, `MAX_NAME_LEN`, `MAX_MATCH_PATTERNS`, etc.) allow operators to easily scale capacity boundaries prior to building.
- **Hardened Positional Parsing:** Token-based schema checking that resists log token injection and line-truncation attacks by validating status codes/keywords at deterministic left-anchored positions before user payload processing.
- **Kernel-Native Enforcement:** Direct integration with `nftables` (`inet uban_filter`) for line-rate packet dropping before packets reach the application layer.
- **App-Agnostic Engine:** Monitors any plain-text log stream (Nginx, Apache, SSHD, PostgreSQL, custom apps) using positional tokens or flexible full-line phrase scans.
- **Smart Offender Escalation & Snapshot Recovery:** Tracks repeat offenders across restarts in SQLite, exponentially scaling ban durations via `banfactor`, alongside automated prestart and on-demand `nftables` snapshots (`save_to_snapshot` / `restore_from_snapshot`).
- **Zero-Downtime Reloads (`SIGHUP`):** Hot-reload configuration changes and log handles (`logrotate`) without clearing active timers or dropping firewall protection for a single millisecond.

---

## Architecture Overview

```text
    +---------------+     +-------------------------+     +-----------------------+
    |   Log Files   | --> |  Real-Time Log Tailer   | --> |  C99 Token Evaluator  |
    +---------------+     +-------------------------+     +-----------------------+
                                                                      |
                          +-------------------------------------------+
                          |                           |
                          v                           v
            +---------------------------+   +--------------------------+
            |   Embedded SQLite & RAM   |   |   Kernel Enforcement     |
            |   (/var/lib/uban/*.sqlite)|   |  (nftables uban_filter)  |
            +---------------------------+   +--------------------------+
```
Unlike Python-based log monitors that parse complex regular expressions across whole lines, `uban` uses space-delimited and delimiter-aware token extraction (`""`, `()`, `[]`, `{}`, `<>`) combined with fast C string operations to inspect log lines in microseconds upon disk write.

---

## Benchmarks & Performance Comparison

Measured on Linux (Kernel 6.x) monitoring active web server logs under a 10,000 log lines/sec stress test:

| Metric | Fail2ban (Python) | **uban v1.1 (C99)** |
| :--- | :--- | :--- |
| **RAM Residency (Steady State)** | ~25 MB – 40 MB | **5 MB – 7 MB** *(~1 MB w/ SQLite cache reclaimed)* |
| **RAM Footprint (10k Log Lines/sec Stress Test)** | ~35 MB – 50 MB | **4 MB – 7 MB** |
| **CPU Usage (10k Log Lines/sec Stress Test)** | 25% – 60% CPU (35% avg) | **2% – 13% CPU (7% avg)** |
| **Action-to-Ban Latency (Match to Kernel Enforcement)** | 0.5s – 1.0s | **1ms – 10ms (avg ~5ms)** |
| **State Storage Backend** | External Python SQLite wrapper | **Embedded C SQLite (WAL Mode)** |
| **Firewall Backend** | `iptables` / `nftables` wrapper | **Native `nftables` Sets** |
| **Parsing Engine** | Regex scanning | **Positional C Tokenizer** |

*(Note: Most of `uban` v1.1's steady-state 5–7 MB RSS footprint is held by SQLite's internal page cache for fast disk-backed history lookups; invoking `sync && echo 3 | sudo tee /proc/sys/vm/drop_caches` reclaims cached pages and reduces active heap usage to ~1 MB.)*

---

## Quick Start & Installation

### Requirements

- **OS:** Linux (Kernel 3.13+)
- **Network:** IPv4 ONLY (v1.1 spec)
- **Firewall:** `nftables` (`nft` CLI utility installed)
- **Compiler & Build Tools:** `gcc` or `clang` (C99 support) and `make` (`build-essential` on Debian/Ubuntu)
- **Migration Utility (Upgrading from v1.0 only):** `sqlite3` CLI (only required if migrating legacy v1.0 flat state files during `sudo make install`)

### Building from Source

    # 1. Clone the repository
    git clone https://github.com/HandyDoctor/uban.git
    cd uban

    # 2. Build the binary (-O3 optimized)
    make

    # 3. Install binary, configuration, service unit, and logrotate handles
    sudo make install

### Starting the Service

    # Reload systemd and enable uban on boot
    sudo systemctl daemon-reload
    sudo systemctl enable --now uban

    # Verify service health
    sudo systemctl status uban

---

## Usage & CLI Reference

`uban` provides an intuitive CLI to view active bans, manage rules, capture firewall snapshots, or manually enforce IP bans.

### Basic Commands

    # View active kernel bans across all jails
    uban status

    # View detailed active bans with remaining TTL timers
    uban status -d

    # Filter status output by application or specific jail
    uban status -a nginx
    uban status -j nginx-403_404

    # Manually ban an IP for a specific jail (requires active daemon; supports 30m, 24h, 7d, 0=infinite)
    uban ban nginx-403_404 192.168.1.50 24h

    # Manually unban single or multiple IP addresses across all sets (requires active daemon)
    uban unban 192.168.1.50 10.0.0.8

    # Flush all active kernel bans (requires active daemon; preserves offender escalation history)
    uban flush

    # Full state reset (flushes kernel bans AND wipes historical SQLite records)
    uban flush --reset

    # Export live kernel nftables state to a permanent manual snapshot (online or offline)
    uban save_to_snapshot
    uban save_to_snapshot ~/uban_backup.dump

    # Reconcile and restore SQLite database from an nftables snapshot (daemon must be stopped)
    sudo systemctl stop uban
    sudo uban restore_from_snapshot
    sudo systemctl start uban

    # Check version or built-in help
    uban version
    uban help

*(Note: `ban`, `unban`, and `flush` communicate directly with the running daemon via runtime IPC at `/run/uban/uban.cmd` to prevent concurrent database/firewall race conditions, and require the `uban` service to be active.)*

### Daemon Control

    # Hot-reload configuration & re-open log handles (Zero downtime)
    sudo systemctl reload uban

    # Restart the service process (Captures prestart snapshot and re-syncs kernel rules)
    sudo systemctl restart uban

---

## Configuration Summary (`/etc/uban/uban.conf`)

`uban` uses a fast INI configuration file. For maximum security against log token injection and 8KB/syslog line truncation, configure your application logs to place the client IP and target status/keywords at **positive left-anchored offsets** (`1`, `2`, etc.) **before** any user-controlled payloads.

For complete technical details, hardened Nginx/Apache log schemas, and full jail examples, see `uban.conf` or visit the [Documentation Portal](https://amzdealshq.com/blog/category/uban/).

### Minimal Example Configuration

    [global]
    log_file = "/var/log/uban/uban.log"
    db_dir = "/var/lib/uban"
    poll_interval_ms = 10
    ignoreip = 127.0.0.1/8 100.74.125.235

    # Optional SQLite history purge & RAM runway ceiling (built-in defaults shown)
    db_purge_enable = true
    db_purge_age = 30d
    db_purge_interval = 1d
    max_track_ip = 10000

    [nginx]
    enabled = true

    # Excessive unauthorized / non-existent resource probes (hardened log format: $remote_addr $status ...)
    [nginx-403_404]
    enabled = true
    log_path = "/var/log/nginx/access.log"
    ip_pos = 1
    match_pos = 2
    match_string = "403", "404"
    max_retry = 10
    find_time = 5m
    ban_time = 1h
    banfactor = 2
    max_bantime = 2d

    [sshd]
    enabled = true

    # Flexible phrase scanning for human-readable keywords
    [sshd-retry]
    enabled = true
    log_path = "/var/log/auth.log"
    ip_pos = -4
    match_pos = 6
    match_string = "Failed password", "Invalid user"
    max_retry = 3
    find_time = 10m
    ban_time = 1h
    banfactor = 2
    max_bantime = 1y

---

## Logrotate Integration

`uban` integrates with system log rotation via `/etc/logrotate.d/uban`. It executes `systemctl reload uban` (`SIGHUP`) post-rotation to shift log file descriptors cleanly with zero dropped log lines and no RAM state reset.

---

## Directory Layout

| Path | Purpose |
| :--- | :--- |
| `/usr/local/bin/uban` | Compiled C executable (with embedded SQLite engine) |
| `/etc/uban/uban.conf` | Primary configuration and jail definitions |
| `/etc/uban/uban.help` | Built-in manual and CLI help source |
| `/etc/logrotate.d/uban` | Log rotation configuration |
| `/var/lib/uban/uban.sqlite` | Embedded ACID SQLite database (active bans & offender history) |
|`/var/lib/uban/uban.sqlite-wal` / `-shm` | SQLite Write-Ahead Log & shared-memory index (do not delete while running) |
| `/var/lib/uban/nftables_*.dump` | Automated prestart & manual `nftables` state snapshots |
| `/run/uban/uban.cmd` | Runtime IPC command interface for live CLI operations |
| `/var/log/uban/*.log` | Daemon execution and unban expiration logs |
| `assets/` | Project logos and protected website badges |

---

## Displaying the UBAN Protected Badge

If your server or web application is secured by `uban`, you can optionally display the **UBAN Protected** badge (available under `assets/`) in your website footer or site documentation. This is completely optional.

You can embed the badge on your website using the following HTML snippet:

    <a href="https://github.com/HandyDoctor/uban" target="_blank" rel="noopener noreferrer">
      <img src="dir_to_images/uban_protected.jpg" alt="Protected by UBAN Security Daemon" width="120" height="120" />
    </a>

---

## Acknowledgments

- **[SQLite](https://www.sqlite.org/):** `uban` embeds the public-domain SQLite C amalgamation (`sqlite3.c` / `sqlite3.h`) directly into its binary for fast, zero-configuration, ACID-compliant persistence.

---

## License & Copyright

Copyright © 2026 UBAN Security Engine Project.

This project, including its source code, documentation, and official project branding/logos (`assets/uban.jpg` and `assets/uban_protected.jpg`), is licensed under the **[MIT License](LICENSE)**. You are free to modify, distribute, and embed the project assets in accordance with the license terms.
