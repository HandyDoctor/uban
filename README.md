# uban — Universal Ban Daemon for Linux

<p align="center">
  <img src="assets/uban.jpg" alt="UBAN Logo" width="220" />
</p>

[![Language](https://img.shields.io/badge/language-C99-blue.svg)](https://en.cppreference.com/w/c/99)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(nftables)-orange.svg)](https://netfilter.org/projects/nftables/)

**uban** (Universal Ban) is an open-source, ultra-lightweight, high-performance security daemon written in pure C99. It performs real-time log analysis and automatically enforces kernel-level IP bans using native `nftables` sets.

Designed as a modern, high-speed alternative to traditional log monitors like Fail2ban, `uban` avoids slow regex engines by using deterministic, token-based positional log matching. It operates with a near-zero memory footprint and minimal CPU overhead—making it ideal for high-traffic edge servers, cloud instances, and resource-constrained systems.

---

## Key Features

- **High Performance & Low Resource Footprint:** Steady-state memory footprint of **~600 KB RAM** (peaking at **4–7 MB** under 10k log lines/sec stress tests) with negligible CPU overhead under live production traffic.
- **Compile-Time Scalability & Customization:** Centralized system limits in `include/uban.h` (`MAX_JAILS`, `MAX_APPS`, `MAX_NAME_LEN`, `MAX_TRACKED_IPS`, etc.) allow operators to easily scale capacity boundaries to fit high-throughput or massive multi-tenant deployment needs prior to building.
- **Hardened Positional Parsing:** Token-based schema checking that resists log token injection attacks by validating status codes at deterministic positions before user payload processing.
- **Kernel-Native Enforcement:** Direct integration with `nftables` (`inet uban_filter`) for line-rate packet dropping before packets reach the application layer.
- **App-Agnostic Engine:** Monitors any plain-text log stream (Nginx, Apache, SSHD, PostgreSQL, custom apps) using positional tokens or flexible full-line phrase scans.
- **Smart Offender Escalation:** Tracks repeat offenders across restarts using persistent state tracking (`/var/lib/uban`), exponentially scaling ban durations via `banfactor`.
- **Zero-Downtime Reloads (`SIGHUP`):** Hot-reload configuration changes and log handles (`logrotate`) without clearing active in-memory timers or dropping firewall protection for a single millisecond.
- **TTL Persistence Across Reboots:** State tracking ensures active kernel bans and exact remaining TTLs survive service reboots.

---

## Architecture Overview

+---------------+     +-------------------------+     +-----------------------+
|  Log Files    | --> | Real-Time Log Tailer    | --> | C99 Token Evaluator   |
+---------------+     +-------------------------+     +-----------------------+
                                                                  |
                                              +-------------------+-------------------+
                                              |                                       |
                                              v                                       v
                                +---------------------------+           +--------------------------+
                                | Memory & TTL Tracking     |           | Kernel Enforcement       |
                                | (/var/lib/uban/*.db)      |           | (nftables uban_filter)   |
                                +---------------------------+           +--------------------------+

Unlike Python-based log monitors that parse complex regular expressions across whole lines, `uban` uses space-delimited and delimiter-aware token extraction (`""`, `()`, `[]`, `{}`, `<>`) combined with fast C string operations to inspect log lines in microseconds upon disk write.

---

## Benchmarks & Performance Comparison

Measured on Linux (Kernel 6.x) monitoring active web server logs under a 10,000 log lines/sec stress test:

| Metric | Fail2ban (Python) | **uban (C99)** |
| :--- | :--- | :--- |
| **RAM Residency (Steady State)** | ~25 MB – 40 MB | **~600 KB** |
| **RAM Footprint (10k Log Lines/sec Stress Test)** | ~35 MB – 50 MB | **4 MB – 7 MB** |
| **CPU Usage (10k Log Lines/sec Stress Test)** | 25% – 60% CPU (35% avg) | **2% – 13% CPU (7% avg)** |
| **Action-to-Ban Latency (Match to Kernel Enforcement)** | 0.5s – 1.0s | **1ms – 10ms (avg ~5ms)** |
| **Firewall Backend** | `iptables` / `nftables` wrapper | Native `nftables` Sets |
| **Parsing Engine** | Regex scanning | Positional C Tokenizer |

---

## Quick Start & Installation

### Requirements

- **OS:** Linux (Kernel 3.13+)
- **Network:** IPv4 ONLY (v1.0 spec)
- **Firewall:** `nftables` (`nft` CLI utility installed)
- **Compiler:** `gcc` or `clang` (C99 support)
- **Build Tools:** `make`

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

`uban` provides an intuitive CLI to view active bans, manage rules, or manually enforce IP bans.

### Basic Commands

    # View active kernel bans across all jails
    uban status

    # View detailed active bans with remaining TTL timers
    uban status -d

    # Filter status output by application or specific jail
    uban status -a nginx
    uban status -j nginx-403_404

    # Manually ban an IP for a specific jail (supports 30m, 24h, 7d, 0=infinite)
    uban ban nginx-403_404 192.168.1.50 24h

    # Manually unban single or multiple IP addresses across all sets
    uban unban 192.168.1.50 10.0.0.8

    # Flush all active kernel bans (preserves offender escalation history)
    uban flush

    # Full state reset (flushes kernel bans AND wipes historical records)
    uban flush --reset

### Daemon Control

    # Hot-reload configuration & re-open log handles (Zero downtime)
    sudo systemctl reload uban

    # Restart the service process (Saves state snapshot to disk and reboots)
    sudo systemctl restart uban

---

## Configuration Summary (`/etc/uban/uban.conf`)

`uban` uses a fast INI configuration file. Below is a minimal example demonstrating core syntax. For complete technical details, edge cases, and full jail examples, see `uban.conf.example` or visit the [Documentation Portal](https://amzdealshq.com/blog/category/uban/).

### Minimal Example Configuration

    [global]
    log_file = "/var/log/uban/uban.log"
    db_dir = "/var/lib/uban"
    poll_interval_ms = 10
    ignoreip = 127.0.0.1/8 100.74.125.235

    [nginx]
    enabled = true

    # Excessive unauthorized / non-existent resource probes
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
| `/usr/local/bin/uban` | Compiled C executable |
| `/etc/uban/uban.conf` | Primary configuration and jail definitions |
| `/etc/uban/uban.help` | Built-in manual and CLI help source |
| `/etc/logrotate.d/uban` | Log rotation configuration |
| `/var/lib/uban/*.db` | Historical offender tracking and escalation state |
| `/var/lib/uban/bans.state` | Active ban snapshot for reboot persistence |
| `/var/log/uban/*.log` | Daemon execution and unban expiration logs |
| `assets/` | Project logos and protected website badges |

---

## Displaying the UBAN Protected Badge

If your server or web application is secured by `uban`, you can optionally display the **UBAN Protected** badge in your website footer or site documentation. This is completely optional.

You can embed the badge on your website using the following HTML snippet:

    <a href="https://github.com/HandyDoctor/uban" target="_blank" rel="noopener noreferrer">
      <img src="dir_to_images/uban_protected.jpg" alt="Protected by UBAN Security Daemon" width="120" height="120" />
    </a>

---

## License & Copyright

Copyright © 2026 UBAN Security Engine Project.

This project, including its source code, documentation, and official project branding/logos (`assets/uban.jpg` and `assets/uban_protected.jpg`), is licensed under the **[MIT License](LICENSE)**. You are free to modify, distribute, and embed the project assets in accordance with the license terms.
