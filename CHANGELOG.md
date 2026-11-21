# Changelog

All notable changes to **uban** are documented in this file.

## [1.1.0] - 2026-11-19

### Added
- **Embedded SQLite Persistence Engine (Self-Contained Amalgamation):**
  - Migrated active ban tracking, countdown timers, and repeat-offender strike history from v1.0 flat state files to an embedded, ACID-compliant WAL-mode SQLite database (`/var/lib/uban/uban.sqlite`).
  - **Zero External Dependencies:** SQLite (`sqlite3.c` / `sqlite3.h`) is bundled directly in the source tree and compiled statically into the `uban` binary—no external SQLite libraries, development headers, or background database services are required.
  - `sudo make install` automatically detects legacy v1.0 state files in `/var/lib/uban` and migrates them into `uban.sqlite` via `scripts/db_migration.sh`.
- **On-Demand Manual Snapshots (`uban save_to_snapshot [path]`):**
  - Export live kernel `nftables` state at any time (online or offline).
  - Supports automatic timestamped naming (`nftables_manual_YYYYMMDD_HHMMSS.dump` in `/var/lib/uban/`), bare filenames, relative paths (`./`), absolute paths, and `~/` home directory expansion.
  - Manual snapshots are permanently retained and excluded from the 5-file rolling prestart retention pruning.
- **Snapshot Disaster Recovery (`uban restore_from_snapshot [dump_file]`):**
  - Reconcile and restore `uban.sqlite` from a kernel `nftables` snapshot file (defaults to the latest automated prestart dump if omitted).
  - Parses embedded creation timestamps from `nftables_prestart_*.dump` and `nftables_manual_*.dump` files to calculate snapshot age and preserve remaining ban durations. Custom/static filenames fall back to raw static timeouts calculated from the current time.
  - Requires the `uban` daemon to be stopped prior to execution to prevent SQLite lock contention and state race conditions.
- **SQLite History Retention & Purge Directives (`[global]`):**
  - `db_purge_enable`: Enable periodic cleanup of inactive records (`ban_end == -1`).
  - `db_purge_age`: Maximum retention age for inactive records (default: `30d`).
  - `db_purge_interval`: Interval between cleanup runs (default: `1d`).
- **Memory Runway Ceiling (`[global]`):**
  - `max_track_ip`: Caps imminent expiration records held in the 5-minute RAM runway queue (default: `10000`).

### Changed
- **IPC Command Architecture & Daemon Liveness Guards (`ban`, `unban`, `flush`):**
  - In v1.0, `ban`, `unban`, and `flush` spawned standalone CLI processes that modified flat state files and `nftables` directly, allowing execution while the service was stopped.
  - In v1.1, these commands dispatch via runtime IPC (`/run/uban/uban.cmd`) directly to the single active daemon process to eliminate concurrent state/firewall race conditions.
  - **Architectural Trade-off:** `ban`, `unban`, and `flush` now require the `uban` daemon to be running and will fail immediately if executed while the service is offline.
- **Hardened Log Parsing Documentation (`uban.conf`):** Emphasized left-anchored positive offsets (`ip_pos`, `match_pos`) preceding user-controlled payloads and documented buffer-truncation risks with negative right-based offsets (`-1`, `-2`).

### Fixed
- **CIDR Subnet Whitelisting (`ignoreip`):** Fixed a bug in v1.0 where IPv4 CIDR subnet ranges (e.g., `127.0.0.1/8`, `10.0.0.0/8`, `192.168.1.0/24`) in `[global]` or jail-level `ignoreip` lists failed to match incoming IPs. Both single IPv4 addresses and CIDR subnet masks are now properly evaluated.

---

### Upgrading from v1.0 to v1.1

#### 1. Compile the v1.1 Binary
Compile the new binary while v1.0 continues running. Only standard C build tools (`build-essential` or `gcc` + `make`) are required:

```bash
git pull
make clean && make
```
*(Minimal prod hosts: you may build on a matching architecture host and copy the standalone `uban` binary over.)*

#### 2. Capture a Pre-Upgrade Snapshot (Optional)
```bash
sudo nft -j list table inet uban_filter > ~/uban_v1.0_backup.dump
```

#### 3. Add New v1.1 Directives to `/etc/uban/uban.conf` (Optional)
If omitted, `uban` falls back to these exact built-in defaults. Add them under `[global]` if you wish to tune them:

```ini
# --- Database History Purge Settings ---
db_purge_enable = true
db_purge_age = 30d
db_purge_interval = 1d

# --- Memory Safety Ceiling ---
max_track_ip = 10000
```

#### 4. Stop v1.0, Install v1.1, and Migrate State
```bash
sudo systemctl stop uban
sudo make install
```
* `make install` updates the `uban` binary and `/etc/uban/uban.help` while preserving `/etc/uban/uban.conf`.
* `scripts/db_migration.sh` requires the `sqlite3` CLI (`apt install sqlite3` / `dnf install sqlite`) to convert legacy v1.0 state files into `/var/lib/uban/uban.sqlite`. Alternatively, copy `/var/lib/uban/` to another host with `sqlite3`, run `scripts/db_migration.sh`, and copy `uban.sqlite` back.

#### 5. Review Log Offset Positions (Recommended)
Ensure `ip_pos` and `match_pos` use positive left-based offsets placed **before** user-controlled request strings or headers to prevent token displacement and line truncation.

#### 6. Start v1.1 and Verify
```bash
sudo systemctl start uban
sudo uban status -d
```

---

## [1.0.0] - Initial Release (2026-10-25)
- Real-time log tailing with `nftables` (`inet uban_filter`) kernel enforcement.
- Positional token extraction (`ip_pos`, `match_pos`) and full-line phrase matching.
- Flat state file persistence with strike escalation (`banfactor`, `max_bantime`).
- CLI management (`status`, `ban`, `unban`, `flush`, `version`, `help`).
