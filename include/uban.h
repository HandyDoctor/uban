/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        uban.h
 * Description: Global data structures, state constants, and function prototypes.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#ifndef UBAN_H
#define UBAN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sqlite3.h>

#define UBAN_VERSION "1.1.0"

#define UBAN_RUN_DIR    "/run/uban"
#define UBAN_STAT_FILE  "/run/uban/uban.stat"
#define UBAN_CMD_FILE   "/run/uban/uban.cmd"

#define MAX_IP_LEN 46
#define MAX_LINE_LEN 8192
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 64
#define MAX_MATCH_LEN 128
#define MAX_JAILS 32
#define MAX_APPS 16
#define MAX_MATCH_PATTERNS 16
#define MAX_TRACKED_IPS 10000
#define TEN_YEARS_SEC 315360000
#define MAX_IGNOREIP_LEN 256

static inline uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // Use CLOCK_MONOTONIC to avoid clock jump glitches
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

// Safe string copy helper
static inline void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

/* Event node tracking log occurrences */
typedef struct EventNode {
    uint64_t timestamp_ms;
    char jail_name[MAX_NAME_LEN];
    struct EventNode *next;
} EventNode;

/* IP tracking entry holding linked list of events */
typedef struct IPEntry {
    char ip[MAX_IP_LEN];
    EventNode *events;
    time_t last_ban_timestamp;
    struct IPEntry *next;
} IPEntry;

typedef struct ActiveBanNode {
    char ip[MAX_IP_LEN];
    char jail_name[MAX_NAME_LEN];
    char set_name[MAX_MATCH_LEN];
    uint64_t expire_ms;         // Absolute monotonic time in milliseconds when ban expires
    long long ban_end;          // Epoch timestamp when ban expires (0 for permanent)
    int ban_duration;           // Stored original ban duration in seconds
    int offense_count;          // Cumulative offense count maintained in RAM
    bool is_max_ban;            // True if ban duration reached max_bantime or permanent
    bool dirty;                 // Needs sync to SQLite at 60s tick or shutdown
    struct ActiveBanNode *next;
} ActiveBanNode;

/* Application configuration structure */
typedef struct {
    char name[MAX_NAME_LEN];
    bool enabled;
} AppConfig;

/* Jail configuration structure */
typedef struct {
    char name[MAX_NAME_LEN];
    char app_name[MAX_NAME_LEN];
    char nft_set_name[MAX_MATCH_LEN];
    char logpath[MAX_PATH_LEN];
    char ignoreip[MAX_IGNOREIP_LEN];
    int maxretry;
    int findtime;
    int bantime;
    int banfactor;      // Multiplier factor (e.g., 2, 3)
    int max_bantime;    // Maximum ban time cap in seconds
    int ip_pos;         // +1 left-based, -1 right-based
    int match_pos;      // Used for short patterns <= 5 chars
    char match_strings[MAX_MATCH_PATTERNS][MAX_MATCH_LEN];
    int match_count;
    bool enabled;
} Jail;

/* Global application configuration structure */
typedef struct {
    char default_ignoreip[MAX_IGNOREIP_LEN];
    Jail jails[MAX_JAILS];
    int jail_count;
    AppConfig apps[MAX_APPS];
    int app_count;
    int poll_interval_ms;
    char uban_logpath[MAX_PATH_LEN];
    char db_dir[MAX_PATH_LEN];
    int default_banfactor;   // Global default escalation factor (e.g. 2)
    int default_max_bantime; // Global default max cap (e.g. 1 year in secs)
    char firewall_backend[MAX_NAME_LEN];
    bool db_purge_enable;    // Enable periodic purge of inactive records
    int db_purge_age;        // Max age in seconds for inactive records (default: 30d)
    int db_purge_interval;   // Purge interval in seconds (default: 1d)
    int max_track_ip;        // Ceiling of records held in RAM runway queue (default: 10000)
} Config;

/* Parsed log evaluation entry */
typedef struct {
    char raw_line[MAX_LINE_LEN];
    uint64_t timestamp_ms;
} LogEntry;

/* Banned IP status item structure */
typedef struct {
    char ip[MAX_IP_LEN];
    int expires_in_sec;
    int original_timeout_sec;
    time_t ban_timestamp;
} BanStatusItem;

/* Configuration functions (src/config.c) */
int load_config(const char *filename, Config *config);

/* Logging & Utility functions (src/logger.c) */
void set_log_path(const char *path);
void log_msg(const char *level, const char *fmt, ...);
int parse_duration(const char *str);

/* Firewall management functions (src/firewall.c) */
int firewall_init(const Config *config);
int firewall_ban_ip(const char *set_name, const char *ip, int bantime);
int firewall_unban_ip_all(const Config *config, const char *ip, int *out_ori_duration, char *out_jail_name);
int firewall_flush_jail(const Config *config, const char *nft_set_name);
int firewall_flush_all(const Config *config);
int firewall_get_banned_ips(const char *set_name, BanStatusItem **items, int *count);
int firewall_get_ip_remaining_ttl(const char *set_name, const char *ip);
void firewall_free_status_items(BanStatusItem *items);
int firewall_dump_snapshot(const Config *config, char *out_snapshot_path, size_t path_size, bool manual);
void firewall_prune_snapshots(const Config *config, int keep_count);
int firewall_sync_from_db(const Config *config);

/* SQLite Database & Evaluation functions (src/evaluator.c) */
int uban_db_init(const Config *config);
void uban_db_close(void);
int uban_db_get_record(const char *jail_name, const char *ip, int *out_count, long long *out_ban_end, int *out_orig_ban_time);
int uban_db_upsert_ban(const char *jail_name, const char *ip, long long ban_end, int orig_ban_time, int *out_new_count);
int uban_db_mark_inactive(const char *jail_name, const char *ip);
int uban_db_unban_ip_all(const char *ip);
int uban_db_flush_jail(const char *jail_name, bool reset);
int uban_db_flush_all(bool reset);
void uban_db_purge_orphans(const Config *config);
int uban_db_load_runway(const Config *config, int max_capacity);
int uban_db_purge_history(const Config *config);
int uban_db_get_counts(const Config *config, const char *target_app, const char *target_jail, int *out_active, int *out_total);
int get_ram_runway_count(const Config *config, const char *target_app, const char *target_jail);
void evaluate_entry(const LogEntry *entry, const Jail *jail, const char *matched_ip, Config *config);
int calculate_incremental_ban(const Config *config, const Jail *jail, const char *ip, int offender_count);
void register_active_ban(const char *ip, const char *jail_name, const char *set_name, int duration_sec, uint64_t expire_ms);
void remove_active_ban_from_ram(const char *set_name, const char *ip);
void clear_all_ip_trackers(void);
void prune_stale_ip_trackers(void);
const Jail* find_jail_by_name(const Config *config, const char *jail_name);
int uban_db_flush_ram_state(void);
int uban_db_mark_expired(time_t now);
int uban_db_get_runway_count(const Config *config, const char *target_app, const char *target_jail);

/* Log parser function (src/log_parser.c) */
bool parse_log_line(const char *line, const Jail *jail, char *extracted_ip);

/* Log tailer function (src/log_tailer.c) */
int tail_log(const Config *config);
void clear_active_bans_ram(void);
int get_active_ban_duration(const char *set_name, const char *ip);
int get_active_bans_count(void);
ActiveBanNode* find_active_ban(const char *jail_name, const char *ip);
void register_active_ban_full(const char *ip, const char *jail_name, const char *set_name, 
                              int duration_sec, uint64_t expire_ms, long long ban_end, 
                              int offense_count, bool is_max_ban, bool dirty);
void prune_active_bans_distant(time_t cutoff_epoch);
ActiveBanNode* get_active_bans_head(void);
void sync_ram_stats_file(const Config *config);

/*  Commands for CLI functions (src/commands.c) */
int init_command_listener(void);
void process_queued_commands(const Config *config);
int send_cli_command(const char *cmd_line);

#endif /* UBAN_H */
