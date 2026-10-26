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

#define UBAN_VERSION "1.0.0"

#define MAX_IP_LEN 46
#define MAX_LINE_LEN 8192
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 64
#define MAX_MATCH_LEN 128
#define MAX_JAILS 32
#define MAX_APPS 16
#define MAX_MATCH_PATTERNS 16
#define MAX_TRACKED_IPS 50000
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

/* Persistent offender historical record tracked in RAM */
typedef struct OffenderRecord {
    char ip[MAX_IP_LEN];
    char jail_name[MAX_NAME_LEN];
    int offense_count;
    bool dirty;
    struct OffenderRecord *next;
} OffenderRecord;

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

/* In-memory active ban node tracking */
typedef struct ActiveBanNode {
    char ip[MAX_IP_LEN];
    char jail_name[MAX_NAME_LEN];
    char set_name[MAX_MATCH_LEN];
    uint64_t expire_ms;         // Absolute epoch time in milliseconds when ban expires
    int ban_duration;           // Stored original ban duration in seconds
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
int firewall_save_state(const Config *config);
int firewall_restore_state(const Config *config);

/* Evaluator & Offender RAM State management functions (src/evaluator.c) */
void offender_db_init(const Config *config);
void sync_db_files_on_startup(const Config *config);
void offender_db_sync_to_disk(const Config *config);
int offender_db_get_count(const char *jail_name, const char *ip);
int offender_db_increment(const char *jail_name, const char *ip);
void evaluate_entry(const LogEntry *entry, const Jail *jail, const char *matched_ip, Config *config);
int calculate_incremental_ban(const Config *config, const Jail *jail, const char *ip, int offender_count);
void register_active_ban(const char *ip, const char *jail_name, const char *set_name, int duration_sec, uint64_t expire_ms);
void remove_active_ban_from_ram(const char *set_name, const char *ip);
void clear_all_ip_trackers(void);
void offender_db_reload(const Config *config);
void offender_db_wipe_all(const Config *config);

/* Log parser function (src/log_parser.c) */
bool parse_log_line(const char *line, const Jail *jail, char *extracted_ip);

/* Log tailer function (src/log_tailer.c) */
int tail_log(const Config *config);
void clear_active_bans_ram(void);
int get_active_ban_duration(const char *set_name, const char *ip);

#endif /* UBAN_H */
