/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        firewall.c
 * Description: Kernel-level nftables netlink/CLI wrapper, snapshot dumper, and sync engine.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"
#include <dirent.h>
#include <stdbool.h>

static int parse_nft_duration(const char *dur_str) {
    int total_sec = 0;
    int current_num = 0;

    for (int i = 0; dur_str[i] != '\0'; i++) {
        if (isdigit((unsigned char)dur_str[i])) {
            current_num = current_num * 10 + (dur_str[i] - '0');
        } else {
            if ((dur_str[i] == 'm' || dur_str[i] == 'M') && 
                (dur_str[i+1] == 's' || dur_str[i+1] == 'S')) {
                if (current_num >= 500) total_sec += 1;
                current_num = 0;
                i++;
                continue;
            }

            if (dur_str[i] == 's' || dur_str[i] == 'S') total_sec += current_num;
            else if (dur_str[i] == 'm' || dur_str[i] == 'M') total_sec += current_num * 60;
            else if (dur_str[i] == 'h' || dur_str[i] == 'H') total_sec += current_num * 3600;
            else if (dur_str[i] == 'd' || dur_str[i] == 'D') total_sec += current_num * 86400;
            current_num = 0;
        }
    }
    return total_sec;
}

int firewall_init(const Config *config) {
    if (!config) return -1;

    int res = system("nft add table inet uban_filter 2>/dev/null");
    (void)res;

    res = system("nft add chain inet uban_filter input '{ type filter hook input priority -100; policy accept; }' 2>/dev/null");
    (void)res;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        if (!j || strlen(j->nft_set_name) == 0) continue;

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "nft add set inet uban_filter %s '{ type ipv4_addr; flags timeout; }' 2>/dev/null", j->nft_set_name);
        res = system(cmd);

        snprintf(cmd, sizeof(cmd), "nft add rule inet uban_filter input ip saddr @%s drop 2>/dev/null", j->nft_set_name);
        res = system(cmd);
    }
    (void)res;
    return 0;
}

int firewall_ban_ip(const char *set_name, const char *ip, int bantime) {
    char cmd[512];
    if (bantime > 0) {
        snprintf(cmd, sizeof(cmd), "nft add element inet uban_filter %s '{ %s timeout %ds }' 2>/dev/null", set_name, ip, bantime);
    } else {
        snprintf(cmd, sizeof(cmd), "nft add element inet uban_filter %s '{ %s }' 2>/dev/null", set_name, ip);
    }
    return system(cmd);
}

int firewall_unban_ip_all(const Config *config, const char *ip, int *out_ori_duration, char *out_jail_name) {
    int unbanned_count = 0;
    if (out_ori_duration) *out_ori_duration = 0;
    if (out_jail_name) out_jail_name[0] = '\0';

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "nft delete element inet uban_filter %s '{ %s }' 2>/dev/null", j->nft_set_name, ip);
        if (system(cmd) == 0) {
            unbanned_count++;
            if (out_jail_name && out_jail_name[0] == '\0') {
                safe_strncpy(out_jail_name, j->name, MAX_NAME_LEN);
            }
        }
    }
    return unbanned_count;
}

int firewall_get_ip_remaining_ttl(const char *set_name, const char *ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nft get element inet uban_filter %s '{ %s }' 2>/dev/null", set_name, ip);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char buffer[2048] = "";
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    buffer[bytes_read] = '\0';
    pclose(fp);

    if (strlen(buffer) == 0) return -1;

    char *saveptr = NULL;
    char *token = strtok_r(buffer, " \t\n,{}", &saveptr);
    while (token) {
        if (strcmp(token, "expires") == 0) {
            token = strtok_r(NULL, " \t\n,{}", &saveptr);
            if (token) return parse_nft_duration(token);
        }
        token = strtok_r(NULL, " \t\n,{}", &saveptr);
    }

    return -1;
}

int firewall_flush_jail(const Config *config, const char *nft_set_name) {
    (void)config;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nft flush set inet uban_filter %s >/dev/null 2>&1", nft_set_name);
    return system(cmd);
}

int firewall_flush_all(const Config *config) {
    int flushed_jails = 0;
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        if (firewall_flush_jail(config, j->nft_set_name) == 0) flushed_jails++;
    }
    return flushed_jails;
}

int firewall_get_banned_ips(const char *set_name, BanStatusItem **items, int *count) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nft list set inet uban_filter %s 2>/dev/null", set_name);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        *count = 0;
        *items = NULL;
        return -1;
    }

    int capacity = 64;
    *count = 0;
    *items = (BanStatusItem*)calloc(capacity, sizeof(BanStatusItem));

    char line[1024];
    char current_ip[MAX_IP_LEN] = "";
    int current_expires = -1;
    int current_timeout = -1;

    while (fgets(line, sizeof(line), fp)) {
        char *saveptr = NULL;
        char *token = strtok_r(line, " \t\n,{}", &saveptr);

        while (token) {
            struct in_addr sa;

            if (inet_pton(AF_INET, token, &sa) == 1) {
                if (strlen(current_ip) > 0) {
                    if (*count >= capacity) {
                        capacity *= 2;
                        *items = (BanStatusItem*)realloc(*items, capacity * sizeof(BanStatusItem));
                    }
                    safe_strncpy((*items)[*count].ip, current_ip, sizeof((*items)[*count].ip));
                    (*items)[*count].expires_in_sec = current_expires;
                    (*items)[*count].original_timeout_sec = current_timeout;
                    (*count)++;
                }
                safe_strncpy(current_ip, token, sizeof(current_ip));
                current_expires = -1;
                current_timeout = -1;
            } else if (strcmp(token, "timeout") == 0) {
                token = strtok_r(NULL, " \t\n,{}", &saveptr);
                if (token) current_timeout = parse_nft_duration(token);
            } else if (strcmp(token, "expires") == 0 && strlen(current_ip) > 0) {
                token = strtok_r(NULL, " \t\n,{}", &saveptr);
                if (token) current_expires = parse_nft_duration(token);
            }

            token = strtok_r(NULL, " \t\n,{}", &saveptr);
        }
    }

    if (strlen(current_ip) > 0) {
        if (*count >= capacity) {
            capacity *= 2;
            *items = (BanStatusItem*)realloc(*items, capacity * sizeof(BanStatusItem));
        }
        safe_strncpy((*items)[*count].ip, current_ip, sizeof((*items)[*count].ip));
        (*items)[*count].expires_in_sec = current_expires;
        (*items)[*count].original_timeout_sec = current_timeout;
        (*count)++;
    }

    pclose(fp);
    return 0;
}

void firewall_free_status_items(BanStatusItem *items) {
    if (items) free(items);
}

/* ==============================================================================
 * SNAPSHOT BACKUP & ROTATION (PRE-START DUMP, RETAIN TOP 5; 	MANUAL DUMP, RETAIN FOREVER)
 * ============================================================================== */

int firewall_dump_snapshot(const Config *config, char *out_snapshot_path, size_t path_size, bool manual) {
    if (!config || strlen(config->db_dir) == 0) return -1;

    char dump_file[MAX_PATH_LEN + 128];
    char tmp_file[MAX_PATH_LEN + 136];

    // 1. Determine destination path: custom name, generated manual name, or default auto name
    if (out_snapshot_path && out_snapshot_path[0] != '\0') {
        if (out_snapshot_path[0] == '~') {
            const char *home = getenv("HOME");
            if (!home || home[0] == '\0') {
                log_msg("ERROR", "[SNAPSHOT] Unable to expand '~': HOME environment variable not set.");
                return -1;
            }
            // Skip the leading '~' and handle whether a slash follows (e.g. "~/file" vs "~")
            const char *subpath = out_snapshot_path + 1;
            if (*subpath == '/') subpath++;

            snprintf(dump_file, sizeof(dump_file), "%s/%s", home, subpath);
        } else if (out_snapshot_path[0] == '/' || strchr(out_snapshot_path, '/') != NULL) {
            // Absolute (/var/...) or explicit relative (./dumps/..., sub/dir/...)
            snprintf(dump_file, sizeof(dump_file), "%s", out_snapshot_path);
        } else {
            // Plain filename provided: place inside db_dir
            snprintf(dump_file, sizeof(dump_file), "%s/%s", config->db_dir, out_snapshot_path);
        }
    } else {
        time_t now = time(NULL);
        struct tm tm_info;
        localtime_r(&now, &tm_info);

        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", &tm_info);

        const char *prefix = manual ? "nftables_manual" : "nftables_prestart";
        snprintf(dump_file, sizeof(dump_file), "%s/%s_%s.dump", config->db_dir, prefix, time_str);
    }

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", dump_file);

    // 2. Resolve nftables binary location
    const char *nft_bin = "/usr/sbin/nft";
    if (access(nft_bin, X_OK) != 0) {
        nft_bin = "/sbin/nft";
        if (access(nft_bin, X_OK) != 0) {
            nft_bin = "nft";
        }
    }

    char cmd[MAX_PATH_LEN + 256];
    snprintf(cmd, sizeof(cmd), "%s -j list table inet uban_filter 2>/dev/null", nft_bin);

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        log_msg("ERROR", "[SNAPSHOT] Failed to invoke popen for command: %s", cmd);
        return -1;
    }

    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        pclose(pipe);
        log_msg("ERROR", "[SNAPSHOT] Unable to open %s for writing.", tmp_file);
        return -1;
    }

    char buf[4096];
    size_t bytes_read;
    long total_bytes = 0;

    while ((bytes_read = fread(buf, 1, sizeof(buf), pipe)) > 0) {
        fwrite(buf, 1, bytes_read, out);
        total_bytes += bytes_read;
    }

    int pclose_rc = pclose(pipe);
    fclose(out);

    // 3. Validate output before committing
    if (pclose_rc != 0 || total_bytes == 0) {
        unlink(tmp_file);
        log_msg("DEBUG", "[SNAPSHOT] Snapshot capture discarded: exit=%d, bytes=%ld", pclose_rc, total_bytes);
        return -1;
    }

    if (rename(tmp_file, dump_file) != 0) {
        unlink(tmp_file);
        log_msg("ERROR", "[SNAPSHOT] Failed to commit snapshot rename: %s -> %s", tmp_file, dump_file);
        return -1;
    }

    // 4. Return the resolved final path to caller if buffer is available
    if (out_snapshot_path && path_size > 0) {
        safe_strncpy(out_snapshot_path, dump_file, path_size);
    }

    log_msg("INFO", "[SNAPSHOT] Created firewall state snapshot at %s (%ld bytes).", dump_file, total_bytes);
    return 0;
}

static int compare_dump_filenames_desc(const void *a, const void *b) {
    const char *fa = *(const char **)a;
    const char *fb = *(const char **)b;
    return strcmp(fb, fa); // Descending order (newest timestamp first)
}

void firewall_prune_snapshots(const Config *config, int keep_count) {
    DIR *dir = opendir(config->db_dir);
    if (!dir) return;

    char **dumps = NULL;
    int count = 0;
    int capacity = 16;
    dumps = (char **)malloc(capacity * sizeof(char *));

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "nftables_prestart_", 18) == 0 &&
            strstr(entry->d_name, ".dump") != NULL) {
            if (count >= capacity) {
                capacity *= 2;
                dumps = (char **)realloc(dumps, capacity * sizeof(char *));
            }
            dumps[count++] = strdup(entry->d_name);
        }
    }
    closedir(dir);

    if (count > keep_count) {
        qsort(dumps, count, sizeof(char *), compare_dump_filenames_desc);
        for (int i = keep_count; i < count; i++) {
            char remove_path[MAX_PATH_LEN + 128];
            snprintf(remove_path, sizeof(remove_path), "%s/%s", config->db_dir, dumps[i]);
            unlink(remove_path);
            log_msg("INFO", "[SNAPSHOT] Pruned old snapshot: %s", dumps[i]);
        }
    }

    for (int i = 0; i < count; i++) free(dumps[i]);
    free(dumps);
}

/* ==============================================================================
 * DATABASE TO KERNEL SYNCHRONIZATION
 * ============================================================================== */

int firewall_sync_from_db(const Config *config) {
    char db_path[MAX_PATH_LEN + 32];
    snprintf(db_path, sizeof(db_path), "%s/uban.sqlite", config->db_dir);

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        return -1;
    }

    const char *sql = 
        "SELECT ip, jail, ban_end "
        "FROM uban_records "
        "WHERE ban_end = 0 OR ban_end > strftime('%s', 'now');";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    int synced = 0;
    time_t now = time(NULL);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *ip = (const char*)sqlite3_column_text(stmt, 0);
        const char *jail_name = (const char*)sqlite3_column_text(stmt, 1);
        long long ban_end = sqlite3_column_int64(stmt, 2);

        const Jail *j = find_jail_by_name(config, jail_name);
        if (!j) continue;

        if (ban_end == 0) {
            firewall_ban_ip(j->nft_set_name, ip, 0);
            synced++;
        } else {
            long long remaining = ban_end - now;
            if (remaining > 0) {
                firewall_ban_ip(j->nft_set_name, ip, (int)remaining);
                synced++;
            }
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (synced > 0) {
        log_msg("INFO", "[FIREWALL] Synced %d active bans from database into nftables.", synced);
    }
    return synced;
}
