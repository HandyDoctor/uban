/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        log_tailer.c
 * Description: Real-time file descriptor tailer, runway queue manager, and scheduler.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#define _DEFAULT_SOURCE
#include "uban.h"
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>

static ActiveBanNode *g_active_bans = NULL;

void sync_ram_stats_file(const Config *config) {
    if (!config) return;

    FILE *fp = fopen(UBAN_STAT_FILE, "w");
    if (!fp) return;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        int count = 0;
        for (ActiveBanNode *n = g_active_bans; n; n = n->next) {
            if (strcmp(n->jail_name, j->name) == 0 && (n->ban_end == 0 || n->ban_end > 0)) {
                count++;
            }
        }
        fprintf(fp, "%s %d\n", j->name, count);
    }

    fclose(fp);
}

void clear_active_bans_ram(void) {
    ActiveBanNode *curr = g_active_bans;
    while (curr) {
        ActiveBanNode *next = curr->next;
        free(curr);
        curr = next;
    }
    g_active_bans = NULL;
}

int get_active_bans_count(void) {
    int count = 0;
    ActiveBanNode *scan = g_active_bans;
    while (scan) {
        if (scan->ban_end == 0 || scan->ban_end > 0) {
            count++;
        }
        scan = scan->next;
    }
    return count;
}

ActiveBanNode* get_active_bans_head(void) {
    return g_active_bans;
}

ActiveBanNode* find_active_ban(const char *jail_name, const char *ip) {
    ActiveBanNode *scan = g_active_bans;
    while (scan) {
        if ((!jail_name || strcmp(scan->jail_name, jail_name) == 0) && strcmp(scan->ip, ip) == 0) {
            return scan;
        }
        scan = scan->next;
    }
    return NULL;
}

int get_active_ban_duration(const char *set_name, const char *ip) {
    ActiveBanNode *scan = g_active_bans;
    while (scan) {
        if ((!set_name || strcmp(scan->set_name, set_name) == 0) && strcmp(scan->ip, ip) == 0) {
            return scan->ban_duration;
        }
        scan = scan->next;
    }
    return -1;
}


void register_active_ban_full(const char *ip, const char *jail_name, const char *set_name, 
                              int duration_sec, uint64_t expire_ms, long long ban_end, 
                              int offense_count, bool is_max_ban, bool dirty) {
    ActiveBanNode *scan = g_active_bans;
    while (scan) {
        if (strcmp(scan->jail_name, jail_name) == 0 && strcmp(scan->ip, ip) == 0) {
            scan->ban_duration = duration_sec;
            scan->expire_ms = expire_ms;
            scan->ban_end = ban_end;
            scan->offense_count = offense_count;
            scan->is_max_ban = is_max_ban;
            if (dirty) scan->dirty = true;
            return;
        }
        scan = scan->next;
    }

    ActiveBanNode *new_ban = (ActiveBanNode*)calloc(1, sizeof(ActiveBanNode));
    if (new_ban) {
        safe_strncpy(new_ban->ip, ip, sizeof(new_ban->ip));
        safe_strncpy(new_ban->jail_name, jail_name, sizeof(new_ban->jail_name));
        safe_strncpy(new_ban->set_name, set_name, sizeof(new_ban->set_name));
        new_ban->ban_duration = duration_sec;
        new_ban->expire_ms = expire_ms;
        new_ban->ban_end = ban_end;
        new_ban->offense_count = offense_count;
        new_ban->is_max_ban = is_max_ban;
        new_ban->dirty = dirty;
        new_ban->next = g_active_bans;
        g_active_bans = new_ban;
    }
}

void prune_active_bans_distant(time_t cutoff_epoch) {
    ActiveBanNode **curr_ptr = &g_active_bans;
    while (*curr_ptr) {
        ActiveBanNode *node = *curr_ptr;
        /* Evict if ban ended (ban_end == -1) OR non-permanent ban is beyond runway (> cutoff_epoch).
         * Keep active permanent bans (ban_end == 0) and runway items (0 < ban_end <= cutoff_epoch). */
        if (node->ban_end == -1 || node->ban_end > cutoff_epoch) {
            *curr_ptr = node->next;
            free(node);
            continue;
        }
        curr_ptr = &(*curr_ptr)->next;
    }
}

void remove_active_ban_from_ram(const char *set_name, const char *ip) {
    ActiveBanNode **curr_ptr = &g_active_bans;
    while (*curr_ptr) {
        ActiveBanNode *tracked = *curr_ptr;
        if ((!set_name || strcmp(tracked->set_name, set_name) == 0) && strcmp(tracked->ip, ip) == 0) {
            *curr_ptr = tracked->next;
            free(tracked);
            return;
        }
        curr_ptr = &(*curr_ptr)->next;
    }
}

static void process_in_memory_ban_expirations(const Config *config) {
    uint64_t now_ms = get_current_time_ms();

    ActiveBanNode *tracked = g_active_bans;
    while (tracked) {
        if (tracked->expire_ms > 0 && now_ms >= tracked->expire_ms) {
            const Jail *j = find_jail_by_name(config, tracked->jail_name);
            const char *disabled_tag = (j && !j->enabled) ? "[DISABLED JAIL] " : "";

            log_msg("INFO", "[UNBAN] %s[%ds EXPIRED] IP %s timeout expired in jail [%s]. Ban lifted.",
                    disabled_tag, tracked->ban_duration, tracked->ip, tracked->jail_name);

            /* Transition to inactive in RAM but retain offense_count history.
             * The 300-second maintenance tick commits this state to SQLite. */
            tracked->expire_ms = 0;
            tracked->ban_end = -1;
            tracked->ban_duration = -1;
            tracked->is_max_ban = false;
            tracked->dirty = true;
        }
        tracked = tracked->next;
    }
}

int tail_log(const Config *config) {
    log_msg("INFO", "[TAILER] Initializing uban multi-path log monitor...");

    // Initialize inotify listener for CLI commands
    int cmd_inotify_fd = init_command_listener();

    FILE *fps[MAX_JAILS] = {NULL};
    ino_t inodes[MAX_JAILS] = {0};
    long offsets[MAX_JAILS] = {0};

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        if (!j->enabled || strlen(j->logpath) == 0) continue;

        fps[i] = fopen(j->logpath, "r");
        if (fps[i]) {
            fseek(fps[i], 0, SEEK_END);
            offsets[i] = ftell(fps[i]);
            struct stat st;
            if (stat(j->logpath, &st) == 0) inodes[i] = st.st_ino;
            log_msg("INFO", "[TAILER] Monitoring jail [%s] on: %s", j->name, j->logpath);
        } else {
            log_msg("ERROR", "[TAILER] Failed to open log for jail [%s]: %s", j->name, j->logpath);
        }
    }

    char line[MAX_LINE_LEN];
    time_t last_sweep_time = 0;
    time_t last_ingest_time = 0;
    time_t last_purge_time = time(NULL);

    while (1) {
        time_t now = time(NULL);

        // Check for incoming CLI commands via inotify
        if (cmd_inotify_fd >= 0) {
            char ev_buf[sizeof(struct inotify_event) + 256];
            ssize_t len = read(cmd_inotify_fd, ev_buf, sizeof(ev_buf));
            if (len > 0) {
                process_queued_commands(config);
            }
        }

        // 1-SECOND TICK: Process expiring items in the RAM runway queue & sync real-time count
        if (now - last_sweep_time >= 1) {
            process_in_memory_ban_expirations(config);
            sync_ram_stats_file(config);
            last_sweep_time = now;
        }

        // 300-SECOND TICK: Consolidated Maintenance
        if (now - last_ingest_time >= 300) {
            // Job A: Dump dirty RAM entries to SQLite
            uban_db_flush_ram_state();

            // Job B: Mark expired bans in SQLite
            uban_db_mark_expired(now);

            // Job C: Evict inactive (-1) and distant bans (> now + 600) from RAM
            prune_active_bans_distant(now + 600);

            // Job D: Clean up empty retry tracking nodes
            prune_stale_ip_trackers();

            // Job E: Load next 5-minute runway window into RAM
            int current_ram_count = get_active_bans_count();
            int runway_headroom = config->max_track_ip - current_ram_count;
            if (runway_headroom > 0) {
                uban_db_load_runway(config, runway_headroom);
            }

            // Release unused glibc heap arenas back to the Linux kernel
            malloc_trim(0);

            last_ingest_time = now;
        }

        // SCHEDULED MAINTENANCE TICK: Database history purge
        if (config->db_purge_enable && (now - last_purge_time >= config->db_purge_interval)) {
            uban_db_purge_history(config);
            last_purge_time = now;
        }

        bool lines_read = false;

        for (int i = 0; i < config->jail_count; i++) {
            const Jail *j = &config->jails[i];
            if (!j->enabled || !fps[i]) continue;

            struct stat st;
            if (stat(j->logpath, &st) == 0) {
                if (st.st_ino != inodes[i] || st.st_size < offsets[i]) {
                    log_msg("INFO", "[LOGROTATE] Rotation detected on %s. Re-opening.", j->logpath);
                    fclose(fps[i]);
                    fps[i] = fopen(j->logpath, "r");
                    if (fps[i]) {
                        inodes[i] = st.st_ino;
                        offsets[i] = 0;
                    }
                    continue;
                }
            }

            fseek(fps[i], offsets[i], SEEK_SET);

            uint64_t line_timestamp_ms = get_current_time_ms();
            while (fgets(line, sizeof(line), fps[i])) {
                lines_read = true;
                size_t len = strlen(line);

                if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
                    int c;
                    while ((c = fgetc(fps[i])) != EOF && c != '\n');

                    log_msg("DEBUG", "[PARSER] Oversized log line (>%d bytes) discarded to prevent positional drift.", MAX_LINE_LEN);
                    continue;
                }

                char extracted_ip[MAX_IP_LEN];
                if (parse_log_line(line, j, extracted_ip)) {
                    LogEntry entry;
                    entry.timestamp_ms = line_timestamp_ms++;
                    safe_strncpy(entry.raw_line, line, MAX_LINE_LEN);
                    evaluate_entry(&entry, j, extracted_ip, (Config*)config);
                }
            }

            if (ferror(fps[i])) {
                clearerr(fps[i]);
            }

            offsets[i] = ftell(fps[i]);
        }

        if (!lines_read) {
            usleep(config->poll_interval_ms * 1000);
        }
    }

    for (int i = 0; i < config->jail_count; i++) {
        if (fps[i]) fclose(fps[i]);
    }
    return 0;
}

int get_ram_runway_count(const Config *config, const char *target_app, const char *target_jail) {
    int count = 0;
    for (ActiveBanNode *n = g_active_bans; n; n = n->next) {
        if (n->ban_end != 0 && n->ban_end <= 0) continue; // Exclude inactive nodes
        if (target_jail && strlen(target_jail) > 0) {
            if (strcmp(n->jail_name, target_jail) == 0) count++;
        } else if (target_app && strlen(target_app) > 0 && config) {
            const Jail *j = find_jail_by_name(config, n->jail_name);
            if (j && strcmp(j->app_name, target_app) == 0) count++;
        } else {
            count++;
        }
    }
    return count;
}
