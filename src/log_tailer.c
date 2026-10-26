/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        log_tailer.c
 * Description: Real-time file descriptor tailer and non-blocking log stream reader.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#define _DEFAULT_SOURCE
#include "uban.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static ActiveBanNode *g_active_bans = NULL;

void clear_active_bans_ram(void) {
    ActiveBanNode *curr = g_active_bans;
    while (curr) {
        ActiveBanNode *next = curr->next;
        free(curr);
        curr = next;
    }
    g_active_bans = NULL;
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

void register_active_ban(const char *ip, const char *jail_name, const char *set_name, int duration_sec, uint64_t expire_ms) {
    ActiveBanNode *scan = g_active_bans;
    while (scan) {
        if (strcmp(scan->set_name, set_name) == 0 && strcmp(scan->ip, ip) == 0) {
            scan->ban_duration = duration_sec;
            scan->expire_ms = expire_ms;
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
        new_ban->next = g_active_bans;
        g_active_bans = new_ban;
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
    (void)config;
    uint64_t now_ms = get_current_time_ms();

    ActiveBanNode **curr_ptr = &g_active_bans;
    while (*curr_ptr) {
        ActiveBanNode *tracked = *curr_ptr;

        // Check if in-memory ban duration timer completed
        if (tracked->expire_ms > 0 && now_ms >= tracked->expire_ms) {
            // Fast in-memory unban log (No popen subprocess bottleneck!)
            log_msg("INFO", "[UNBAN] [%ds EXPIRED] IP %s timeout expired in jail [%s]. Ban lifted.",
                    tracked->ban_duration, tracked->ip, tracked->jail_name);

            *curr_ptr = tracked->next;
            free(tracked);
            continue;
        }

        curr_ptr = &(*curr_ptr)->next;
    }
}

int tail_log(const Config *config) {
    log_msg("INFO", "[TAILER] Initializing uban multi-path log monitor...");

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
    time_t last_sync_time = 0;

    while (1) {
        time_t now = time(NULL);

        // RATE-LIMIT TIMER SWEEP: Fast RAM sweep once per second
        if (now - last_sweep_time >= 1) {
            process_in_memory_ban_expirations(config);
            last_sweep_time = now;
        }

        // Periodic 60-second RAM-to-Disk Offender Database & Firewall State Flush
        if (now - last_sync_time >= 60) {
            firewall_save_state(config);
            offender_db_sync_to_disk(config);
            last_sync_time = now;
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
