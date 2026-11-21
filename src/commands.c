/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        commands.c
 * Description: Command file parser, inotify listener, and asynchronous CLI dispatcher.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#define _GNU_SOURCE
#include "uban.h"
#include <sys/inotify.h>
#include <sys/stat.h>
#include <fcntl.h>

static int g_inotify_fd = -1;
static int g_watch_wd = -1;

static void ensure_run_dir(void) {
    struct stat st;
    if (stat(UBAN_RUN_DIR, &st) != 0) {
        mkdir(UBAN_RUN_DIR, 0755);
    }
}

int init_command_listener(void) {
    ensure_run_dir();

    // Ensure command file exists so inotify can attach a watch
    int fd = open(UBAN_CMD_FILE, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);

    g_inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd < 0) {
        log_msg("ERROR", "[CMD] Failed to initialize inotify: %m");
        return -1;
    }

    g_watch_wd = inotify_add_watch(g_inotify_fd, UBAN_CMD_FILE, IN_CLOSE_WRITE | IN_MODIFY);
    if (g_watch_wd < 0) {
        log_msg("ERROR", "[CMD] Failed to add inotify watch on %s: %m", UBAN_CMD_FILE);
        close(g_inotify_fd);
        g_inotify_fd = -1;
        return -1;
    }

    return g_inotify_fd;
}

static void execute_cmd_ban(const Config *config, const char *jail_name, const char *ip, int bantime) {
    const Jail *target_jail = find_jail_by_name(config, jail_name);
    if (!target_jail) {
        log_msg("ERROR", "[CMD] Manual ban failed: jail [%s] not found.", jail_name);
        return;
    }

    if (bantime < 0) bantime = target_jail->bantime;

    if (firewall_ban_ip(target_jail->nft_set_name, ip, bantime) == 0) {
        time_t now_epoch = time(NULL);
        long long ban_end = (bantime > 0) ? ((long long)now_epoch + bantime) : 0;
        int new_count = 1;

        // Upsert into persistent SQLite
        uban_db_upsert_ban(target_jail->name, ip, ban_end, bantime, &new_count);

        // Track in RAM runway queue if ban expires within 600s
        if (bantime > 0 && bantime <= 600) {
            uint64_t now_ms = get_current_time_ms();
            uint64_t expire_ms = now_ms + ((uint64_t)bantime * 1000ULL);
            register_active_ban_full(ip, target_jail->name, target_jail->nft_set_name,
                                     bantime, expire_ms, ban_end, new_count, false, false);
        }

        const char *dis_tag = (!target_jail->enabled) ? "[DISABLED JAIL] " : "";
        log_msg("INFO", "[BAN] [MANUAL] %sIP %s manually banned in jail [%s] for %ds.",
                dis_tag, ip, target_jail->name, bantime);

        sync_ram_stats_file(config);
    } else {
        log_msg("ERROR", "[CMD] Failed to apply firewall ban for IP %s in jail [%s].", ip, target_jail->name);
    }
}

static void execute_cmd_unban(const Config *config, const char *target_ip) {
    int ori_dur = 0;
    char jail_name[MAX_NAME_LEN] = "";

    // 1. Remove from nftables kernel set
    if (firewall_unban_ip_all(config, target_ip, &ori_dur, jail_name) > 0) {
        const Jail *j = find_jail_by_name(config, jail_name);
        const char *dis_tag = (j && !j->enabled) ? "[DISABLED JAIL] " : "";

        if (ori_dur > 0) {
            log_msg("INFO", "[UNBAN] [MANUAL, ORI %ds] %sIP %s manually unbanned from jail [%s].",
                    ori_dur, dis_tag, target_ip, jail_name);
        } else {
            log_msg("INFO", "[UNBAN] [MANUAL] %sIP %s manually unbanned from firewall.", dis_tag, target_ip);
        }
    } else {
        log_msg("INFO", "[UNBAN] [MANUAL] IP %s unbanned (was not active in kernel sets).", target_ip);
    }

    // 2. Mark inactive in RAM node while preserving offense_count
    ActiveBanNode *tracked = find_active_ban(jail_name[0] ? jail_name : NULL, target_ip);
    if (tracked) {
        tracked->expire_ms = 0;
        tracked->ban_end = -1;
        tracked->ban_duration = -1;
        tracked->is_max_ban = false;
        tracked->dirty = true;
    }

    // 3. Mark inactive in SQLite
    uban_db_unban_ip_all(target_ip);

    sync_ram_stats_file(config);
}

static void execute_cmd_flush(const Config *config, const char *target_jail, const char *target_app, bool reset_db) {
    if (!reset_db) {
        uban_db_flush_ram_state();
    }

    int cleared = 0;
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        if (target_app && strlen(target_app) > 0 && strcmp(j->app_name, target_app) != 0) continue;
        if (target_jail && strlen(target_jail) > 0 && strcmp(j->name, target_jail) != 0) continue;

        if (firewall_flush_jail(config, j->nft_set_name) == 0) {
            uban_db_flush_jail(j->name, reset_db);
            cleared++;
        }
    }

    if (reset_db && (!target_app || strlen(target_app) == 0) && (!target_jail || strlen(target_jail) == 0)) {
        uban_db_flush_all(true);
        clear_all_ip_trackers();
    }

    clear_active_bans_ram();
    sync_ram_stats_file(config);

    if (reset_db) {
        log_msg("INFO", "[FLUSH] Cleared firewall sets and WIPED persistent database state across %d jails.", cleared);
    } else {
        log_msg("INFO", "[FLUSH] Cleared firewall sets across %d jails (history database preserved).", cleared);
    }
}

void process_queued_commands(const Config *config) {
    FILE *fp = fopen(UBAN_CMD_FILE, "r+");
    if (!fp) return;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char *cmd_str = line;
        while (isspace((unsigned char)*cmd_str)) cmd_str++;
        if (*cmd_str == '\0' || *cmd_str == '#') continue;

        char verb[32] = "";
        char arg1[MAX_NAME_LEN] = "";
        char arg2[MAX_IP_LEN] = "";
        char arg3[64] = "";

        int parts = sscanf(cmd_str, "%31s %63s %45s %63s", verb, arg1, arg2, arg3);
        if (parts < 1) continue;

        if (strcasecmp(verb, "BAN") == 0 && parts >= 3) {
            // Format: BAN <jail> <ip> [duration]
            int duration = (parts >= 4) ? atoi(arg3) : -1;
            execute_cmd_ban(config, arg1, arg2, duration);
        } else if (strcasecmp(verb, "UNBAN") == 0 && parts >= 2) {
            // Format: UNBAN <ip>
            execute_cmd_unban(config, arg1);
        } else if (strcasecmp(verb, "FLUSH") == 0) {
            // Format: FLUSH [target_jail] [RESET]
            bool reset_db = false;
            char target_jail[MAX_NAME_LEN] = "";

            for (int i = 1; i < parts; i++) {
                const char *val = (i == 1) ? arg1 : (i == 2) ? arg2 : arg3;
                if (strcasecmp(val, "RESET") == 0 || strcasecmp(val, "--reset") == 0) {
                    reset_db = true;
                } else if (strlen(target_jail) == 0) {
                    safe_strncpy(target_jail, val, sizeof(target_jail));
                }
            }
            execute_cmd_flush(config, target_jail, NULL, reset_db);
        }
    }

    // Truncate command file after reading all queued operations
    int fd = fileno(fp);
    if (fd >= 0) {
        if (ftruncate(fd, 0) != 0) {
            // Fallback truncate
            freopen(UBAN_CMD_FILE, "w", fp);
        }
    }
    fclose(fp);
}

int send_cli_command(const char *cmd_line) {
    ensure_run_dir();

    FILE *fp = fopen(UBAN_CMD_FILE, "a");
    if (!fp) {
        fprintf(stderr, "Error: Unable to open %s. Is uban daemon running or permissions valid?\n", UBAN_CMD_FILE);
        return -1;
    }

    fprintf(fp, "%s\n", cmd_line);
    fclose(fp);
    return 0;
}
