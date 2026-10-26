/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        main.c
 * Description: Daemon entry point, CLI argument parser, signal handling, and main event loop.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"
#include <signal.h>
#include <stdbool.h>

static const Config *g_config_ptr = NULL;
static const char *g_cfg_path = "/etc/uban/uban.conf";

static int compare_ips_num(const void *a, const void *b) {
    const BanStatusItem *ia = (const BanStatusItem *)a;
    const BanStatusItem *ib = (const BanStatusItem *)b;

    struct in_addr addr_a, addr_b;
    inet_pton(AF_INET, ia->ip, &addr_a);
    inet_pton(AF_INET, ib->ip, &addr_b);

    uint32_t ipa = ntohl(addr_a.s_addr);
    uint32_t ipb = ntohl(addr_b.s_addr);

    return (ipa > ipb) - (ipa < ipb);
}

static int compare_time_desc(const void *a, const void *b) {
    const BanStatusItem *ia = (const BanStatusItem *)a;
    const BanStatusItem *ib = (const BanStatusItem *)b;
    return (ia->expires_in_sec < ib->expires_in_sec) - (ia->expires_in_sec > ib->expires_in_sec);
}

void handle_signal(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_msg("INFO", "uban daemon shutting down (Signal %d received)...", sig);
        if (g_config_ptr) {
            firewall_save_state(g_config_ptr);
            offender_db_sync_to_disk(g_config_ptr);
        }
        exit(0);
    } else if (sig == SIGHUP) {
        if (g_config_ptr) {
            // 1. Read fresh uban.conf into memory
            Config new_cfg;
            if (load_config(g_cfg_path, &new_cfg) == 0) {
                *((Config *)g_config_ptr) = new_cfg;
                log_msg("INFO", "[RELOAD] Configuration reloaded successfully from %s.", g_cfg_path);
            } else {
                log_msg("ERROR", "[RELOAD] Failed to re-read %s on SIGHUP.", g_cfg_path);
            }

            // 2. Refresh active memory states with new config
            clear_all_ip_trackers();
            clear_active_bans_ram();
            offender_db_reload(g_config_ptr);
            firewall_restore_state(g_config_ptr);
        }
    }
}

int handle_cli_version(void) {
    printf("uban version %s (Universal Ban Engine for Linux)\n", UBAN_VERSION);
    printf("Backend: nftables | Target Arch: x86_64 Linux\n");
    return 0;
}

int handle_cli_help(void) {
    const char *help_path = "/etc/uban/uban.help";
    if (access("uban.help", F_OK) == 0) help_path = "uban.help";

    FILE *fp = fopen(help_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Could not open help file at %s\n", help_path);
        return -1;
    }

    char buffer[MAX_LINE_LEN];
    while (fgets(buffer, sizeof(buffer), fp)) {
        fputs(buffer, stdout);
    }

    fclose(fp);
    return 0;
}

int handle_cli_status(const Config *config, int argc, char **argv) {
    bool detail = false;
    bool sort_time = false;
    bool sort_ip = true;
    char target_app[MAX_NAME_LEN] = "";
    char target_jail[MAX_NAME_LEN] = "";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) detail = true;
        else if (strcmp(argv[i], "-t") == 0) { sort_time = true; sort_ip = false; }
        else if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
            safe_strncpy(target_app, argv[++i], MAX_NAME_LEN);
        } else if (strcmp(argv[i], "-j") == 0 && (i + 1) < argc) {
            safe_strncpy(target_jail, argv[++i], MAX_NAME_LEN);
        } else if (argv[i][0] != '-') {
            safe_strncpy(target_jail, argv[i], MAX_NAME_LEN);
        }
    }

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        if (strlen(target_app) > 0 && strcmp(j->app_name, target_app) != 0) continue;
        if (strlen(target_jail) > 0 && strcmp(j->name, target_jail) != 0) continue;

        BanStatusItem *items = NULL;
        int count = 0;
        firewall_get_banned_ips(j->nft_set_name, &items, &count);

        if (sort_time && count > 1) qsort(items, count, sizeof(BanStatusItem), compare_time_desc);
        else if (sort_ip && count > 1) qsort(items, count, sizeof(BanStatusItem), compare_ips_num);

        printf("[%s] [%s] (Maxretry: %d | Base Bantime: %ds)\n",
               j->name, j->enabled ? "ENABLED" : "DISABLED", j->maxretry, j->bantime);
        printf("Currently banned (%d): ", count);

        if (!detail) {
            int print_cap = (count > 500) ? 500 : count;
            for (int k = 0; k < print_cap; k++) printf("%s ", items[k].ip);
            if (count > print_cap) {
                printf("\n... and %d more (use 'uban status -d' to view all)", count - print_cap);
            }
            printf("\n\n");
        } else {
            printf("\n  %-18s %-20s\n", "IP ADDRESS", "TIME REMAINING");
            printf("  ---------------------------------------\n");
            for (int k = 0; k < count; k++) {
                int sec = items[k].expires_in_sec;
                if (sec < 0) {
                    printf("  %-18s %s\n", items[k].ip, "Permanent");
                } else {
                    int d = sec / 86400;
                    int h = (sec % 86400) / 3600;
                    int m = (sec % 3600) / 60;
                    int s = sec % 60;

                    if (d > 0) printf("  %-18s %dd %02dh %02dm %02ds\n", items[k].ip, d, h, m, s);
                    else if (h > 0) printf("  %-18s %02dh %02dm %02ds\n", items[k].ip, h, m, s);
                    else if (m > 0) printf("  %-18s %02dm %02ds\n", items[k].ip, m, s);
                    else printf("  %-18s %02ds\n", items[k].ip, s);
                }
            }
            printf("\n");
        }
        firewall_free_status_items(items);
    }
    return 0;
}

int handle_cli_ban(const Config *config, int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: uban ban <jail_name> <IP> [duration]\n");
        return -1;
    }

    const char *jail_name = argv[2];
    const char *ip = argv[3];
    int bantime = (argc >= 5) ? parse_duration(argv[4]) : config->jails[0].bantime;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        if (strcmp(j->name, jail_name) == 0) {
            if (argc < 5) bantime = j->bantime;
            if (firewall_ban_ip(j->nft_set_name, ip, bantime) == 0) {
                // FIX: Register in RAM first so firewall_save_state() picks up the new duration!
                uint64_t now_ms = get_current_time_ms();
                uint64_t expire_ms = (bantime > 0) ? (now_ms + ((uint64_t)bantime * 1000ULL)) : 0;
                register_active_ban(ip, j->name, j->nft_set_name, bantime, expire_ms);

                log_msg("INFO", "[BAN] [MANUAL] IP %s manually banned in jail [%s] for %ds.", ip, j->name, bantime);
                firewall_save_state(config);
                int res = system("pkill -HUP -f '^/usr/local/bin/uban$' 2>/dev/null || pkill -HUP -f '^./uban$' 2>/dev/null || true");
                (void)res;
                printf("Successfully banned IP %s in jail [%s].\n", ip, j->name);
                return 0;
            }
        }
    }
    printf("Error: Jail [%s] not found.\n", jail_name);
    return -1;
}

int handle_cli_unban(const Config *config, int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: uban unban <IPs...>\n");
        return -1;
    }
    for (int i = 2; i < argc; i++) {
        int ori_dur = 0;
        char jail_name[MAX_NAME_LEN] = "";
        if (firewall_unban_ip_all(config, argv[i], &ori_dur, jail_name) > 0) {
            if (ori_dur > 0) {
                log_msg("INFO", "[UNBAN] [MANUAL, ORI %ds] IP %s manually unbanned from jail [%s].", ori_dur, argv[i], jail_name);
            } else {
                log_msg("INFO", "[UNBAN] [MANUAL] IP %s manually unbanned from firewall.", argv[i]);
            }
            remove_active_ban_from_ram(NULL, argv[i]);
            printf("Unbanned IP: %s\n", argv[i]);
        }
    }
    return 0;
}

int handle_cli_flush(const Config *config, int argc, char **argv) {
    char target_app[MAX_NAME_LEN] = "";
    char target_jail[MAX_NAME_LEN] = "";
    bool reset_db = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--reset") == 0) {
            reset_db = true;
        } else if (strcmp(argv[i], "-a") == 0 && (i + 1) < argc) {
            safe_strncpy(target_app, argv[++i], MAX_NAME_LEN);
        } else if (strcmp(argv[i], "flush") != 0 && strcmp(argv[i], "--flush") != 0) {
            safe_strncpy(target_jail, argv[i], MAX_NAME_LEN);
        }
    }

    int cleared = 0;
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        if (strlen(target_app) > 0 && strcmp(j->app_name, target_app) != 0) continue;
        if (strlen(target_jail) > 0 && strcmp(j->name, target_jail) != 0) continue;

        if (firewall_flush_jail(config, j->nft_set_name) == 0) {
            if (reset_db) {
                char db_file[MAX_PATH_LEN + 128];
                snprintf(db_file, sizeof(db_file), "%s/%s.db", config->db_dir, j->name);
                unlink(db_file);
            }
            cleared++;
        }
    }

    if (reset_db) {
        if (strlen(target_app) == 0 && strlen(target_jail) == 0) {
            offender_db_wipe_all(config);
        }
    }

    clear_all_ip_trackers();

    int res = system("pkill -HUP -x uban 2>/dev/null || true");
    (void)res;

    if (reset_db) {
        log_msg("INFO", "[FLUSH] Cleared firewall sets and WIPED persistent database state across %d jails via CLI.", cleared);
        printf("Successfully flushed firewall rules and reset persistent history database across %d jails.\n", cleared);
    } else {
        log_msg("INFO", "[FLUSH] Cleared firewall sets across %d jails via CLI (history database preserved).", cleared);
        printf("Successfully flushed active kernel firewall rules across %d jails (history database preserved).\n", cleared);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    Config config;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && (i + 1) < argc) {
            g_cfg_path = argv[i + 1];
            break;
        }
    }

    if (load_config(g_cfg_path, &config) != 0) {
        fprintf(stderr, "Error loading configuration file from %s\n", g_cfg_path);
        return 1;
    }

    g_config_ptr = &config;

    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (argc > 1) {
        if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            return handle_cli_version();
        }
        if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            return handle_cli_help();
        }
        if (strcmp(argv[1], "status") == 0) return handle_cli_status(&config, argc, argv);
        if (strcmp(argv[1], "unban") == 0) return handle_cli_unban(&config, argc, argv);
        if (strcmp(argv[1], "ban") == 0) return handle_cli_ban(&config, argc, argv);
        if (strcmp(argv[1], "flush") == 0 || strcmp(argv[1], "--flush") == 0 || 
           (argc > 2 && (strcmp(argv[argc-1], "flush") == 0 || strcmp(argv[argc-1], "--flush") == 0))) {
            return handle_cli_flush(&config, argc, argv);
        }
        printf("Unknown command: %s\nRun 'uban help' for usage documentation.\n", argv[1]);
        return 1;
    }

    log_msg("INFO", "==================================================");
    log_msg("INFO", "uban v%s Universal Ban Engine starting up...", UBAN_VERSION);
    log_msg("INFO", "Polling interval: %d ms | Database: %s", config.poll_interval_ms, config.db_dir);
    log_msg("INFO", "==================================================");

    sync_db_files_on_startup(&config);
    firewall_init(&config);
    firewall_restore_state(&config);
    offender_db_init(&config);

    return tail_log(&config);
}
