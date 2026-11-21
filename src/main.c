/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        main.c
 * Description: Daemon entry point, CLI argument parser, signal handling, and recovery engine.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#define _XOPEN_SOURCE 700
#include <time.h>
#include <sys/stat.h>
#include "uban.h"
#include <signal.h>
#include <stdbool.h>
#include <dirent.h>
#include <unistd.h>

/* Global heap-allocated / BSS static configuration */
static Config g_config;
static const Config *g_config_ptr = &g_config;
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
        // Persist all volatile dirty bans and cumulative offense hits to SQLite
        uban_db_flush_ram_state();
        unlink(UBAN_STAT_FILE);
        unlink(UBAN_CMD_FILE);
        firewall_dump_snapshot(g_config_ptr, NULL, 0, false);
        uban_db_close();
        exit(0);
    } else if (sig == SIGHUP) {
        /* Allocate on the heap to avoid blowing the restricted signal execution stack */
        Config *new_cfg = (Config *)calloc(1, sizeof(Config));
        if (new_cfg) {
            if (load_config(g_cfg_path, new_cfg) == 0) {
                g_config = *new_cfg;
                log_msg("INFO", "[RELOAD] Configuration reloaded successfully from %s.", g_cfg_path);
            } else {
                log_msg("ERROR", "[RELOAD] Failed to re-read %s on SIGHUP.", g_cfg_path);
            }
            free(new_cfg);

            uban_db_flush_ram_state();
            clear_all_ip_trackers();
            clear_active_bans_ram();
            uban_db_load_runway(g_config_ptr, g_config.max_track_ip);
        }
    }
}

int handle_cli_version(void) {
    printf("uban version %s (Universal Ban Engine for Linux)\n", UBAN_VERSION);
    printf("Backend: nftables | Database: SQLite3 WAL | Target Arch: Linux\n");
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

    // Open read view of the SQLite state
    uban_db_init(config);

    // Retrieve metrics based on scope
    int db_active = 0, db_total = 0;
    uban_db_get_counts(config, target_app, target_jail, &db_active, &db_total);

    // Read real-time volatile RAM count from daemon's UBAN_STAT_FILE
    int ram_count = 0;
    FILE *sfp = fopen(UBAN_STAT_FILE, "r");
    if (sfp) {
        char jname[MAX_NAME_LEN];
        int cnt = 0;
        while (fscanf(sfp, "%63s %d", jname, &cnt) == 2) {
            if (strlen(target_jail) > 0) {
                if (strcmp(jname, target_jail) == 0) {
                    ram_count = cnt;
                    break;
                }
            } else if (strlen(target_app) > 0) {
                const Jail *j = find_jail_by_name(config, jname);
                if (j && strcmp(j->app_name, target_app) == 0) {
                    ram_count += cnt;
                }
            } else {
                ram_count += cnt;
            }
        }
        fclose(sfp);
    }

    if (strlen(target_jail) > 0) {
        printf("=== Status for Jail [%s] ===\n", target_jail);
        printf("State: RAM runway: %d | DB Active: %d | DB Total Tracked: %d\n\n",
               ram_count, db_active, db_total);
    } else if (strlen(target_app) > 0) {
        printf("=== Status for App [%s] ===\n", target_app);
        printf("State: RAM runway: %d | DB Active: %d | DB Total Tracked: %d\n\n",
               ram_count, db_active, db_total);
    } else {
        printf("=== uban Overall System Status ===\n");
        printf("State: RAM runway: %d | DB Active: %d | DB Total Tracked: %d\n\n",
               ram_count, db_active, db_total);
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

    uban_db_close();
    return 0;
}

int uban_daemon_status() {
	char check_cmd[128];
	snprintf(check_cmd, sizeof(check_cmd), "pgrep -x uban | grep -v '^%d$' >/dev/null 2>&1", getpid());
	if (system(check_cmd) != 0)  return -1; 
	
	return 0;
}

int handle_cli_ban(const Config *config, int argc, char **argv) {
	
	if (uban_daemon_status()) {
		fprintf(stderr, "Error: uban daemon is not running. Commands cannot be queued while offline.\n");
		return -1;
	}
	
    if (argc < 4) {
        printf("Usage: uban ban <jail_name> <IP> [duration]\n");
        return -1;
    }

    const char *jail_name = argv[2];
    const char *ip = argv[3];
    int bantime = (argc >= 5) ? parse_duration(argv[4]) : -1;

    const Jail *target_jail = find_jail_by_name(config, jail_name);
    if (!target_jail) {
        printf("Error: Jail [%s] not found in configuration.\n", jail_name);
        return -1;
    }
    if (bantime < 0) bantime = target_jail->bantime;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "BAN %s %s %d", jail_name, ip, bantime);

    if (send_cli_command(cmd) == 0) {
        printf("Ban request queued for %s in jail [%s] (%ds).\n", ip, jail_name, bantime);
        return 0;
    }
    return -1;
}

int handle_cli_unban(const Config *config, int argc, char **argv) {
	
	if (uban_daemon_status()) {
		fprintf(stderr, "Error: uban daemon is not running. Commands cannot be queued while offline.\n");
		return -1;
	}
	
    (void)config;
    if (argc < 3) {
        printf("Usage: uban unban <IPs...>\n");
        return -1;
    }

    for (int i = 2; i < argc; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "UNBAN %s", argv[i]);
        if (send_cli_command(cmd) == 0) {
            printf("Unban request queued for %s.\n", argv[i]);
        }
    }
    return 0;
}

int handle_cli_flush(const Config *config, int argc, char **argv) {
	
	if (uban_daemon_status()) {
		fprintf(stderr, "Error: uban daemon is not running. Commands cannot be queued while offline.\n");
		return -1;
	}
	
    (void)config;
    bool reset_db = false;
    char target_jail[MAX_NAME_LEN] = "";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--reset") == 0) {
            reset_db = true;
        } else if (strcmp(argv[i], "flush") != 0 && strcmp(argv[i], "--flush") != 0) {
            safe_strncpy(target_jail, argv[i], MAX_NAME_LEN);
        }
    }

    char cmd[256];
    if (strlen(target_jail) > 0) {
        snprintf(cmd, sizeof(cmd), "FLUSH %s %s", target_jail, reset_db ? "RESET" : "");
    } else {
        snprintf(cmd, sizeof(cmd), "FLUSH %s", reset_db ? "RESET" : "");
    }

    if (send_cli_command(cmd) == 0) {
        printf("Flush request queued%s.\n", reset_db ? " (with database reset)" : "");
        return 0;
    }
    return -1;
}

int handle_cli_save_to_snapshot(const Config *config, const char *dump_file) {
	char final_path[512] = {0};

    if (dump_file && dump_file[0] != '\0') {
        safe_strncpy(final_path, dump_file, sizeof(final_path));
    }
	
	int rc = firewall_dump_snapshot(config, final_path, sizeof(final_path), true);
	
	if (rc != 0) {
		fprintf(stderr, "Failed to create snapshot\n");
		return -1;
	}
	
	printf("Snapshot saved to: %s\n", final_path);
	return 0;
	
}

int handle_cli_restore_from_snapshot(const Config *config, const char *dump_file) {
   
	if (!uban_daemon_status()) {
        fprintf(stderr, "Error: uban daemon is currently running.\n"
                        "Please stop the service before restoring ('systemctl stop uban').\n");
        return -1;
    }

    char chosen_dump[MAX_PATH_LEN + 128] = "";

    if (dump_file && strlen(dump_file) > 0) {
        safe_strncpy(chosen_dump, dump_file, sizeof(chosen_dump));
    } else {
        DIR *dir = opendir(config->db_dir);
        if (!dir) {
            fprintf(stderr, "Error: Unable to open database directory %s\n", config->db_dir);
            return -1;
        }

        struct dirent *entry;
        char latest_name[MAX_PATH_LEN] = "";

        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "nftables_prestart_", 18) == 0 &&
                strstr(entry->d_name, ".dump") != NULL) {
                if (strcmp(entry->d_name, latest_name) > 0) {
                    safe_strncpy(latest_name, entry->d_name, sizeof(latest_name));
                }
            }
        }
        closedir(dir);

        if (strlen(latest_name) == 0) {
            fprintf(stderr, "Error: No nftables snapshots found in %s\n", config->db_dir);
            return -1;
        }
        snprintf(chosen_dump, sizeof(chosen_dump), "%s/%s", config->db_dir, latest_name);
    }

    if (access(chosen_dump, R_OK) != 0) {
        fprintf(stderr, "Error: Dump file does not exist or is unreadable: %s\n", chosen_dump);
        return -1;
    }

    /* 1. Determine if filename follows standard timestamp pattern */
    const char *base_fn = strrchr(chosen_dump, '/');
    base_fn = base_fn ? (base_fn + 1) : chosen_dump;

    time_t now = time(NULL);
    long elapsed = 0;
    struct tm tm_file;
    memset(&tm_file, 0, sizeof(struct tm));

    if (sscanf(base_fn, "nftables_%*[^_]_%4d%2d%2d_%2d%2d%2d.dump",
               &tm_file.tm_year, &tm_file.tm_mon, &tm_file.tm_mday,
               &tm_file.tm_hour, &tm_file.tm_min, &tm_file.tm_sec) == 6) {
        tm_file.tm_year -= 1900;
        tm_file.tm_mon -= 1;
        tm_file.tm_isdst = -1;
        time_t parsed_time = mktime(&tm_file);
        if (parsed_time > 0) {
            elapsed = (long)(now - parsed_time);
            printf("Restoring timestamped snapshot: %s\n", chosen_dump);
            printf("Snapshot age: %ld seconds. Re-aligning expirations...\n", elapsed);
        } else {
            printf("Restoring static snapshot (raw timeouts): %s\n", chosen_dump);
        }
    } else {
        printf("Restoring static snapshot (raw timeouts): %s\n", chosen_dump);
    }

    FILE *fp = fopen(chosen_dump, "r");
    if (!fp) {
        fprintf(stderr, "Error opening dump file: %s\n", chosen_dump);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_buf = (char *)malloc(fsize + 1);
    if (!json_buf) {
        fclose(fp);
        return -1;
    }
    size_t read_bytes = fread(json_buf, 1, fsize, fp);
    json_buf[read_bytes] = '\0';
    fclose(fp);

    /* 2. Flush current state across all uban jails */
    firewall_init(config);
    uban_db_init(config);

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        firewall_flush_jail(config, j->nft_set_name);
        uban_db_flush_jail(j->name, false);
    }

    int restored_active = 0;
    int skipped_expired = 0;

    /* 3. Reconcile elements */
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        char set_key[MAX_NAME_LEN + 32];
        snprintf(set_key, sizeof(set_key), "\"name\": \"%s\"", j->nft_set_name);

        char *set_pos = strstr(json_buf, set_key);
        if (!set_pos) continue;

        char *elem_tag = strstr(set_pos, "\"elem\":");
        if (!elem_tag) continue;

        char *next_set = strstr(set_pos + strlen(set_key), "{\"set\":");
        if (next_set && elem_tag > next_set) continue;

        char *elem_end = strchr(elem_tag, ']');
        if (!elem_end) continue;
        if (next_set && elem_end > next_set) elem_end = next_set;

        char *scan = elem_tag;
        while (scan < elem_end) {
            char *val_tag = strstr(scan, "\"val\":");
            if (!val_tag || val_tag >= elem_end) break;

            char parsed_ip[MAX_IP_LEN] = "";
            char *quote_start = strchr(val_tag + 6, '"');
            if (quote_start && quote_start < elem_end) {
                char *quote_end = strchr(quote_start + 1, '"');
                if (quote_end && quote_end <= elem_end) {
                    size_t iplen = quote_end - (quote_start + 1);
                    if (iplen < sizeof(parsed_ip)) {
                        memcpy(parsed_ip, quote_start + 1, iplen);
                        parsed_ip[iplen] = '\0';
                    }
                }
            }

            int expires = 0;
            char *exp_tag = strstr(val_tag, "\"expires\":");
            if (exp_tag && exp_tag < elem_end) {
                char *next_val = strstr(val_tag + 6, "\"val\":");
                if (!next_val || exp_tag < next_val) {
                    expires = atoi(exp_tag + 10);
                }
            }

            if (strlen(parsed_ip) > 0) {
                if (expires == 0) {
                    /* Permanent ban */
                    firewall_ban_ip(j->nft_set_name, parsed_ip, 0);
                    uban_db_upsert_ban(j->name, parsed_ip, 0, 0, NULL);
                    restored_active++;
                } else {
                    /* Apply drift adjustment only if snapshot had a valid timestamp header */
                    int remaining = expires - (int)elapsed;
                    if (remaining > 0) {
                        long long ban_end = (long long)now + remaining;
                        firewall_ban_ip(j->nft_set_name, parsed_ip, remaining);
                        uban_db_upsert_ban(j->name, parsed_ip, ban_end, remaining, NULL);
                        restored_active++;
                    } else {
                        /* Expired in the interval between snapshot and restore */
                        uban_db_upsert_ban(j->name, parsed_ip, -1, 0, NULL);
                        skipped_expired++;
                    }
                }
            }

            scan = val_tag + 6;
        }
    }

    free(json_buf);
    uban_db_close();

    if (elapsed != 0) {
        printf("Restore complete: %d active elements restored into nftables/DB, %d naturally expired elements discarded.\n",
               restored_active, skipped_expired);
    } else {
        printf("Restore complete: %d elements restored verbatim into nftables/DB.\n", restored_active);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    memset(&g_config, 0, sizeof(Config));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && (i + 1) < argc) {
            g_cfg_path = argv[i + 1];
            break;
        }
    }

    if (load_config(g_cfg_path, &g_config) != 0) {
        fprintf(stderr, "Error loading configuration file from %s\n", g_cfg_path);
        return 1;
    }

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
        if (strcmp(argv[1], "status") == 0) return handle_cli_status(&g_config, argc, argv);
        if (strcmp(argv[1], "unban") == 0) return handle_cli_unban(&g_config, argc, argv);
        if (strcmp(argv[1], "ban") == 0) return handle_cli_ban(&g_config, argc, argv);
        if (strcmp(argv[1], "flush") == 0 || strcmp(argv[1], "--flush") == 0 || 
           (argc > 2 && (strcmp(argv[argc-1], "flush") == 0 || strcmp(argv[argc-1], "--flush") == 0))) {
            return handle_cli_flush(&g_config, argc, argv);
        }
        if (strcmp(argv[1], "restore_from_snapshot") == 0) {
            const char *file_arg = (argc > 2) ? argv[2] : NULL;
            return handle_cli_restore_from_snapshot(&g_config, file_arg);
        }
		
		if (strcmp(argv[1], "save_to_snapshot") == 0) {
            const char *file_arg = (argc > 2) ? argv[2] : NULL;
            return handle_cli_save_to_snapshot(&g_config, file_arg);
        }

        printf("Unknown command: %s\nRun 'uban help' for usage documentation.\n", argv[1]);
        return 1;
    }

    log_msg("INFO", "==================================================");
    log_msg("INFO", "uban v%s Universal Ban Engine starting up...", UBAN_VERSION);
    log_msg("INFO", "Polling interval: %d ms | Database: %s", g_config.poll_interval_ms, g_config.db_dir);
    log_msg("INFO", "==================================================");

    /* 1. Dump startup nftables snapshot */
    firewall_dump_snapshot(&g_config, NULL, 0, false);

    /* 2. Initialize SQLite persistence layer */
    if (uban_db_init(&g_config) != 0) {
        log_msg("ERROR", "Failed to initialize SQLite database. Exiting.");
        return 1;
    }

    /* 3. Purge orphaned jails */
    uban_db_purge_orphans(&g_config);

    /* 4. Initialize firewall sets and drop rules */
    firewall_init(&g_config);

    /* 5. Sync active database bans into nftables */
    firewall_sync_from_db(&g_config);

    /* 6. Seed imminent runway expirations (<= 600) into RAM and write to temp file */
    uban_db_load_runway(&g_config, g_config.max_track_ip);
    sync_ram_stats_file(&g_config);

    /* 7. Retain up to 5 newest dumps */
    firewall_prune_snapshots(&g_config, 5);

    return tail_log(&g_config);
}
