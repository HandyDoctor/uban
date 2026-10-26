/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        evaluator.c
 * Description: Retry threshold evaluation, find_time window logic, and TTL decay tracking.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <dirent.h>

static IPEntry *g_ip_table = NULL;
static OffenderRecord *g_offender_table = NULL;
static int g_offender_count = 0;


/* ==============================================================================
 * STARTUP FILE MAINTENANCE (TOUCH ALL DEFINED, DELETE ORPHAN .db FILES)
 * ============================================================================== */
void sync_db_files_on_startup(const Config *config) {
    char mkdir_cmd[MAX_PATH_LEN + 64];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s 2>/dev/null", config->db_dir);
    int res = system(mkdir_cmd);
    (void)res;

    // 1. Touch/create .db file for every jail declared in .conf (enabled or disabled)
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        char db_file[MAX_PATH_LEN + 128];
        snprintf(db_file, sizeof(db_file), "%s/%s.db", config->db_dir, j->name);

        FILE *fp = fopen(db_file, "a");
        if (fp) fclose(fp);
    }

    // 2. Scan db_dir and unlink any .db file that has no matching jail in .conf
    DIR *dir = opendir(config->db_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len > 3 && strcmp(entry->d_name + name_len - 3, ".db") == 0) {
            char jail_name_from_file[MAX_NAME_LEN];
            safe_strncpy(jail_name_from_file, entry->d_name, name_len - 2);

            bool matches_conf = false;
            for (int i = 0; i < config->jail_count; i++) {
                if (strcmp(config->jails[i].name, jail_name_from_file) == 0) {
                    matches_conf = true;
                    break;
                }
            }

            if (!matches_conf) {
                char orphan_path[MAX_PATH_LEN + 256];
                snprintf(orphan_path, sizeof(orphan_path), "%s/%s", config->db_dir, entry->d_name);
                unlink(orphan_path);
                log_msg("INFO", "[CLEANUP] Deleted orphaned database file: %s", orphan_path);
            }
        }
    }
    closedir(dir);
}

/* ==============================================================================
 * IN-MEMORY OFFENDER DATABASE (RAM-ONLY UPDATES WITH DISK SYNC)
 * ============================================================================== */
void offender_db_wipe_all(const Config *config) {
    // 1. Clear in-memory offender records
    OffenderRecord *off = g_offender_table;
    while (off) {
        OffenderRecord *next_off = off->next;
        free(off);
        off = next_off;
    }
    g_offender_table = NULL;
    g_offender_count = 0;

    // 2. Unlink all jail .db files from disk
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        char db_file[MAX_PATH_LEN + 128];
        snprintf(db_file, sizeof(db_file), "%s/%s.db", config->db_dir, j->name);
        unlink(db_file);
    }

    // 3. Unlink bans.state file
    char state_file[MAX_PATH_LEN + 128];
    snprintf(state_file, sizeof(state_file), "%s/bans.state", config->db_dir);
    unlink(state_file);
}

void offender_db_init(const Config *config) {
    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        char db_file[MAX_PATH_LEN + 128];
        snprintf(db_file, sizeof(db_file), "%s/%s.db", config->db_dir, j->name);

        FILE *fp = fopen(db_file, "r");
        if (!fp) continue;

        char record_ip[MAX_IP_LEN];
        int count = 0;
        int loaded_jail = 0;

        while (fscanf(fp, "%45s %d", record_ip, &count) == 2) {
            if (g_offender_count >= MAX_TRACKED_IPS) break;

            OffenderRecord *rec = (OffenderRecord*)calloc(1, sizeof(OffenderRecord));
            if (rec) {
                safe_strncpy(rec->ip, record_ip, sizeof(rec->ip));
                safe_strncpy(rec->jail_name, j->name, sizeof(rec->jail_name));
                rec->offense_count = count;
                rec->dirty = false;
                rec->next = g_offender_table;
                g_offender_table = rec;
                g_offender_count++;
                loaded_jail++;
            }
        }
        fclose(fp);
        if (loaded_jail > 0) {
            log_msg("INFO", "[STATE] Loaded %d persistent offender records into RAM for jail [%s].", loaded_jail, j->name);
        }
    }
}

void offender_db_sync_to_disk(const Config *config) {
    char mkdir_cmd[MAX_PATH_LEN + 64];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "%s 2>/dev/null", config->db_dir);
    int res = system(mkdir_cmd);
    (void)res;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        char db_file[MAX_PATH_LEN + 128];
        snprintf(db_file, sizeof(db_file), "%s/%s.db", config->db_dir, j->name);

        // If file was deleted by --reset CLI, don't overwrite it with stale RAM data
        if (access(db_file, F_OK) != 0 && g_offender_count == 0) {
            continue;
        }

        char temp_file[MAX_PATH_LEN + 128];
        snprintf(temp_file, sizeof(temp_file), "%s/%s.db.tmp", config->db_dir, j->name);

        FILE *tfp = fopen(temp_file, "w");
        if (!tfp) continue;

        OffenderRecord *curr = g_offender_table;
        while (curr) {
            if (strcmp(curr->jail_name, j->name) == 0) {
                fprintf(tfp, "%s %d\n", curr->ip, curr->offense_count);
                curr->dirty = false;
            }
            curr = curr->next;
        }

        fclose(tfp);
        rename(temp_file, db_file);
    }
}

void offender_db_reload(const Config *config) {
    // 1. Free existing in-memory offender table
    OffenderRecord *off = g_offender_table;
    while (off) {
        OffenderRecord *next_off = off->next;
        free(off);
        off = next_off;
    }
    g_offender_table = NULL;
    g_offender_count = 0;

    // 2. Reload state from .db files
    offender_db_init(config);
}

int offender_db_get_count(const char *jail_name, const char *ip) {
    OffenderRecord *curr = g_offender_table;
    while (curr) {
        if (strcmp(curr->jail_name, jail_name) == 0 && strcmp(curr->ip, ip) == 0) {
            return curr->offense_count;
        }
        curr = curr->next;
    }
    return 0;
}

int offender_db_increment(const char *jail_name, const char *ip) {
    OffenderRecord *curr = g_offender_table;
    while (curr) {
        if (strcmp(curr->jail_name, jail_name) == 0 && strcmp(curr->ip, ip) == 0) {
            curr->offense_count++;
            curr->dirty = true;
            return curr->offense_count;
        }
        curr = curr->next;
    }

    // Hard Memory Cap Guard: Evict oldest if MAX_TRACKED_IPS exceeded
    if (g_offender_count >= MAX_TRACKED_IPS) {
        OffenderRecord *prev = NULL;
        OffenderRecord *tail = g_offender_table;
        while (tail && tail->next) {
            prev = tail;
            tail = tail->next;
        }
        if (prev && tail) {
            prev->next = NULL;
            free(tail);
            g_offender_count--;
        }
    }

    OffenderRecord *new_rec = (OffenderRecord*)calloc(1, sizeof(OffenderRecord));
    if (!new_rec) return 1;

    safe_strncpy(new_rec->ip, ip, sizeof(new_rec->ip));
    safe_strncpy(new_rec->jail_name, jail_name, sizeof(new_rec->jail_name));
    new_rec->offense_count = 1;
    new_rec->dirty = true;
    new_rec->next = g_offender_table;
    g_offender_table = new_rec;
    g_offender_count++;

    return 1;
}

/* ==============================================================================
 * WHITELIST VALIDATION LOGIC
 * ============================================================================== */

static bool check_ip_in_string(const char *whitelist_str, const char *ip) {
    if (!whitelist_str || whitelist_str[0] == '\0') {
        return false;
    }

    char list_copy[MAX_IGNOREIP_LEN];
    safe_strncpy(list_copy, whitelist_str, sizeof(list_copy));

    // Strip quotes if wrapped
    size_t len = strlen(list_copy);
    if (len >= 2 && list_copy[0] == '"' && list_copy[len - 1] == '"') {
        list_copy[len - 1] = '\0';
        memmove(list_copy, list_copy + 1, len - 1);
    }

    char *saveptr = NULL;
    char *token = strtok_r(list_copy, " ,\t", &saveptr);
    while (token) {
        char clean_token[MAX_NAME_LEN];
        safe_strncpy(clean_token, token, sizeof(clean_token));

        char *slash = strchr(clean_token, '/');
        if (slash) *slash = '\0';

        if (strcmp(clean_token, ip) == 0) {
            return true;
        }
        token = strtok_r(NULL, " ,\t", &saveptr);
    }

    return false;
}

static bool is_whitelisted(const Config *config, const Jail *jail, const char *ip) {
    // 1. Always protect loopback IPs
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) {
        return true;
    }

    // 2. Check global default whitelist
    if (config && check_ip_in_string(config->default_ignoreip, ip)) {
        return true;
    }

    // 3. Check jail-specific whitelist
    if (jail && check_ip_in_string(jail->ignoreip, ip)) {
        return true;
    }

    return false;
}

/* ==============================================================================
 * IP & INCREMENTAL BAN FACTOR LOGIC
 * ============================================================================== */

static IPEntry* get_or_create_ip(const char *ip) {
    IPEntry *curr = g_ip_table;
    while (curr) {
        if (strcmp(curr->ip, ip) == 0) return curr;
        curr = curr->next;
    }
    IPEntry *new_node = (IPEntry*)calloc(1, sizeof(IPEntry));
    safe_strncpy(new_node->ip, ip, sizeof(new_node->ip));
    new_node->next = g_ip_table;
    g_ip_table = new_node;
    return new_node;
}

void clear_all_ip_trackers(void) {
    IPEntry *curr = g_ip_table;
    while (curr) {
        IPEntry *next_ip = curr->next;
        EventNode *ev = curr->events;
        while (ev) {
            EventNode *next_ev = ev->next;
            free(ev);
            ev = next_ev;
        }
        free(curr);
        curr = next_ip;
    }
    g_ip_table = NULL;

    OffenderRecord *off = g_offender_table;
    while (off) {
        OffenderRecord *next_off = off->next;
        free(off);
        off = next_off;
    }
    g_offender_table = NULL;
    g_offender_count = 0;
}

int calculate_incremental_ban(const Config *config, const Jail *jail, const char *ip, int offender_count) {
    if (jail->bantime <= 0) return 0; // Explicit permanent mode

    int factor = (jail->banfactor > 0) ? jail->banfactor : config->default_banfactor;
    if (factor < 1) factor = 2;

    int max_cap = jail->max_bantime;
    bool allows_permanent = (max_cap <= 0 || max_cap > TEN_YEARS_SEC);

    // Dynamic target limit: use max_cap if finite, otherwise target 10y ceiling
    long long target_limit = allows_permanent ? TEN_YEARS_SEC : max_cap;

    long long calculated_ban = jail->bantime;

    for (int i = 1; i < offender_count; i++) {
        if (calculated_ban >= target_limit) {
            calculated_ban = target_limit;
            break;
        }

        calculated_ban *= factor;

        if (calculated_ban >= target_limit || calculated_ban < 0) {
            calculated_ban = target_limit;
            break;
        }
    }

    // 1. Permanent Ban Path
    if (calculated_ban >= TEN_YEARS_SEC && allows_permanent) {
        log_msg("INFO", "[BANFACTOR] IP %s hit count (%d) reached 10y threshold. Promoting to PERMANENT ban.",
                ip, offender_count);
        return 0; // Signal permanent ban (0s)
    }

    // 2. Finite Cap Path
    if (!allows_permanent && calculated_ban >= max_cap) {
        log_msg("INFO", "[BANFACTOR] IP %s hit count (%d) reached max threshold (%ds). Capping ban at jail limit.",
                ip, offender_count, max_cap);
        return max_cap;
    }

    // 3. Normal calculated ban duration
    return (int)calculated_ban;
}

void evaluate_entry(const LogEntry *entry, const Jail *jail, const char *matched_ip, Config *config) {
    if (is_whitelisted(config, jail, matched_ip)) {
        log_msg("DEBUG", "[WHITELIST] IP %s is whitelisted in jail [%s]. Skipping evaluation.", matched_ip, jail->name);
        return;
    }

    IPEntry *ip_node = get_or_create_ip(matched_ip);

    // 1. Tag event node with current jail name and millisecond timestamp
    EventNode *new_ev = (EventNode*)calloc(1, sizeof(EventNode));
    new_ev->timestamp_ms = entry->timestamp_ms;
    safe_strncpy(new_ev->jail_name, jail->name, sizeof(new_ev->jail_name));
    new_ev->next = ip_node->events;
    ip_node->events = new_ev;

    // 2. Count hits matching THIS jail within findtime window (converted to ms)
    int hits = 0;
    uint64_t findtime_ms = (uint64_t)jail->findtime * 1000ULL;
    EventNode **curr_ptr = &ip_node->events;

    while (*curr_ptr) {
        EventNode *ev = *curr_ptr;
        if (entry->timestamp_ms - ev->timestamp_ms > findtime_ms) {
            *curr_ptr = ev->next;
            free(ev);
        } else {
            // ONLY count timestamps belonging to this specific jail!
            if (strcmp(ev->jail_name, jail->name) == 0) {
                hits++;
            }
            curr_ptr = &ev->next;
        }
    }

    if (hits >= jail->maxretry) {
        int new_offender_count = offender_db_increment(jail->name, matched_ip);
        int final_bantime = calculate_incremental_ban(config, jail, matched_ip, new_offender_count);
        int factor = (jail->banfactor > 0) ? jail->banfactor : config->default_banfactor;

        char ban_duration_str[32];
        if (final_bantime <= 0) {
            snprintf(ban_duration_str, sizeof(ban_duration_str), "Permanent");
        } else {
            snprintf(ban_duration_str, sizeof(ban_duration_str), "%ds", final_bantime);
        }

        log_msg("INFO", "[BAN] IP %s -> [%s] | Base: %ds | Factor: %d | Offense: #%d | Banned for: %s",
                matched_ip, jail->name, jail->bantime, factor, new_offender_count, ban_duration_str);

        firewall_ban_ip(jail->nft_set_name, matched_ip, final_bantime);

        uint64_t now_ms = get_current_time_ms();
        uint64_t expire_ms = (final_bantime > 0) ? (now_ms + ((uint64_t)final_bantime * 1000ULL)) : 0;
        register_active_ban(matched_ip, jail->name, jail->nft_set_name, final_bantime, expire_ms);

        // Clear events belonging to THIS jail upon ban trigger
        curr_ptr = &ip_node->events;
        while (*curr_ptr) {
            EventNode *ev = *curr_ptr;
            if (strcmp(ev->jail_name, jail->name) == 0) {
                *curr_ptr = ev->next;
                free(ev);
            } else {
                curr_ptr = &ev->next;
            }
        }
    }
}
