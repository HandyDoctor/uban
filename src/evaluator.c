/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        evaluator.c
 * Description: SQLite state engine, retry threshold evaluation, and escalation tracking.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"
#include <sys/stat.h>
#include <time.h>
#include <math.h>

static sqlite3 *g_db = NULL;
static IPEntry *g_ip_table = NULL;

const Jail* find_jail_by_name(const Config *config, const char *jail_name) {
    if (!config || !jail_name) return NULL;
    for (int i = 0; i < config->jail_count; i++) {
        if (strcmp(config->jails[i].name, jail_name) == 0) {
            return &config->jails[i];
        }
    }
    return NULL;
}

/* ==============================================================================
 * SQLITE STORAGE ADAPTER (PRAGMA WAL, ACID POINT LOOKUPS & UPSERTS)
 * ============================================================================== */

int uban_db_init(const Config *config) {
    if (g_db) return 0; // Already initialized

    if (!config || strlen(config->db_dir) == 0) {
        log_msg("ERROR", "[DB] Invalid database configuration or db_dir is empty.");
        return -1;
    }
  
    /* Initialize the SQLite core engine and memory allocator subsystems */
    int rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        log_msg("ERROR", "[DB] Failed to initialize SQLite library engine (rc: %d)", rc);
        return -1;
    }

    char db_path[MAX_PATH_LEN + 64];
    snprintf(db_path, sizeof(db_path), "%s/uban.sqlite", config->db_dir);

    rc = sqlite3_open_v2(db_path, &g_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        log_msg("ERROR", "[DB] Failed to open SQLite database at %s (rc: %d)", db_path, rc);
        if (g_db) {
            sqlite3_close(g_db);
            g_db = NULL;
        }
        return -1;
    }

    // Set Pragmas safely
    sqlite3_exec(g_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA synchronous = NORMAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA busy_timeout = 5000;", NULL, NULL, NULL);

    const char *schema_sql =
        "CREATE TABLE IF NOT EXISTS uban_records ("
        "    ip            TEXT    NOT NULL,"
        "    jail          TEXT    NOT NULL,"
        "    ban_end       INTEGER NOT NULL DEFAULT -1,"
        "    orig_ban_time INTEGER NOT NULL DEFAULT -1,"
        "    ban_count     INTEGER NOT NULL DEFAULT 1,"
        "    last_update   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),"
        "    PRIMARY KEY (ip, jail)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_uban_ip ON uban_records(ip);"
        "CREATE INDEX IF NOT EXISTS idx_uban_jail ON uban_records(jail);"
        "CREATE INDEX IF NOT EXISTS idx_uban_lookup ON uban_records(jail, ip);"
        "CREATE INDEX IF NOT EXISTS idx_uban_eviction ON uban_records(ban_end, last_update);";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_db, schema_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        log_msg("ERROR", "[DB] Schema creation error: %s", err_msg ? err_msg : "unknown");
        if (err_msg) sqlite3_free(err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Clean init: suppressed noisy INFO message so CLI tools like 'uban status' stay quiet
    return 0;
}

void uban_db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

int uban_db_get_record(const char *jail_name, const char *ip, int *out_count, long long *out_ban_end, int *out_orig_ban_time) {
    if (!g_db) return 0;

    const char *sql = "SELECT ban_count, ban_end, orig_ban_time FROM uban_records WHERE jail = ? AND ip = ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, jail_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_STATIC);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
        if (out_count) *out_count = count;
        if (out_ban_end) *out_ban_end = sqlite3_column_int64(stmt, 1);
        if (out_orig_ban_time) *out_orig_ban_time = sqlite3_column_int(stmt, 2);
    } else {
        if (out_count) *out_count = 0;
        if (out_ban_end) *out_ban_end = -1;
        if (out_orig_ban_time) *out_orig_ban_time = -1;
    }

    sqlite3_finalize(stmt);
    return count;
}

int uban_db_upsert_ban(const char *jail_name, const char *ip, long long ban_end, int orig_ban_time, int *out_new_count) {
    if (!g_db) return 1;

    const char *sql = 
        "INSERT INTO uban_records (ip, jail, ban_end, orig_ban_time, ban_count, last_update) "
        "VALUES (?, ?, ?, ?, 1, strftime('%s', 'now')) "
        "ON CONFLICT(ip, jail) DO UPDATE SET "
        "  ban_end = excluded.ban_end, "
        "  orig_ban_time = excluded.orig_ban_time, "
        "  ban_count = ban_count + 1, "
        "  last_update = excluded.last_update "
        "RETURNING ban_count;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 1;

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, jail_name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, ban_end);
    sqlite3_bind_int(stmt, 4, orig_ban_time);

    int new_count = 1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        new_count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (out_new_count) *out_new_count = new_count;
    return new_count;
}

int uban_db_flush_ram_state(void) {
    if (!g_db) return 0;

    ActiveBanNode *scan = get_active_bans_head();
    if (!scan) return 0;

    const char *sql = 
        "INSERT INTO uban_records (ip, jail, ban_end, orig_ban_time, ban_count, last_update) "
        "VALUES (?, ?, ?, ?, ?, strftime('%s', 'now')) "
        "ON CONFLICT(ip, jail) DO UPDATE SET "
        "  ban_end = excluded.ban_end, "
        "  orig_ban_time = excluded.orig_ban_time, "
        "  ban_count = excluded.ban_count, "
        "  last_update = excluded.last_update;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_msg("ERROR", "[DB] Failed to prepare flush statement: %s", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_exec(g_db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    int flushed = 0;
    while (scan) {
        if (scan->dirty) {
            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, scan->ip, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, scan->jail_name, -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, scan->ban_end);
            sqlite3_bind_int(stmt, 4, scan->ban_duration);
            sqlite3_bind_int(stmt, 5, scan->offense_count);

            if (sqlite3_step(stmt) == SQLITE_DONE) {
                flushed++;
                scan->dirty = false;
            }
        }
        scan = scan->next;
    }

    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
    sqlite3_finalize(stmt);

    if (flushed > 0) {
        log_msg("DEBUG", "[DB] Synchronized %d dirty ban records from RAM to SQLite.", flushed);
    }
    return flushed;
}

int uban_db_mark_expired(time_t now) {
    if (!g_db) return -1;

    const char *sql = 
        "UPDATE uban_records "
        "SET ban_end = -1, last_update = strftime('%s', 'now') "
        "WHERE ban_end > 0 AND ban_end <= ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (long long)now);
    sqlite3_step(stmt);
    int changes = sqlite3_changes(g_db);
    sqlite3_finalize(stmt);

    return changes;
}

int uban_db_mark_inactive(const char *jail_name, const char *ip) {
    if (!g_db) return -1;

    const char *sql = 
        "UPDATE uban_records "
        "SET ban_end = -1, orig_ban_time = -1, last_update = strftime('%s', 'now') "
        "WHERE ip = ? AND jail = ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, jail_name, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

int uban_db_unban_ip_all(const char *ip) {
    if (!g_db) return 0;

    const char *sql = 
        "UPDATE uban_records "
        "SET ban_end = -1, orig_ban_time = -1, last_update = strftime('%s', 'now') "
        "WHERE ip = ? AND (ban_end = 0 OR ban_end > strftime('%s', 'now'));";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    int changes = sqlite3_changes(g_db);
    sqlite3_finalize(stmt);
    return changes;
}

int uban_db_flush_jail(const char *jail_name, bool reset) {
    if (!g_db) return -1;
    char sql[256];

    if (reset) {
        snprintf(sql, sizeof(sql), "DELETE FROM uban_records WHERE jail = ?;");
    } else {
        snprintf(sql, sizeof(sql), "UPDATE uban_records SET ban_end = -1, orig_ban_time = -1, last_update = strftime('%%s', 'now') WHERE jail = ?;");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, jail_name, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

int uban_db_flush_all(bool reset) {
    if (!g_db) return -1;

    if (reset) {
        return sqlite3_exec(g_db, "DELETE FROM uban_records;", NULL, NULL, NULL);
    } else {
        return sqlite3_exec(g_db, "UPDATE uban_records SET ban_end = -1, orig_ban_time = -1, last_update = strftime('%s', 'now');", NULL, NULL, NULL);
    }
}

void uban_db_purge_orphans(const Config *config) {
    if (!g_db || !config) return;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT DISTINCT jail FROM uban_records;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_msg("ERROR", "[DB] Failed to prepare orphan query: %s", sqlite3_errmsg(g_db));
        return;
    }

    char (*orphans)[MAX_NAME_LEN] = calloc(MAX_JAILS, sizeof(*orphans));
    if (!orphans) {
        sqlite3_finalize(stmt);
        return;
    }

    int orphan_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && orphan_count < MAX_JAILS) {
        const char *jname = (const char*)sqlite3_column_text(stmt, 0);
        if (!jname || jname[0] == '\0') continue;

        bool found = false;
        for (int i = 0; i < config->jail_count; i++) {
            if (strcmp(config->jails[i].name, jname) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            safe_strncpy(orphans[orphan_count], jname, MAX_NAME_LEN);
            orphan_count++;
        }
    }
    sqlite3_finalize(stmt);

    for (int i = 0; i < orphan_count; i++) {
        if (orphans[i][0] == '\0') continue;

        uban_db_flush_jail(orphans[i], true);

        char nft_set_name[MAX_MATCH_LEN];
        snprintf(nft_set_name, sizeof(nft_set_name), "uban_%.63s", orphans[i]);
        for (int c = 0; nft_set_name[c]; c++) {
            if (nft_set_name[c] == '-') nft_set_name[c] = '_';
        }

        char del_cmd[256];
        snprintf(del_cmd, sizeof(del_cmd), "nft delete set inet uban_filter %s 2>/dev/null", nft_set_name);
        int res = system(del_cmd);
        (void)res;

        log_msg("INFO", "[CLEANUP] Deleted orphaned jail [%s] from database and firewall sets.", orphans[i]);
    }

    free(orphans);
}

int uban_db_load_runway(const Config *config, int max_capacity) {
    if (!g_db) return 0;

    const char *sql = 
        "SELECT ip, jail, ban_end, orig_ban_time, ban_count "
        "FROM uban_records "
        "WHERE ban_end > strftime('%s', 'now') "
        "  AND ban_end <= (strftime('%s', 'now') + 600) "
        "LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, max_capacity);

    int loaded = 0;
    time_t now_epoch = time(NULL);
    uint64_t now_mono = get_current_time_ms();

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *ip = (const char*)sqlite3_column_text(stmt, 0);
        const char *jail_name = (const char*)sqlite3_column_text(stmt, 1);
        long long ban_end = sqlite3_column_int64(stmt, 2);
        int orig_ban_time = sqlite3_column_int(stmt, 3);
        int ban_count = sqlite3_column_int(stmt, 4);

        const Jail *j = find_jail_by_name(config, jail_name);
        if (!j) continue;

        long long remaining_sec = ban_end - now_epoch;
        if (remaining_sec > 0) {
            uint64_t expire_ms = now_mono + (uint64_t)remaining_sec * 1000ULL;
            bool is_max = (j->max_bantime > 0 && orig_ban_time >= j->max_bantime);
            register_active_ban_full(ip, jail_name, j->nft_set_name, orig_ban_time,
                                     expire_ms, ban_end, ban_count, is_max, false);
            loaded++;
        }
    }
    sqlite3_finalize(stmt);
    return loaded;
}

int uban_db_get_runway_count(const Config *config, const char *target_app, const char *target_jail) {
    if (!g_db) return 0;

    sqlite3_stmt *stmt = NULL;
    char sql[1024];

    if (target_jail && strlen(target_jail) > 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*) FROM uban_records "
                 "WHERE jail = ? "
                 "  AND ban_end > strftime('%%s', 'now') "
                 "  AND ban_end <= (strftime('%%s', 'now') + 600);");
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
        sqlite3_bind_text(stmt, 1, target_jail, -1, SQLITE_STATIC);
    } else if (target_app && strlen(target_app) > 0 && config) {
        int matching = 0;
        char in_clause[512] = "";
        for (int i = 0; i < config->jail_count; i++) {
            if (strcmp(config->jails[i].app_name, target_app) == 0) {
                if (matching > 0) strncat(in_clause, ", ", sizeof(in_clause) - strlen(in_clause) - 1);
                strncat(in_clause, "?", sizeof(in_clause) - strlen(in_clause) - 1);
                matching++;
            }
        }
        if (matching == 0) return 0;

        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*) FROM uban_records "
                 "WHERE jail IN (%s) "
                 "  AND ban_end > strftime('%%s', 'now') "
                 "  AND ban_end <= (strftime('%%s', 'now') + 600);", in_clause);
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

        int bind_idx = 1;
        for (int i = 0; i < config->jail_count; i++) {
            if (strcmp(config->jails[i].app_name, target_app) == 0) {
                sqlite3_bind_text(stmt, bind_idx++, config->jails[i].name, -1, SQLITE_STATIC);
            }
        }
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*) FROM uban_records "
                 "WHERE ban_end > strftime('%%s', 'now') "
                 "  AND ban_end <= (strftime('%%s', 'now') + 600);");
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int uban_db_purge_history(const Config *config) {
    if (!g_db || !config->db_purge_enable) return 0;

    const char *sql = 
        "DELETE FROM uban_records "
        "WHERE ban_end = -1 "
        "  AND last_update <= (strftime('%s', 'now') - ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, config->db_purge_age);
    sqlite3_step(stmt);
    int purged = sqlite3_changes(g_db);
    sqlite3_finalize(stmt);

    if (purged > 0) {
        log_msg("INFO", "[PURGE] Cleaned up %d expired history records older than %ds from database.", purged, config->db_purge_age);
    }
    return purged;
}

int uban_db_get_counts(const Config *config, const char *target_app, const char *target_jail, int *out_active, int *out_total) {
    if (!g_db) return -1;
    if (out_active) *out_active = 0;
    if (out_total) *out_total = 0;

    sqlite3_stmt *stmt = NULL;
    char sql[1024];

    if (target_jail && strlen(target_jail) > 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT "
                 "  COALESCE(SUM(CASE WHEN ban_end = 0 OR ban_end > strftime('%%s', 'now') THEN 1 ELSE 0 END), 0), "
                 "  COUNT(*) "
                 "FROM uban_records WHERE jail = ?;");
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_text(stmt, 1, target_jail, -1, SQLITE_STATIC);
    } else if (target_app && strlen(target_app) > 0 && config) {
        int matching = 0;
        char in_clause[512] = "";
        for (int i = 0; i < config->jail_count; i++) {
            if (strcmp(config->jails[i].app_name, target_app) == 0) {
                if (matching > 0) strncat(in_clause, ", ", sizeof(in_clause) - strlen(in_clause) - 1);
                strncat(in_clause, "?", sizeof(in_clause) - strlen(in_clause) - 1);
                matching++;
            }
        }
        if (matching == 0) return 0;

        snprintf(sql, sizeof(sql),
                 "SELECT "
                 "  COALESCE(SUM(CASE WHEN ban_end = 0 OR ban_end > strftime('%%s', 'now') THEN 1 ELSE 0 END), 0), "
                 "  COUNT(*) "
                 "FROM uban_records WHERE jail IN (%s);", in_clause);

        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

        int bind_idx = 1;
        for (int i = 0; i < config->jail_count; i++) {
            if (strcmp(config->jails[i].app_name, target_app) == 0) {
                sqlite3_bind_text(stmt, bind_idx++, config->jails[i].name, -1, SQLITE_STATIC);
            }
        }
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT "
                 "  COALESCE(SUM(CASE WHEN ban_end = 0 OR ban_end > strftime('%%s', 'now') THEN 1 ELSE 0 END), 0), "
                 "  COUNT(*) "
                 "FROM uban_records;");
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (out_active) *out_active = sqlite3_column_int(stmt, 0);
        if (out_total) *out_total = sqlite3_column_int(stmt, 1);
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* ==============================================================================
 * WHITELIST VALIDATION LOGIC
 * ============================================================================== */

static bool ip_matches_pattern(const char *ip_str, const char *pattern) {
    if (!ip_str || !pattern) return false;

    char clean_pat[MAX_IGNOREIP_LEN];
    safe_strncpy(clean_pat, pattern, sizeof(clean_pat));

    char *slash = strchr(clean_pat, '/');
    int prefix_len = 32;

    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) return false;
    }

    struct in_addr ip_addr, net_addr;
    if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) return false;
    if (inet_pton(AF_INET, clean_pat, &net_addr) != 1) return false;

    uint32_t ip = ntohl(ip_addr.s_addr);
    uint32_t net = ntohl(net_addr.s_addr);
    uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));

    return (ip & mask) == (net & mask);
}

static bool check_ip_in_string(const char *whitelist_str, const char *ip) {
    if (!whitelist_str || whitelist_str[0] == '\0') {
        return false;
    }

    char list_copy[MAX_IGNOREIP_LEN];
    safe_strncpy(list_copy, whitelist_str, sizeof(list_copy));

    size_t len = strlen(list_copy);
    if (len >= 2 && list_copy[0] == '"' && list_copy[len - 1] == '"') {
        list_copy[len - 1] = '\0';
        memmove(list_copy, list_copy + 1, len - 1);
    }

    char *saveptr = NULL;
    char *token = strtok_r(list_copy, " ,\t", &saveptr);
    while (token) {
        if (ip_matches_pattern(ip, token)) {
            return true;
        }
        token = strtok_r(NULL, " ,\t", &saveptr);
    }

    return false;
}

static bool is_whitelisted(const Config *config, const Jail *jail, const char *ip) {
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) {
        return true;
    }
    if (config && check_ip_in_string(config->default_ignoreip, ip)) {
        return true;
    }
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
}

int calculate_incremental_ban(const Config *config, const Jail *jail, const char *ip, int offender_count) {
    if (jail->bantime <= 0) return 0; // Explicit permanent mode

    int factor = (jail->banfactor > 0) ? jail->banfactor : config->default_banfactor;
    if (factor < 1) factor = 2;

    int max_cap = jail->max_bantime;
    bool allows_permanent = (max_cap <= 0 || max_cap > TEN_YEARS_SEC);

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

    if (calculated_ban >= TEN_YEARS_SEC && allows_permanent) {
        log_msg("INFO", "[BANFACTOR] IP %s hit count (%d) reached 10y threshold. Promoting to PERMANENT ban.",
                ip, offender_count);
        return 0;
    }

    if (!allows_permanent && calculated_ban >= max_cap) {
        log_msg("INFO", "[BANFACTOR] IP %s hit count (%d) reached max threshold (%ds). Capping ban at jail limit.",
                ip, offender_count, max_cap);
        return max_cap;
    }

    return (int)calculated_ban;
}

void evaluate_entry(const LogEntry *entry, const Jail *jail, const char *matched_ip, Config *config) {
    if (is_whitelisted(config, jail, matched_ip)) {
        log_msg("DEBUG", "[WHITELIST] IP %s is whitelisted in jail [%s]. Skipping evaluation.", matched_ip, jail->name);
        return;
    }

    IPEntry *ip_node = get_or_create_ip(matched_ip);

    // Tag event node with current jail name and monotonic millisecond timestamp
    EventNode *new_ev = (EventNode*)calloc(1, sizeof(EventNode));
    new_ev->timestamp_ms = entry->timestamp_ms;
    safe_strncpy(new_ev->jail_name, jail->name, sizeof(new_ev->jail_name));
    new_ev->next = ip_node->events;
    ip_node->events = new_ev;

    // Count hits matching THIS jail within findtime window
    int hits = 0;
    uint64_t findtime_ms = (uint64_t)jail->findtime * 1000ULL;
    EventNode **curr_ptr = &ip_node->events;

    while (*curr_ptr) {
        EventNode *ev = *curr_ptr;
        if (entry->timestamp_ms - ev->timestamp_ms > findtime_ms) {
            *curr_ptr = ev->next;
            free(ev);
        } else {
            if (strcmp(ev->jail_name, jail->name) == 0) {
                hits++;
            }
            curr_ptr = &ev->next;
        }
    }

    if (hits >= jail->maxretry) {
        time_t now_epoch = time(NULL);
        uint64_t now_mono = get_current_time_ms();

        // -------------------------------------------------------------
        // BRANCH A: CHECK RAM FIRST (Zero disk I/O, sub-nanosecond path)
        // -------------------------------------------------------------
        ActiveBanNode *ram_node = find_active_ban(jail->name, matched_ip);
        if (ram_node) {
            bool is_currently_banned = (ram_node->ban_end == 0 || ram_node->ban_end > (long long)now_epoch);

            if (is_currently_banned && ram_node->is_max_ban) {
                // IP is actively banned and already at max ban factor -> Suppress in RAM
                ram_node->offense_count++;
                ram_node->dirty = true;
                log_msg("DEBUG", "[SUPPRESSED] IP %s -> [%s] already max banned (Offense #%d in RAM)",
                        matched_ip, jail->name, ram_node->offense_count);
            } else {
                // Either actively escalating or re-offending after an expiration: increment offense_count
                ram_node->offense_count++;
                int final_bantime = calculate_incremental_ban(config, jail, matched_ip, ram_node->offense_count);
                bool is_max = (final_bantime <= 0 || (jail->max_bantime > 0 && final_bantime >= jail->max_bantime));

                char ban_duration_str[32];
                if (final_bantime <= 0) {
                    snprintf(ban_duration_str, sizeof(ban_duration_str), "Permanent");
                } else {
                    snprintf(ban_duration_str, sizeof(ban_duration_str), "%ds", final_bantime);
                }

                int factor = (jail->banfactor > 0) ? jail->banfactor : config->default_banfactor;
                log_msg("INFO", "[BAN] IP %s -> [%s] | Base: %ds | Factor: %d | Offense: #%d | Banned for: %s",
                        matched_ip, jail->name, jail->bantime, factor, ram_node->offense_count, ban_duration_str);

                firewall_ban_ip(jail->nft_set_name, matched_ip, final_bantime);

                ram_node->ban_duration = final_bantime;
                ram_node->ban_end = (final_bantime > 0) ? ((long long)now_epoch + final_bantime) : 0;
                ram_node->expire_ms = (final_bantime > 0) ? (now_mono + ((uint64_t)final_bantime * 1000ULL)) : 0;
                ram_node->is_max_ban = is_max;
                ram_node->dirty = true;
            }
        } else {
            // ---------------------------------------------------------
            // BRANCH B: NOT IN RAM (Read SQLite for persistent history)
            // ---------------------------------------------------------
            int prior_strikes = 0;
            long long current_ban_end = -1;
            int current_orig_duration = -1;
            uban_db_get_record(jail->name, matched_ip, &prior_strikes, &current_ban_end, &current_orig_duration);

            int new_offender_count = (prior_strikes > 0) ? (prior_strikes + 1) : 1;
            int final_bantime = calculate_incremental_ban(config, jail, matched_ip, new_offender_count);
            bool is_max = (final_bantime <= 0 || (jail->max_bantime > 0 && final_bantime >= jail->max_bantime));

            char ban_duration_str[32];
            if (final_bantime <= 0) {
                snprintf(ban_duration_str, sizeof(ban_duration_str), "Permanent");
            } else {
                snprintf(ban_duration_str, sizeof(ban_duration_str), "%ds", final_bantime);
            }

            int factor = (jail->banfactor > 0) ? jail->banfactor : config->default_banfactor;
            log_msg("INFO", "[BAN] IP %s -> [%s] | Base: %ds | Factor: %d | Offense: #%d | Banned for: %s",
                    matched_ip, jail->name, jail->bantime, factor, new_offender_count, ban_duration_str);

            firewall_ban_ip(jail->nft_set_name, matched_ip, final_bantime);

            long long ban_end = (final_bantime > 0) ? ((long long)now_epoch + final_bantime) : 0;
            uint64_t expire_ms = (final_bantime > 0) ? (now_mono + ((uint64_t)final_bantime * 1000ULL)) : 0;

            register_active_ban_full(matched_ip, jail->name, jail->nft_set_name, final_bantime,
                                     expire_ms, ban_end, new_offender_count, is_max, true);
        }

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

void prune_stale_ip_trackers(void) {
    IPEntry **curr = &g_ip_table;
    while (*curr) {
        IPEntry *entry = *curr;
        // If there are no active retry events pending for this IP, free it
        if (entry->events == NULL) {
            *curr = entry->next;
            free(entry);
            continue;
        }
        curr = &(*curr)->next;
    }
}
