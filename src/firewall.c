/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        firewall.c
 * Description: Kernel-level nftables netlink/CLI wrapper for IP ban and unban enforcement.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"

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
    int res = system("nft add table inet uban_filter 2>/dev/null");
    (void)res;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];
        if (!j->enabled) continue;

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "nft add set inet uban_filter %s '{ type ipv4_addr; flags timeout; }' 2>/dev/null", j->nft_set_name);
        res = system(cmd);

        snprintf(cmd, sizeof(cmd), "nft add chain inet uban_filter input '{ type filter hook input priority -100; policy accept; }' 2>/dev/null");
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
        if (!j->enabled) continue;

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

int firewall_save_state(const Config *config) {
    char mkdir_cmd[MAX_PATH_LEN + 16];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", config->db_dir);
    int res = system(mkdir_cmd);
    (void)res;

    char state_file[MAX_PATH_LEN + 16];
    char tmp_state_file[MAX_PATH_LEN + 20];
    snprintf(state_file, sizeof(state_file), "%s/bans.state", config->db_dir);
    snprintf(tmp_state_file, sizeof(tmp_state_file), "%s/bans.state.tmp", config->db_dir);

    // 1. Pre-load existing 4th column from disk as fallback
    typedef struct {
        char jail[MAX_NAME_LEN];
        char ip[MAX_IP_LEN];
        int orig_duration;
    } ExistingStateItem;

    ExistingStateItem saved_items[512];
    int saved_count = 0;

    FILE *rfp = fopen(state_file, "r");
    if (rfp) {
        char line[MAX_LINE_LEN];
        char r_jail[MAX_NAME_LEN], r_ip[MAX_IP_LEN];
        int r_rem, r_orig;
        while (fgets(line, sizeof(line), rfp) && saved_count < 512) {
            if (sscanf(line, "%63s %45s %d %d", r_jail, r_ip, &r_rem, &r_orig) == 4) {
                safe_strncpy(saved_items[saved_count].jail, r_jail, MAX_NAME_LEN);
                safe_strncpy(saved_items[saved_count].ip, r_ip, MAX_IP_LEN);
                saved_items[saved_count].orig_duration = r_orig;
                saved_count++;
            }
        }
        fclose(rfp);
    }

    FILE *fp = fopen(tmp_state_file, "w");
    if (!fp) return -1;

    for (int i = 0; i < config->jail_count; i++) {
        const Jail *j = &config->jails[i];

        BanStatusItem *items = NULL;
        int count = 0;
        firewall_get_banned_ips(j->nft_set_name, &items, &count);

        for (int k = 0; k < count; k++) {
            // PRIORITY 1: Check RAM for fresh/escalated ban duration
            int orig_sec = get_active_ban_duration(j->nft_set_name, items[k].ip);

            // PRIORITY 2: If not in RAM, fall back to preserved disk 4th column
            if (orig_sec <= 0) {
                for (int s = 0; s < saved_count; s++) {
                    if (strcmp(saved_items[s].jail, j->name) == 0 && strcmp(saved_items[s].ip, items[k].ip) == 0) {
                        orig_sec = saved_items[s].orig_duration;
                        break;
                    }
                }
            }

            // PRIORITY 3: Fallback to nftables element / remaining TTL
            if (orig_sec <= 0) {
                orig_sec = (items[k].original_timeout_sec > 0) ? items[k].original_timeout_sec : items[k].expires_in_sec;
            }

            fprintf(fp, "%s %s %d %d\n", j->name, items[k].ip, items[k].expires_in_sec, orig_sec);
        }
        firewall_free_status_items(items);
    }

    fclose(fp);
    rename(tmp_state_file, state_file);
    return 0;
}

int firewall_restore_state(const Config *config) {
    char state_file[MAX_PATH_LEN + 32];
    snprintf(state_file, sizeof(state_file), "%s/bans.state", config->db_dir);

    FILE *fp = fopen(state_file, "r");
    if (!fp) return 0;

    char jail_name[MAX_NAME_LEN];
    char ip[MAX_IP_LEN];
    int expires_in_sec;
    int orig_duration;
    int restored_count = 0;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63s %45s %d %d", jail_name, ip, &expires_in_sec, &orig_duration) != 4) {
            continue;
        }

        for (int i = 0; i < config->jail_count; i++) {
            const Jail *j = &config->jails[i];
            if (strcmp(j->name, jail_name) == 0 && j->enabled) {
                if (expires_in_sec > 0 || expires_in_sec == -1) {
                    firewall_ban_ip(j->nft_set_name, ip, expires_in_sec);

                    uint64_t now_ms = get_current_time_ms();
                    uint64_t expire_ms = (expires_in_sec > 0) ? (now_ms + ((uint64_t)expires_in_sec * 1000ULL)) : 0;

                    // Passes orig_duration so tracked->ban_duration holds true initial length
                    register_active_ban(ip, j->name, j->nft_set_name, orig_duration, expire_ms);
                    restored_count++;
                }
            }
        }
    }

    fclose(fp);

    if (restored_count > 0) {
        log_msg("INFO", "[STATE] Restored %d active bans from state file.", restored_count);
    }
    return restored_count;
}
