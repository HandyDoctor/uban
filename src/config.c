/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        config.c
 * Description: INI configuration parser, section evaluator, and jail rule loader.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include <strings.h>
#include "uban.h"
#include <ctype.h>

static char* strip_quotes(char *str) {
    if (!str) return str;
    size_t len = strlen(str);
    if (len >= 2 && str[0] == '"' && str[len - 1] == '"') {
        str[len - 1] = '\0';
        return str + 1;
    }
    return str;
}

static char* trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void strip_inline_comments(char *str) {
    bool in_quote = false;
    for (char *p = str; *p; p++) {
        if (*p == '"') in_quote = !in_quote;
        if (!in_quote && (*p == '#' || *p == ';')) {
            *p = '\0';
            break;
        }
    }
}

int parse_duration(const char *str) {
    if (!str || strlen(str) == 0) return 0;
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (val <= 0) return 0;

    while (*endptr && isspace((unsigned char)*endptr)) endptr++;
    if (*endptr == 'm' || *endptr == 'M') val *= 60;
    else if (*endptr == 'h' || *endptr == 'H') val *= 3600;
    else if (*endptr == 'd' || *endptr == 'D') val *= 86400;
    else if (*endptr == 'y' || *endptr == 'Y') val *= 31536000;

    return (int)val;
}

static bool is_app_enabled(const Config *config, const char *app_name) {
    for (int i = 0; i < config->app_count; i++) {
        if (strcmp(config->apps[i].name, app_name) == 0) {
            return config->apps[i].enabled;
        }
    }
    return true; // Default to enabled if no top-level app block exists
}

int load_config(const char *filepath, Config *config) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return -1;

    memset(config, 0, sizeof(Config));
    strcpy(config->firewall_backend, "nftables");
    strcpy(config->uban_logpath, "/var/log/uban/uban.log");
    strcpy(config->db_dir, "/var/lib/uban");
    strcpy(config->default_ignoreip, "127.0.0.1/8 ::1");
    config->default_banfactor = 1;
    config->default_max_bantime = TEN_YEARS_SEC;
    config->poll_interval_ms = 10;

    char line[MAX_LINE_LEN];
    char current_section[MAX_NAME_LEN] = "";
    Jail *current_jail = NULL;

    while (fgets(line, sizeof(line), fp)) {
        strip_inline_comments(line);
        char *s = trim(line);

        if (s[0] == '\0') continue;

        if (s[0] == '[' && s[strlen(s) - 1] == ']') {
            s[strlen(s) - 1] = '\0';
            strcpy(current_section, s + 1);

            if (strcasecmp(current_section, "global") == 0 || strcasecmp(current_section, "uban") == 0) {
                current_jail = NULL;
            } else {
                char *hyphen = strchr(current_section, '-');

                if (hyphen == NULL) {
                    // Top-level APP master section (e.g. [nginx], [sshd], [nginxDefault])
                    current_jail = NULL;
                    int app_idx = -1;
                    for (int i = 0; i < config->app_count; i++) {
                        if (strcmp(config->apps[i].name, current_section) == 0) {
                            app_idx = i;
                            break;
                        }
                    }
                    if (app_idx == -1 && config->app_count < MAX_APPS) {
                        app_idx = config->app_count++;
                        safe_strncpy(config->apps[app_idx].name, current_section, MAX_NAME_LEN);
                        config->apps[app_idx].enabled = true; // Default true until 'enabled = false' is read
                    }
                } else {
                    // Child JAIL section (e.g. [nginx-444_666], [sshd-retry])
                    if (config->jail_count < MAX_JAILS) {
                        current_jail = &config->jails[config->jail_count++];
                        memset(current_jail, 0, sizeof(Jail));
                        safe_strncpy(current_jail->name, current_section, sizeof(current_jail->name));

                        // Extract parent app name (prefix before hyphen)
                        size_t prefix_len = hyphen - current_section;
                        strncpy(current_jail->app_name, current_section, prefix_len);
                        current_jail->app_name[prefix_len] = '\0';

                        // Ensure parent app is tracked in config->apps[]
                        bool app_found = false;
                        for (int a = 0; a < config->app_count; a++) {
                            if (strcmp(config->apps[a].name, current_jail->app_name) == 0) {
                                app_found = true;
                                break;
                            }
                        }
                        if (!app_found && config->app_count < MAX_APPS) {
                            safe_strncpy(config->apps[config->app_count].name, current_jail->app_name, MAX_NAME_LEN);
                            config->apps[config->app_count].enabled = true;
                            config->app_count++;
                        }

                        snprintf(current_jail->nft_set_name, sizeof(current_jail->nft_set_name), "uban_%s", current_section);
                        for (int i = 0; current_jail->nft_set_name[i]; i++) {
                            if (current_jail->nft_set_name[i] == '-') current_jail->nft_set_name[i] = '_';
                        }

                        current_jail->ip_pos = 1;
                        current_jail->match_pos = 1;
                        current_jail->enabled = true; // Default true, updated if 'enabled = false' exists in this jail section
                        current_jail->banfactor = config->default_banfactor;
                        current_jail->max_bantime = config->default_max_bantime;
                    }
                }
            }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (strcasecmp(current_section, "global") == 0 || strcasecmp(current_section, "uban") == 0) {
            if (strcmp(key, "log_file") == 0) {
                safe_strncpy(config->uban_logpath, strip_quotes(val), sizeof(config->uban_logpath));
            } else if (strcmp(key, "db_dir") == 0) {
                safe_strncpy(config->db_dir, strip_quotes(val), sizeof(config->db_dir));
            } else if (strcmp(key, "ignoreip") == 0 || strcmp(key, "ignore_ip") == 0) {
                safe_strncpy(config->default_ignoreip, strip_quotes(val), sizeof(config->default_ignoreip));
            } else if (strcmp(key, "max_ban_time") == 0 || strcmp(key, "max_bantime") == 0) {
                config->default_max_bantime = parse_duration(strip_quotes(val));
            } else if (strcmp(key, "banfactor") == 0 || strcmp(key, "ban_factor") == 0) {
                config->default_banfactor = atoi(strip_quotes(val));
                if (config->default_banfactor < 1) config->default_banfactor = 2;
            } else if (strcmp(key, "poll_interval_ms") == 0) {
                config->poll_interval_ms = atoi(strip_quotes(val));
            }
        } else if (current_jail == NULL) {
            // Processing key-value for APP master block (e.g. [nginx])
            for (int i = 0; i < config->app_count; i++) {
                if (strcmp(config->apps[i].name, current_section) == 0) {
                    if (strcmp(key, "enabled") == 0) {
                        char *clean_val = strip_quotes(val);
                        config->apps[i].enabled = (strcasecmp(clean_val, "true") == 0 || strcmp(clean_val, "1") == 0);
                    }
                }
            }
        } else if (current_jail) {
            // Processing key-value for CHILD JAIL (e.g. [nginx-400_403_405])
            if (strcmp(key, "enabled") == 0) {
                char *clean_val = strip_quotes(val);
                current_jail->enabled = (strcasecmp(clean_val, "true") == 0 || strcmp(clean_val, "1") == 0);
            } else if (strcmp(key, "log_path") == 0) {
                safe_strncpy(current_jail->logpath, strip_quotes(val), sizeof(current_jail->logpath));
            } else if (strcmp(key, "ignoreip") == 0 || strcmp(key, "ignore_ip") == 0) {
                safe_strncpy(current_jail->ignoreip, strip_quotes(val), sizeof(current_jail->ignoreip));
            } else if (strcmp(key, "ip_pos") == 0) {
                current_jail->ip_pos = atoi(strip_quotes(val));
            } else if (strcmp(key, "match_pos") == 0) {
                current_jail->match_pos = atoi(strip_quotes(val));
            } else if (strcmp(key, "find_time") == 0) {
                current_jail->findtime = parse_duration(strip_quotes(val));
            } else if (strcmp(key, "max_retry") == 0) {
                current_jail->maxretry = atoi(strip_quotes(val));
            } else if (strcmp(key, "ban_time") == 0) {
                current_jail->bantime = parse_duration(strip_quotes(val));
            } else if (strcmp(key, "banfactor") == 0 || strcmp(key, "ban_factor") == 0) {
                current_jail->banfactor = atoi(strip_quotes(val));
                if (current_jail->banfactor < 1) current_jail->banfactor = config->default_banfactor;
            } else if (strcmp(key, "max_bantime") == 0 || strcmp(key, "max_ban_time") == 0) {
                current_jail->max_bantime = parse_duration(strip_quotes(val));
            } else if (strcmp(key, "match_string") == 0) {
                char *token = strtok(val, ",");
                while (token && current_jail->match_count < MAX_MATCH_PATTERNS) {
                    char *t = trim(token); // Trim outer spaces first
                    
                    // Strip outer double quotes if present
                    if (t[0] == '"') t++; 
                    size_t t_len = strlen(t);
                    if (t_len > 0 && t[t_len - 1] == '"') {
                        t[t_len - 1] = '\0';
                    }
                    
                    char *clean = trim(t); // Trim any remaining padding inside quotes
                    if (clean[0] != '\0') {
                        safe_strncpy(current_jail->match_strings[current_jail->match_count++], clean, MAX_MATCH_LEN);
                    }
                    token = strtok(NULL, ",");
                }
            }
        }
    }

    fclose(fp);

    // Final AND enforcement: Jail is active ONLY if both parent App AND Jail are enabled
    for (int i = 0; i < config->jail_count; i++) {
        bool app_on = is_app_enabled(config, config->jails[i].app_name);
        config->jails[i].enabled = app_on && config->jails[i].enabled;
    }

    set_log_path(config->uban_logpath);
    return 0;
}
