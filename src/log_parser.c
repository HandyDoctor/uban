/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        log_parser.c
 * Description: Delimiter-aware token extraction and positional string matching engine.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#define _GNU_SOURCE
#include "uban.h"

// Token node structure for zero-heap single-pass tokenizer
typedef struct {
    const char *start;
    size_t length;
} Token;

// Single-pass tokenizer enforcing outermost enclosures and flanked single quotes
static int tokenize_line(const char *line, Token *tokens, int max_tokens) {
    int count = 0;
    const char *p = line;

    while (*p && count < max_tokens) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        const char *token_start = p;
        char close_char = 0;

        if (*p == '"') close_char = '"';
        else if (*p == '[') close_char = ']';
        else if (*p == '{') close_char = '}';
        else if (*p == '(') close_char = ')';
        else if (*p == '<') close_char = '>';
        else if (*p == '\'' && (p == line || isspace((unsigned char)*(p-1)))) close_char = '\'';

        if (close_char) {
            p++; // Skip opening boundary
            const char *inside_start = p;
            while (*p && *p != close_char) p++;
            
            if (*p == close_char) {
                // Successfully closed outer pair
                tokens[count].start = inside_start;
                tokens[count].length = p - inside_start;
                count++;
                p++; // Skip closing boundary
                continue;
            } else {
                // Degrade to space-delimited mode on unclosed pair
                p = token_start;
            }
        }

        // Standard space-delimited token
        token_start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        tokens[count].start = token_start;
        tokens[count].length = p - token_start;
        count++;
    }
    return count;
}

// Edge-anchored IP resolution with outward nearest-neighbor IPv4 fallback
static bool extract_ip_at_pos(Token *tokens, int token_count, int ip_pos, char *extracted_ip) {
    if (token_count <= 0) return false;

    int target_idx = -1;
    if (ip_pos > 0) {
        target_idx = ip_pos - 1; // 1-based left index
    } else if (ip_pos < 0) {
        target_idx = token_count + ip_pos; // Negative right index
    }

    if (target_idx < 0 || target_idx >= token_count) target_idx = 0;

    // Nearest-neighbor outward radiation loop
    for (int offset = 0; offset < token_count; offset++) {
        int check_indices[2] = { target_idx + offset, target_idx - offset };
        for (int i = 0; i < 2; i++) {
            int idx = check_indices[i];
            if (idx >= 0 && idx < token_count) {
                char buf[64];
                size_t len = tokens[idx].length < 63 ? tokens[idx].length : 63;
                strncpy(buf, tokens[idx].start, len);
                buf[len] = '\0';

                struct in_addr sa;
                if (inet_pton(AF_INET, buf, &sa) == 1) {
                    safe_strncpy(extracted_ip, buf, MAX_IP_LEN);
                    return true;
                }
            }
            if (offset == 0) break; // Avoid checking center index twice
        }
    }
    return false;
}

bool parse_log_line(const char *line, const Jail *jail, char *extracted_ip) {
    if (!line || strlen(line) == 0 || !jail || jail->match_count == 0) return false;

    bool pattern_matched = false;

    // Check each match target in jail configuration
    for (int m = 0; m < jail->match_count; m++) {
        const char *pattern = jail->match_strings[m];
        size_t pat_len = strlen(pattern);

        if (pat_len >= 6) {
            // FAST PATH: Raw strstr() scan directly on un-tokenized line
            if (strcasestr(line, pattern) != NULL) {
                pattern_matched = true;
                break;
            }
        } else {
            // SHORT PATH: Single-pass tokenizer for <= 5 chars enforcing match_pos
            Token tokens[128];
            int token_count = tokenize_line(line, tokens, 128);

            int target_idx = (jail->match_pos > 0) ? jail->match_pos - 1 : token_count + jail->match_pos;
            if (target_idx >= 0 && target_idx < token_count) {
                char buf[64];
                size_t len = tokens[target_idx].length < 63 ? tokens[target_idx].length : 63;
                strncpy(buf, tokens[target_idx].start, len);
                buf[len] = '\0';

                if (strcmp(buf, pattern) == 0) {
                    pattern_matched = true;
                    break;
                }
            }
        }
    }

    if (!pattern_matched) return false;

    // Pattern matched! Extract IP using edge-anchored rules
    Token tokens[128];
    int token_count = tokenize_line(line, tokens, 128);
    return extract_ip_at_pos(tokens, token_count, jail->ip_pos, extracted_ip);
}
