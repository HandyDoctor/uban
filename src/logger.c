/*
 * uban ("Universal Ban") - High-Performance C99 Security Daemon
 *
 * File:        logger.c
 * Description: Thread-safe daemon operational logging and alert formatting.
 *
 * Copyright (c) 2026 UBAN Security Engine Project
 * Licensed under the MIT License. See LICENSE in the project root.
 */

#include "uban.h"
#include <stdarg.h>

static char g_logpath[MAX_PATH_LEN] = "/var/log/uban/uban.log";

void set_log_path(const char *path) {
    if (path && strlen(path) > 0) {
        safe_strncpy(g_logpath, path, sizeof(g_logpath));
    }
}

void log_msg(const char *level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char date_buf[32];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", t);

    va_list args;
    printf("%s [%s] ", date_buf, level);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);

    FILE *fp = fopen(g_logpath, "a");
    if (!fp) {
        int res = system("mkdir -p /var/log/uban 2>/dev/null");
        (void)res;
        fp = fopen(g_logpath, "a");
    }

    if (fp) {
        fprintf(fp, "%s [%s] ", date_buf, level);
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);
        fprintf(fp, "\n");
        fclose(fp);
    }
}
