#include <stdarg.h>
#define _GNU_SOURCE
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void tls_bf_log_init() {
    char *log_env = secure_getenv("TLS_BF_LOG");
    tls_bf_log_level default_lvl = WARNING;
    if (log_env == NULL) {
        LOG_LEVEL = default_lvl;
    } else if (strcmp(log_env, "none") == 0) {
        LOG_LEVEL = NO_LOG;
    } else if (strcmp(log_env, "error") == 0) {
        LOG_LEVEL = ERROR;
    } else if (strcmp(log_env, "warning") == 0) {
        LOG_LEVEL = WARNING;
    } else if (strcmp(log_env, "info") == 0) {
        LOG_LEVEL = INFO;
    } else if (strcmp(log_env, "debug") == 0) {
        LOG_LEVEL = DEBUG;
    } else if (strcmp(log_env, "bf_debug") == 0) {
        LOG_LEVEL = BF_DEBUG;
    } else {
        puts("WARNING: Specified log level isn't valid, use one of \"none\", \"error\", \"warning\", \"info\", \"debug\", \"bf_debug\".\nUsing default level (warning).");
        LOG_LEVEL = default_lvl;
    }
}

// Log string and append line feed.
inline void tls_bf_log(tls_bf_log_level level, const char *log) {
    if (level <= LOG_LEVEL) {
        FILE *fd;
        switch (level) {
            case ERROR:
            case WARNING:
                fd = stderr;
                break;
            default:
                fd = stdout;
        }
        fputs(log_prefixes[level], fd);
        fputs(log, fd);
        fputs("\n", fd);
    }
}

// Log data with format string and append line feed.
inline void tls_bf_logf(tls_bf_log_level level, const char *fmt, ...) {
    if (level <= LOG_LEVEL) {
        FILE *fd;
        switch (level) {
            case ERROR:
            case WARNING:
                fd = stderr;
                break;
            default:
                fd = stdout;
        }
        fputs(log_prefixes[level], fd);
        va_list args;
        va_start(args, fmt);
        vfprintf(fd, fmt, args);
        va_end(args);
        fputs("\n", fd);
    }
}

// Log a bytearray and append line feed. Prefix is NULLable for convenience.
inline void tls_bf_log_bytearray(tls_bf_log_level level, const char *prefix, bytearray b) {
    if (level <= LOG_LEVEL) {
        FILE *fd;
        switch (level) {
            case ERROR:
            case WARNING:
                fd = stderr;
                break;
            default:
                fd = stdout;
        }
        fputs(log_prefixes[level], fd);
        if (prefix != NULL) {
            fprintf(fd, "%s: 0x", prefix);
        }
        for (size_t i = 0; i<b.len; i++) {
            fprintf(fd, "%02x", b.data[i]);
        }
        fputs("\n", fd);
    }
}
void tls_bf_log_ssl_data(tls_bf_log_level level, const char *prefix, uint8_t *data, size_t len) {
    if (level <= LOG_LEVEL) {
        FILE *fd;
        switch (level) {
            case ERROR:
            case WARNING:
                fd = stderr;
                break;
            default:
                fd = stdout;
        }
        fputs(log_prefixes[level], fd);
        fprintf(fd, "%s: 0x", prefix);
        for (size_t i = 0; i < len; i++) {
            fprintf(fd, "%02x", data[i]);
        }
        fputs("\n", fd);
    }
}
