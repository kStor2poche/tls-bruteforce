#ifndef LOG_H
#define LOG_H

#include "utils.h"
#include <stddef.h>
#include <stdint.h>
typedef enum {
    NO_LOG,
    ERROR,
    WARNING,
    INFO,
    DEBUG,
    BF_DEBUG,
} tls_bf_log_level;

static tls_bf_log_level LOG_LEVEL;

static const char* log_prefixes[] = {
    NULL,
    "ERROR: ",
    "WARNING: ",
    "INFO: ",
    "DEBUG: ",
    "BF_DEBUG: ",
};

void tls_bf_log_init();
void tls_bf_log(tls_bf_log_level level, const char *log);
void tls_bf_logf(tls_bf_log_level level, const char *fmt, ...);
void tls_bf_log_bytearray(tls_bf_log_level level, const char *prefix, bytearray barray);
void tls_bf_log_ssl_data(tls_bf_log_level level, const char *prefix, uint8_t *data, size_t len);
#define tls_bf_debug_bytearray(b) if (DEBUG <= LOG_LEVEL) print_bytearray_sub(#b, b);

#endif
