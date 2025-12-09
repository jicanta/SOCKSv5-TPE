/**
 * logger.c - Logging utilities for the SOCKSv5 proxy
 */

#define _POSIX_C_SOURCE 200809L

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

// Logger state
static FILE *g_log_file = NULL;
static FILE *g_access_file = NULL;
static log_level_t g_min_level = LOG_INFO;

static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
};

void logger_init(const char *log_file, log_level_t min_level) {
    g_min_level = min_level;
    
    if (log_file != NULL) {
        g_log_file = fopen(log_file, "a");
        if (g_log_file == NULL) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            g_log_file = stderr;
        }
    } else {
        g_log_file = stderr;
    }
    
    // Open access log
    g_access_file = fopen("access.log", "a");
    if (g_access_file == NULL) {
        fprintf(stderr, "Warning: Failed to open access.log\n");
    }
}

void logger_close(void) {
    if (g_log_file != NULL && g_log_file != stderr) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    if (g_access_file != NULL) {
        fclose(g_access_file);
        g_access_file = NULL;
    }
}

void logger_log(log_level_t level, const char *fmt, ...) {
    if (level < g_min_level) {
        return;
    }
    
    FILE *f = g_log_file ? g_log_file : stderr;
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Print log entry
    fprintf(f, "[%s] [%s] ", time_buf, level_strings[level]);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    
    fflush(f);
}

static const char *sockaddr_to_string(const struct sockaddr_storage *addr, 
                                       char *buf, size_t buflen) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%d", ip, ntohs(sin->sin_port));
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        snprintf(buf, buflen, "unknown");
    }
    return buf;
}

void logger_access(const char *username,
                   const struct sockaddr_storage *client_addr,
                   const char *dest_host,
                   uint16_t dest_port,
                   bool success) {
    if (g_access_file == NULL) {
        return;
    }
    
    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Format client address
    char client_str[64];
    sockaddr_to_string(client_addr, client_str, sizeof(client_str));
    
    // Log access entry
    fprintf(g_access_file, "%s %s %s -> %s:%u %s\n",
            time_buf,
            username ? username : "-",
            client_str,
            dest_host ? dest_host : "?",
            dest_port,
            success ? "OK" : "FAIL");
    
    fflush(g_access_file);
}
