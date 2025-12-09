/**
 * logger.h - Logging utilities for the SOCKSv5 proxy
 *
 * Provides access logging as required by the specification.
 */
#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>

/**
 * Log levels
 */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
} log_level_t;

/**
 * Initialize the logger.
 * @param log_file Path to log file (NULL for stderr)
 * @param min_level Minimum log level to output
 */
void logger_init(const char *log_file, log_level_t min_level);

/**
 * Close the logger and flush any pending writes.
 */
void logger_close(void);

/**
 * Log a message.
 */
void logger_log(log_level_t level, const char *fmt, ...);

/**
 * Log an access entry (for access.log).
 * Format: timestamp user client_addr:port -> dest_addr:port status
 */
void logger_access(const char *username,
                   const struct sockaddr_storage *client_addr,
                   const char *dest_host,
                   uint16_t dest_port,
                   bool success);

// Convenience macros
#define LOG_DEBUG(...)   logger_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)    logger_log(LOG_INFO, __VA_ARGS__)
#define LOG_WARNING(...) logger_log(LOG_WARNING, __VA_ARGS__)
#define LOG_ERROR(...)   logger_log(LOG_ERROR, __VA_ARGS__)

#endif // LOGGER_H
