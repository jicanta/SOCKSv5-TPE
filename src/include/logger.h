
#ifndef LOGGER_H
#define LOGGER_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

typedef enum {
  LOG_DEBUG = 0,
  LOG_INFO,
  LOG_WARNING,
  LOG_ERROR,
} log_level_t;

void logger_init(const char *log_file, log_level_t min_level);

void logger_close(void);

void logger_log(log_level_t level, const char *fmt, ...);

void logger_access(const char *username,
                   const struct sockaddr_storage *client_addr,
                   const char *dest_host, uint16_t dest_port, bool success);

#define LOG_DEBUG(...) logger_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) logger_log(LOG_INFO, __VA_ARGS__)
#define LOG_WARNING(...) logger_log(LOG_WARNING, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_ERROR, __VA_ARGS__)

#endif // LOGGER_H
