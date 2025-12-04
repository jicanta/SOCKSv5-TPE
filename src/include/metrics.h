
#ifndef METRICS_H
#define METRICS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct metrics {
  volatile uint64_t historic_connections;
  volatile uint64_t current_connections;
  volatile uint64_t bytes_sent;
  volatile uint64_t bytes_received;
  volatile uint64_t auth_success;
  volatile uint64_t auth_failure;
};

struct metrics *metrics_get(void);

void metrics_init(void);

void metrics_new_connection(void);

void metrics_close_connection(void);

void metrics_add_bytes_sent(size_t bytes);

void metrics_add_bytes_received(size_t bytes);

void metrics_auth_success(void);

void metrics_auth_failure(void);

void metrics_print(FILE *fp);

#endif // METRICS_H
