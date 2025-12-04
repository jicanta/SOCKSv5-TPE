/**
 * metrics.c - Server metrics collection
 *
 * Thread-safe metrics tracking using atomic operations.
 */

#include "metrics.h"
#include <string.h>
#include <stdio.h>

// Global metrics instance
static struct metrics g_metrics;

void metrics_init(void) {
    memset(&g_metrics, 0, sizeof(g_metrics));
}

struct metrics *metrics_get(void) {
    return &g_metrics;
}

void metrics_new_connection(void) {
    __sync_add_and_fetch(&g_metrics.historic_connections, 1);
    __sync_add_and_fetch(&g_metrics.current_connections, 1);
}

void metrics_close_connection(void) {
    __sync_sub_and_fetch(&g_metrics.current_connections, 1);
}

void metrics_add_bytes_sent(size_t bytes) {
    __sync_add_and_fetch(&g_metrics.bytes_sent, bytes);
}

void metrics_add_bytes_received(size_t bytes) {
    __sync_add_and_fetch(&g_metrics.bytes_received, bytes);
}

void metrics_auth_success(void) {
    __sync_add_and_fetch(&g_metrics.auth_success, 1);
}

void metrics_auth_failure(void) {
    __sync_add_and_fetch(&g_metrics.auth_failure, 1);
}

void metrics_print(FILE *fp) {
    fprintf(fp, "Server Statistics\n");
    fprintf(fp, "==============================\n");
    fprintf(fp, "---------- Connections ----------\n");
    fprintf(fp, "Historic connections: %lu\n", g_metrics.historic_connections);
    fprintf(fp, "Current connections:  %lu\n", g_metrics.current_connections);
    fprintf(fp, "---------- Traffic ----------\n");
    fprintf(fp, "Bytes received:       %lu\n", g_metrics.bytes_received);
    fprintf(fp, "Bytes sent:           %lu\n", g_metrics.bytes_sent);
    fprintf(fp, "---------- Authentication ----------\n");
    fprintf(fp, "Auth successes:       %lu\n", g_metrics.auth_success);
    fprintf(fp, "Auth failures:        %lu\n", g_metrics.auth_failure);
    fprintf(fp, "==============================\n");
}
