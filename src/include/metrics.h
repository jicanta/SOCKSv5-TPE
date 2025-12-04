/**
 * metrics.h - Server metrics collection
 *
 * Tracks server metrics as required by the specification:
 * - Historic connections
 * - Concurrent connections
 * - Bytes transferred
 */
#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * Metrics structure for server monitoring.
 * All counters are volatile for thread-safety.
 */
struct metrics {
    // Connection metrics
    volatile uint64_t historic_connections;   // Total connections since start
    volatile uint64_t current_connections;    // Currently active connections
    
    // Traffic metrics
    volatile uint64_t bytes_sent;             // Bytes sent to clients
    volatile uint64_t bytes_received;         // Bytes received from clients
    
    // Authentication metrics
    volatile uint64_t auth_success;           // Successful authentications
    volatile uint64_t auth_failure;           // Failed authentications
};

/**
 * Get the global metrics structure.
 */
struct metrics *metrics_get(void);

/**
 * Initialize metrics (call once at startup).
 */
void metrics_init(void);

/**
 * Record a new connection.
 */
void metrics_new_connection(void);

/**
 * Record a closed connection.
 */
void metrics_close_connection(void);

/**
 * Record bytes transferred.
 */
void metrics_add_bytes_sent(size_t bytes);
void metrics_add_bytes_received(size_t bytes);

/**
 * Record authentication result.
 */
void metrics_auth_success(void);
void metrics_auth_failure(void);

/**
 * Print metrics to the specified file stream.
 */
void metrics_print(FILE *fp);

#endif // METRICS_H
