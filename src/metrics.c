
#include "metrics.h"
#include <stdio.h>
#include <string.h>

static struct metrics g_metrics;

void metrics_init(void) { memset(&g_metrics, 0, sizeof(g_metrics)); }

struct metrics *metrics_get(void) { return &g_metrics; }

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
  fprintf(fp, "\n");
  fprintf(fp, "╔══════════════════════════════════════════╗\n");
  fprintf(fp, "║          SERVER STATISTICS               ║\n");
  fprintf(fp, "╠══════════════════════════════════════════╣\n");
  fprintf(fp, "║   CONNECTIONS                            ║\n");
  fprintf(fp, "║  ├─ Historic: %-20lu       ║\n",
          g_metrics.historic_connections);
  fprintf(fp, "║  └─ Current:  %-20lu       ║\n",
          g_metrics.current_connections);
  fprintf(fp, "╠══════════════════════════════════════════╣\n");
  fprintf(fp, "║   TRAFFIC                                ║\n");
  fprintf(fp, "║  ├─ Received: %-20lu       ║\n", g_metrics.bytes_received);
  fprintf(fp, "║  └─ Sent:     %-20lu       ║\n", g_metrics.bytes_sent);
  fprintf(fp, "╠══════════════════════════════════════════╣\n");
  fprintf(fp, "║  AUTHENTICATION                          ║\n");
  fprintf(fp, "║  ├─ Success:  %-20lu       ║\n", g_metrics.auth_success);
  fprintf(fp, "║  └─ Failures: %-20lu       ║\n", g_metrics.auth_failure);
  fprintf(fp, "╚══════════════════════════════════════════╝\n");
  fprintf(fp, "\n");
}
