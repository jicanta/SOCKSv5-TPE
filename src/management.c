#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "args.h"
#include "include/management.h"
#include "metrics.h"

#include "logger.h"

// =============================================================================
// Helper Functions
// =============================================================================

static char *trim(char *str) {
  if (str == NULL)
    return NULL;
  while (isspace((unsigned char)*str))
    str++;

  if (*str == '\0')
    return str;

  char *end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;
  end[1] = '\0';

  return str;
}

static void to_upper(char *str) {
  for (; *str; str++) {
    *str = toupper((unsigned char)*str);
  }
}

static void format_number(uint64_t num, char *buf, size_t buflen) {
  if (num < 1000) {
    snprintf(buf, buflen, "%lu", (unsigned long)num);
    return;
  }

  char temp[32];
  snprintf(temp, sizeof(temp), "%lu", (unsigned long)num);

  int len = strlen(temp);
  int pos = 0;
  int tpos = 0;

  for (int i = 0; i < len; i++) {
    if (i > 0 && (len - i) % 3 == 0) {
      buf[pos++] = ',';
    }
    buf[pos++] = temp[tpos++];
  }
  buf[pos] = '\0';
}

static void format_bytes(uint64_t bytes, char *buf, size_t buflen) {
  const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  int unit = 0;
  double size = bytes;

  while (size >= 1024 && unit < 4) {
    size /= 1024;
    unit++;
  }

  if (unit == 0) {
    snprintf(buf, buflen, "%lu %s", (unsigned long)bytes, units[unit]);
  } else {
    snprintf(buf, buflen, "%.2f %s", size, units[unit]);
  }
}

// =============================================================================
// Command Handlers
// =============================================================================

static int cmd_stats(char *response, size_t resp_len) {
  struct metrics *m = metrics_get();

  char hist_conns[32], curr_conns[32];
  char bytes_recv[32], bytes_sent[32];
  char auth_ok[32], auth_fail[32];

  format_number(m->historic_connections, hist_conns, sizeof(hist_conns));
  format_number(m->current_connections, curr_conns, sizeof(curr_conns));
  format_bytes(m->bytes_received, bytes_recv, sizeof(bytes_recv));
  format_bytes(m->bytes_sent, bytes_sent, sizeof(bytes_sent));
  format_number(m->auth_success, auth_ok, sizeof(auth_ok));
  format_number(m->auth_failure, auth_fail, sizeof(auth_fail));

  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char time_str[64];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

  snprintf(response, resp_len,
           "%s Server Statistics\n"
           "==============================\n"
           "Time:                 %s\n"
           "---------- Connections ----------\n"
           "Historic connections: %s\n"
           "Current connections:  %s\n"
           "---------- Traffic ----------\n"
           "Bytes received:       %s\n"
           "Bytes sent:           %s\n"
           "---------- Authentication ----------\n"
           "Auth successes:       %s\n"
           "Auth failures:        %s\n"
           "==============================\n",
           MGMT_STATUS_OK, time_str, hist_conns, curr_conns, bytes_recv,
           bytes_sent, auth_ok, auth_fail);

  return 0;
}

static int cmd_users(char *response, size_t resp_len) {
  int offset = snprintf(response, resp_len,
                        "%s Registered Users (%d)\n"
                        "==============================\n",
                        MGMT_STATUS_OK, socks5args.user_count);

  if (socks5args.user_count == 0) {
    offset += snprintf(response + offset, resp_len - offset,
                       "(no users configured)\n");
  } else {
    for (int i = 0; i < socks5args.user_count && i < MAX_USERS; i++) {
      if (socks5args.users[i].name != NULL) {
        offset += snprintf(response + offset, resp_len - offset, "  %d. %s\n",
                           i + 1, socks5args.users[i].name);
      }
    }
  }

  snprintf(response + offset, resp_len - offset,
           "==============================\n");

  return 0;
}

static int cmd_add(const char *args, char *response, size_t resp_len) {
  if (args == NULL || *args == '\0') {
    snprintf(response, resp_len, "%s Usage: ADD <username>:<password>\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  char *colon = strchr(args, ':');
  if (colon == NULL) {
    snprintf(response, resp_len,
             "%s Invalid format. Use: ADD <username>:<password>\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  size_t ulen = colon - args;
  if (ulen == 0 || ulen > 255) {
    snprintf(response, resp_len, "%s Invalid username length\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  const char *password = colon + 1;
  if (*password == '\0') {
    snprintf(response, resp_len, "%s Password cannot be empty\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  for (int i = 0; i < socks5args.user_count; i++) {
    if (socks5args.users[i].name != NULL &&
        strncmp(socks5args.users[i].name, args, ulen) == 0 &&
        socks5args.users[i].name[ulen] == '\0') {
      snprintf(response, resp_len, "%s User '%.*s' already exists\n",
               MGMT_STATUS_ERROR, (int)ulen, args);
      return -1;
    }
  }

  if (socks5args.user_count >= MAX_USERS) {
    snprintf(response, resp_len, "%s Maximum users reached (%d)\n",
             MGMT_STATUS_ERROR, MAX_USERS);
    return -1;
  }

  int idx = socks5args.user_count;
  socks5args.users[idx].name = strndup(args, ulen);
  socks5args.users[idx].pass = strdup(password);

  if (socks5args.users[idx].name == NULL ||
      socks5args.users[idx].pass == NULL) {
    free(socks5args.users[idx].name);
    free(socks5args.users[idx].pass);
    snprintf(response, resp_len, "%s Memory allocation failed\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  socks5args.user_count++;
  socks5args.auth_required = true;

  LOG_INFO("User '%s' added via management interface\n",
           socks5args.users[idx].name);

  snprintf(response, resp_len, "%s User '%s' added successfully\n",
           MGMT_STATUS_OK, socks5args.users[idx].name);

  return 0;
}

static int cmd_del(const char *args, char *response, size_t resp_len) {
  if (args == NULL || *args == '\0') {
    snprintf(response, resp_len, "%s Usage: DEL <username>\n",
             MGMT_STATUS_ERROR);
    return -1;
  }

  int found = -1;
  for (int i = 0; i < socks5args.user_count; i++) {
    if (socks5args.users[i].name != NULL &&
        strcmp(socks5args.users[i].name, args) == 0) {
      found = i;
      break;
    }
  }

  if (found < 0) {
    snprintf(response, resp_len, "%s User '%s' not found\n", MGMT_STATUS_ERROR,
             args);
    return -1;
  }

  char *deleted_name = socks5args.users[found].name;
  free(socks5args.users[found].pass);

  for (int i = found; i < socks5args.user_count - 1; i++) {
    socks5args.users[i] = socks5args.users[i + 1];
  }

  socks5args.user_count--;

  socks5args.users[socks5args.user_count].name = NULL;
  socks5args.users[socks5args.user_count].pass = NULL;

  if (socks5args.user_count == 0) {
    socks5args.auth_required = false;
  }

  LOG_INFO("User '%s' deleted via management interface\n", deleted_name);

  snprintf(response, resp_len, "%s User '%s' deleted successfully\n",
           MGMT_STATUS_OK, deleted_name);

  free(deleted_name);

  return 0;
}

static int cmd_help(char *response, size_t resp_len) {
  snprintf(response, resp_len,
           "%s SOCKSv5 Proxy Management Protocol\n"
           "==========================================\n"
           "Available Commands:\n"
           "\n"
           "  PING               Check management liveness (returns PONG)\n"
           "\n"
           "  STATS              Show server statistics\n"
           "                     - Connection counts\n"
           "                     - Traffic bytes\n"
           "                     - Auth statistics\n"
           "\n"
           "  USERS              List registered users\n"
           "\n"
           "  ADD <user>:<pass>  Add a new user\n"
           "                     Example: ADD alice:secret123\n"
           "\n"
           "  DEL <user>         Delete a user\n"
           "                     Example: DEL alice\n"
           "\n"
           "  HELP               Show this help message\n"
           "\n"
           "==========================================\n"
           "Send commands via UDP to port %d\n"
           "Example: echo 'STATS' | nc -u localhost %d\n"
           "==========================================\n",
           MGMT_STATUS_OK, socks5args.mng_port, socks5args.mng_port);

  return 0;
}

static int cmd_ping(char *response, size_t resp_len) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char time_str[64];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

  snprintf(response, resp_len, "%s PONG %s\n", MGMT_STATUS_OK, time_str);
  return 0;
}

// =============================================================================
// Main Request Handler
// =============================================================================

void mgmt_handle_request(struct selector_key *key) {
  char buf[MGMT_MAX_CMD_LEN];
  char response[MGMT_MAX_RESP_LEN];
  struct sockaddr_storage client_addr;
  socklen_t addr_len = sizeof(client_addr);

  ssize_t n = recvfrom(key->fd, buf, sizeof(buf) - 1, 0,
                       (struct sockaddr *)&client_addr, &addr_len);

  if (n <= 0) {
    return;
  }

  buf[n] = '\0';

  char client_str[64] = "unknown";
  if (client_addr.ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
    inet_ntop(AF_INET, &sin->sin_addr, client_str, sizeof(client_str));
  }
  LOG_DEBUG("Management request from %s: %s\n", client_str, trim(buf));

  char *cmd = trim(buf);
  char *args = NULL;

  char *space = strchr(cmd, ' ');
  if (space != NULL) {
    *space = '\0';
    args = trim(space + 1);
  }

  to_upper(cmd);

  if (strcmp(cmd, MGMT_CMD_PING) == 0) {
    cmd_ping(response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_STATS) == 0) {
    cmd_stats(response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_USERS) == 0) {
    cmd_users(response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_ADD) == 0) {
    cmd_add(args, response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_DEL) == 0) {
    cmd_del(args, response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_HELP) == 0) {
    cmd_help(response, sizeof(response));
  } else if (strcmp(cmd, MGMT_CMD_QUIT) == 0 || strcmp(cmd, "EXIT") == 0) {
    snprintf(response, sizeof(response), "%s Goodbye!\n", MGMT_STATUS_OK);
  } else if (*cmd == '\0') {
    return;
  } else {
    snprintf(response, sizeof(response),
             "%s Unknown command: %s\n"
             "Type 'HELP' for available commands.\n",
             MGMT_STATUS_ERROR, cmd);
  }

  sendto(key->fd, response, strlen(response), 0,
         (struct sockaddr *)&client_addr, addr_len);
}

void mgmt_init(void) { LOG_INFO("Management interface initialized\n"); }

void mgmt_cleanup(void) {}
