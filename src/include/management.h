/**
 * management.h - Management Protocol for SOCKSv5 Proxy
 *
 * Provides a UDP-based management interface for:
 * - Viewing server metrics and statistics
 * - Managing users at runtime
 * - Server configuration
 *
 * Protocol Format:
 *   Request:  <COMMAND> [ARGS...]
 *   Response: <STATUS> <MESSAGE>
 *
 * Commands:
 *   STATS              - Get server statistics
 *   USERS              - List registered users
 *   ADD <user>:<pass>  - Add a new user
 *   DEL <user>         - Remove a user
 *   HELP               - Show available commands
 */
#ifndef MANAGEMENT_H
#define MANAGEMENT_H

#include "selector.h"
#include <stdbool.h>
#include <stdint.h>

// Protocol constants
#define MGMT_MAX_CMD_LEN 256
#define MGMT_MAX_RESP_LEN 4096

// Response status codes
#define MGMT_STATUS_OK "OK"
#define MGMT_STATUS_ERROR "ERR"

// Commands
#define MGMT_CMD_STATS "STATS"
#define MGMT_CMD_USERS "USERS"
#define MGMT_CMD_ADD "ADD"
#define MGMT_CMD_DEL "DEL"
#define MGMT_CMD_HELP "HELP"
#define MGMT_CMD_QUIT "QUIT"
#define MGMT_CMD_PING "PING"

void mgmt_handle_request(struct selector_key *key);

void mgmt_init(void);

void mgmt_cleanup(void);

#endif // MANAGEMENT_H
