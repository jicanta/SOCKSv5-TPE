/**
 * socks5nio.h - SOCKSv5 non-blocking I/O handler declarations
 *
 * Defines the interface for the SOCKSv5 proxy state machine.
 * Implements RFC 1928 (SOCKSv5) and RFC 1929 (Username/Password Auth).
 */
#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Include dependencies
#include "buffer.h"
#include "selector.h"
#include "stm.h"

// =============================================================================
// Buffer sizes
// =============================================================================
#define BUFFER_SIZE 4096

// =============================================================================
// SOCKSv5 Protocol Constants (RFC 1928)
// =============================================================================
#define SOCKS_VERSION 0x05

// Authentication methods
#define SOCKS_AUTH_NONE           0x00
#define SOCKS_AUTH_GSSAPI         0x01
#define SOCKS_AUTH_USERPASS       0x02
#define SOCKS_AUTH_NO_ACCEPTABLE  0xFF

// Commands
#define SOCKS_CMD_CONNECT         0x01
#define SOCKS_CMD_BIND            0x02
#define SOCKS_CMD_UDP_ASSOCIATE   0x03

// Address types
#define SOCKS_ATYP_IPV4           0x01
#define SOCKS_ATYP_DOMAIN         0x03
#define SOCKS_ATYP_IPV6           0x04

// Reply codes
#define SOCKS_REPLY_SUCCEEDED           0x00
#define SOCKS_REPLY_GENERAL_FAILURE     0x01
#define SOCKS_REPLY_NOT_ALLOWED         0x02
#define SOCKS_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS_REPLY_HOST_UNREACHABLE    0x04
#define SOCKS_REPLY_CONNECTION_REFUSED  0x05
#define SOCKS_REPLY_TTL_EXPIRED         0x06
#define SOCKS_REPLY_CMD_NOT_SUPPORTED   0x07
#define SOCKS_REPLY_ATYP_NOT_SUPPORTED  0x08

// =============================================================================
// State Machine States
// =============================================================================
enum socks5_state {
    // Negotiation phase (RFC 1928 section 3)
    HELLO_READ = 0,
    HELLO_WRITE,
    
    // Authentication phase (RFC 1929)
    AUTH_READ,
    AUTH_WRITE,
    
    // Request phase (RFC 1928 section 4)
    REQUEST_READ,
    REQUEST_RESOLVING,  // DNS resolution for FQDN
    REQUEST_CONNECTING, // Connecting to origin server
    REQUEST_WRITE,
    
    // Data relay phase
    COPY,
    
    // Terminal states
    DONE,
    ERROR,
};

// =============================================================================
// State-specific structures
// =============================================================================

// Internal structures are defined in socks5_internal.h

// =============================================================================
// Public API
// =============================================================================

/**
 * Passive accept handler for the master socket.
 * Called when a new client connection is ready to be accepted.
 */
void socksv5_passive_accept(struct selector_key *key);

/**
 * Clean up the connection pool on server shutdown.
 */
void socksv5_pool_destroy(void);

/** Get the SOCKSv5 fd_handler */
const struct fd_handler *socks5_get_handler(void);

#endif // SOCKS5NIO_H
