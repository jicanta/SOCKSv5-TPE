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

/** State for HELLO_READ and HELLO_WRITE */
struct hello_st {
    buffer *rb;
    buffer *wb;
    
    // Parser state
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods_remaining;
    uint8_t method;       // Selected authentication method
    
    enum {
        HELLO_VERSION,
        HELLO_NMETHODS,
        HELLO_METHODS,
        HELLO_DONE,
        HELLO_ERROR,
    } state;
};

/** State for AUTH_READ and AUTH_WRITE (RFC 1929) */
struct auth_st {
    buffer *rb;
    buffer *wb;
    
    // Parser state
    uint8_t version;
    uint8_t ulen;
    uint8_t plen;
    char username[256];
    char password[256];
    uint8_t status;  // 0x00 = success
    
    enum {
        AUTH_VERSION,
        AUTH_ULEN,
        AUTH_UNAME,
        AUTH_PLEN,
        AUTH_PASSWD,
        AUTH_DONE,
        AUTH_ERROR,
    } state;
};

/** State for REQUEST_READ, REQUEST_RESOLVING, REQUEST_CONNECTING, REQUEST_WRITE */
struct request_st {
    buffer *rb;
    buffer *wb;
    
    // Parser state
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    
    // Address storage
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
        char fqdn[256];
    } dest_addr;
    uint8_t fqdn_len;
    uint16_t dest_port;  // Network byte order
    
    // Reply status
    uint8_t reply;
    
    enum {
        REQUEST_VERSION,
        REQUEST_CMD,
        REQUEST_RSV,
        REQUEST_ATYP,
        REQUEST_DSTADDR,
        REQUEST_DSTPORT,
        REQUEST_DONE,
        REQUEST_ERROR,
    } state;
    
    // Bytes read for current field
    uint8_t addr_index;
};

/** State for COPY (bidirectional data relay) */
struct copy_st {
    int *fd;
    buffer *rb;
    buffer *wb;
    fd_interest duplex;
    struct copy_st *other;
};

// =============================================================================
// Main connection structure
// =============================================================================
struct socks5 {
    // File descriptors
    int client_fd;
    int origin_fd;
    
    // Buffers for bidirectional data flow
    buffer read_buffer;    // Client -> Origin
    buffer write_buffer;   // Origin -> Client
    uint8_t read_buffer_data[BUFFER_SIZE];
    uint8_t write_buffer_data[BUFFER_SIZE];
    
    // State machine
    struct state_machine stm;
    
    // Client address info
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    
    // Origin server address info (for FQDN resolution)
    struct addrinfo *origin_resolution;
    struct addrinfo *current_origin_addr;
    
    // State-specific data
    union {
        struct hello_st hello;
        struct auth_st auth;
        struct request_st request;
        struct copy_st copy;
    } client;
    
    union {
        struct copy_st copy;
    } origin;
    
    // Authentication info
    char *username;  // If authenticated
    
    // Connection status
    bool done;
    
    // Reference counting for pool management
    unsigned references;
    struct socks5 *next;  // For connection pool
};

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
