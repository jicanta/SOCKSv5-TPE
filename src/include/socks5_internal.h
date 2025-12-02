#ifndef SOCKS5_INTERNAL_H
#define SOCKS5_INTERNAL_H

#include "buffer.h"
#include "socks5nio.h"
#include "stm.h"
#include <netdb.h>

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

// Shared handler for selector registration
extern const struct fd_handler socks5_handler;

// Internal States for HELLO
enum hello_state {
  HELLO_VERSION,
  HELLO_NMETHODS,
  HELLO_METHODS,
  HELLO_DONE,
  HELLO_ERROR,
};

struct hello_st {
  buffer *rb, *wb;
  uint8_t state; // enum hello_state
  uint8_t version;
  uint8_t nmethods;
  uint8_t methods_remaining;
  uint8_t method;
};

// Internal States for AUTH
enum auth_state {
  AUTH_VERSION,
  AUTH_ULEN,
  AUTH_UNAME,
  AUTH_PLEN,
  AUTH_PASSWD,
  AUTH_DONE,
  AUTH_ERROR,
};

struct auth_st {
  buffer *rb, *wb;
  uint8_t state; // enum auth_state
  uint8_t version;
  uint8_t ulen;
  char username[SOCKS_AUTH_MAX_LEN];
  uint8_t plen;
  char password[SOCKS_AUTH_MAX_LEN];
  uint8_t status;
};

// Internal States for REQUEST
enum request_state {
  REQUEST_VERSION,
  REQUEST_CMD,
  REQUEST_RSV,
  REQUEST_ATYP,
  REQUEST_DSTADDR,
  REQUEST_DSTPORT,
  REQUEST_DONE,
  REQUEST_ERROR,
};

struct request_st {
  buffer *rb, *wb;
  uint8_t state; // enum request_state
  uint8_t version;
  uint8_t cmd;
  uint8_t rsv;
  uint8_t atyp;
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    char fqdn[SOCKS_DOMAIN_MAX_LEN];
  } dest_addr;
  uint8_t fqdn_len;
  uint16_t dest_port;
  uint8_t addr_index;
  uint8_t reply;
};

struct copy_st {
  int *fd;
  buffer *rb, *wb;
  fd_interest duplex;
  struct copy_st *other;
};

struct socks5 {
  struct state_machine stm;
  int client_fd;
  int origin_fd;

  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;

  struct addrinfo *origin_resolution;
  struct addrinfo *current_origin_addr;

  char *username;
  unsigned references;
  bool done;

  struct socks5 *next; // For pool

  uint8_t read_buffer_data[BUFFER_SIZE];
  uint8_t write_buffer_data[BUFFER_SIZE];
  buffer read_buffer;
  buffer write_buffer;

  union {
    struct hello_st hello;
    struct auth_st auth;
    struct request_st request;
    struct copy_st copy;
  } client;

  union {
    struct copy_st copy;
  } origin;
};

// State Handlers
void hello_read_init(const unsigned state, struct selector_key *key);
unsigned hello_read(struct selector_key *key);
unsigned hello_write(struct selector_key *key);

void auth_read_init(const unsigned state, struct selector_key *key);
unsigned auth_read(struct selector_key *key);
unsigned auth_write(struct selector_key *key);

void request_read_init(const unsigned state, struct selector_key *key);
unsigned request_read(struct selector_key *key);
unsigned request_resolving(struct selector_key *key);
unsigned request_connecting(struct selector_key *key);
unsigned request_write(struct selector_key *key);

void copy_init(const unsigned state, struct selector_key *key);
unsigned copy_read(struct selector_key *key);
unsigned copy_write(struct selector_key *key);

#endif
