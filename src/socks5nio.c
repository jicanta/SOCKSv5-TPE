#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5_internal.h"
#include "socks5nio.h"
#include "metrics.h"
#include "logger.h"

// =============================================================================
// Connection Pool
// =============================================================================

static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 *pool = NULL;

static struct socks5 *socks5_new(int client_fd) {
  struct socks5 *s = pool;
  if (s != NULL) {
    pool = pool->next;
    pool_size--;
  } else {
    s = calloc(1, sizeof(struct socks5));
    if (s == NULL)
      return NULL;
  }

  memset(s, 0, sizeof(*s));
  s->client_fd = client_fd;
  s->origin_fd = -1;
  s->references = 1;
  buffer_init(&s->read_buffer, BUFFER_SIZE, s->read_buffer_data);
  buffer_init(&s->write_buffer, BUFFER_SIZE, s->write_buffer_data);
  return s;
}

static void socks5_destroy_(struct socks5 *s) {
  if (s->origin_resolution)
    freeaddrinfo(s->origin_resolution);
  if (s->username)
    free(s->username);
  free(s);
}

static void socks5_destroy(struct socks5 *s) {
  if (!s)
    return;
  if (s->references == 1) {
    if (s->origin_resolution) {
      freeaddrinfo(s->origin_resolution);
      s->origin_resolution = NULL;
    }
    if (s->username) {
      free(s->username);
      s->username = NULL;
    }

    if (pool_size < max_pool) {
      s->next = pool;
      pool = s;
      pool_size++;
    } else {
      socks5_destroy_(s);
    }
  } else {
    s->references--;
  }
}

void socksv5_pool_destroy(void) {
  struct socks5 *s = pool;
  while (s != NULL) {
    struct socks5 *next = s->next;
    free(s);
    s = next;
  }
  pool = NULL;
  pool_size = 0;
}

// =============================================================================
// State Machine Definition
// =============================================================================

static void done_arrival(const unsigned state, struct selector_key *key) {
  (void)state;
  (void)key;
}
static void error_arrival(const unsigned state, struct selector_key *key) {
  (void)state;
  (void)key;
}

static const struct state_definition client_states[] = {
    {.state = HELLO_READ,
     .on_arrival = hello_read_init,
     .on_read_ready = hello_read},
    {.state = HELLO_WRITE, .on_write_ready = hello_write},
    {.state = AUTH_READ,
     .on_arrival = auth_read_init,
     .on_read_ready = auth_read},
    {.state = AUTH_WRITE, .on_write_ready = auth_write},
    {.state = REQUEST_READ,
     .on_arrival = request_read_init,
     .on_read_ready = request_read},
    {.state = REQUEST_RESOLVING, .on_block_ready = request_resolving},
    {.state = REQUEST_CONNECTING, .on_write_ready = request_connecting},
    {.state = REQUEST_WRITE, .on_write_ready = request_write},
    {.state = COPY,
     .on_arrival = copy_init,
     .on_read_ready = copy_read,
     .on_write_ready = copy_write},
    {.state = DONE, .on_arrival = done_arrival},
    {.state = ERROR, .on_arrival = error_arrival},
};

// =============================================================================
// Connection Handlers
// =============================================================================

static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void socksv5_block(struct selector_key *key);

const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

const struct fd_handler *socks5_get_handler(void) { return &socks5_handler; }

static void socksv5_done(struct selector_key *key) {
  struct socks5 *s = ATTACHMENT(key);
  if (s == NULL || s->done)
    return;
  s->done = true;

  if (s->client_fd >= 0) {
    selector_unregister_fd(key->s, s->client_fd);
    close(s->client_fd);
    s->client_fd = -1;
  }
  if (s->origin_fd >= 0) {
    selector_unregister_fd(key->s, s->origin_fd);
    close(s->origin_fd);
    s->origin_fd = -1;
  }
  metrics_close_connection();
}

static void socksv5_read(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks5_state st = stm_handler_read(stm, key);
  if (st == DONE || st == ERROR)
    socksv5_done(key);
}

static void socksv5_write(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks5_state st = stm_handler_write(stm, key);
  if (st == DONE || st == ERROR)
    socksv5_done(key);
}

static void socksv5_block(struct selector_key *key) {
  struct state_machine *stm = &ATTACHMENT(key)->stm;
  const enum socks5_state st = stm_handler_block(stm, key);
  if (st == DONE || st == ERROR)
    socksv5_done(key);
}

static void socksv5_close(struct selector_key *key) {
  socks5_destroy(ATTACHMENT(key));
}

void socksv5_passive_accept(struct selector_key *key) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  int client_fd =
      accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
  if (client_fd < 0)
    return;

  struct metrics *m = metrics_get();
  if (m->current_connections >= 500) {
    LOG_WARNING("Connection limit reached, rejecting client\n");
    close(client_fd);
    return;
  }

  if (selector_fd_set_nio(client_fd) < 0) {
    LOG_ERROR("Failed to set client socket non-blocking\n");
    close(client_fd);
    return;
  }

  struct socks5 *s = socks5_new(client_fd);
  if (s == NULL) {
    LOG_ERROR("Failed to allocate connection state\n");
    close(client_fd);
    return;
  }

  memcpy(&s->client_addr, &client_addr, client_addr_len);
  s->client_addr_len = client_addr_len;
  s->stm.initial = HELLO_READ;
  s->stm.max_state = ERROR;
  s->stm.states = client_states;
  stm_init(&s->stm);

  if (selector_register(key->s, client_fd, &socks5_handler, OP_READ, s) !=
      SELECTOR_SUCCESS) {
    LOG_ERROR("Failed to register client socket\n");
    socks5_destroy(s);
    close(client_fd);
    return;
  }
  metrics_new_connection();
  LOG_DEBUG("New client connection accepted (fd=%d)\n", client_fd);
}
