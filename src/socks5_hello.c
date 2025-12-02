#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "args.h"
#include "selector.h"
#include "socks5_internal.h"

extern struct socks5args socks5args;

// =============================================================================
// HELLO
// =============================================================================

void hello_read_init(const unsigned state, struct selector_key *key) {
  (void)state;
  struct socks5 *s = ATTACHMENT(key);
  struct hello_st *h = &s->client.hello;
  h->rb = &s->read_buffer;
  h->wb = &s->write_buffer;
  h->state = HELLO_VERSION;
  h->method = SOCKS_AUTH_NO_ACCEPTABLE;
}

unsigned hello_read(struct selector_key *key) {
  struct socks5 *s = ATTACHMENT(key);
  struct hello_st *h = &s->client.hello;
  size_t nbytes;
  uint8_t *ptr = buffer_write_ptr(h->rb, &nbytes);
  ssize_t n = recv(key->fd, ptr, nbytes, 0);

  if (n <= 0)
    return ERROR;
  buffer_write_adv(h->rb, n);

  // TODO: emprolijar lola
  while (buffer_can_read(h->rb) && h->state != HELLO_DONE &&
         h->state != HELLO_ERROR) {
    const uint8_t byte = buffer_read(h->rb);
    switch (h->state) {
    case HELLO_VERSION:
      h->state = (byte == SOCKS_VERSION) ? HELLO_NMETHODS : HELLO_ERROR;
      h->version = byte;
      break;
    case HELLO_NMETHODS:
      h->nmethods = byte;
      h->methods_remaining = byte;
      h->state = (byte == 0) ? HELLO_DONE : HELLO_METHODS;
      break;
    case HELLO_METHODS: {
      bool auth_required = (socks5args.users[0].name != NULL);
      if (byte == SOCKS_AUTH_NONE && !auth_required)
        h->method = SOCKS_AUTH_NONE;
      else if (byte == SOCKS_AUTH_USERPASS)
        h->method = SOCKS_AUTH_USERPASS;

      if (--h->methods_remaining == 0)
        h->state = HELLO_DONE;
      break;
    }
    }
  }

  if (h->state == HELLO_ERROR)
    return ERROR;
  if (h->state == HELLO_DONE) {
    buffer_write(h->wb, SOCKS_VERSION);
    buffer_write(h->wb, h->method);
    selector_set_interest_key(key, OP_WRITE);
    return HELLO_WRITE;
  }
  return HELLO_READ;
}

unsigned hello_write(struct selector_key *key) {
  struct socks5 *s = ATTACHMENT(key);
  struct hello_st *h = &s->client.hello;
  size_t nbytes;
  uint8_t *ptr = buffer_read_ptr(h->wb, &nbytes);
  ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

  if (n <= 0)
    return ERROR;
  buffer_read_adv(h->wb, n);

  if (!buffer_can_read(h->wb)) {
    selector_set_interest_key(key, OP_READ);
    if (h->method == SOCKS_AUTH_NO_ACCEPTABLE)
      return ERROR;
    return (h->method == SOCKS_AUTH_USERPASS) ? AUTH_READ : REQUEST_READ;
  }
  return HELLO_WRITE;
}
