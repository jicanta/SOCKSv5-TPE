// strdup requiere _POSIX_C_SOURCE >= 200809L
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#elif _POSIX_C_SOURCE < 200809L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

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
// AUTH
// =============================================================================

void auth_read_init(const unsigned state, struct selector_key *key) {
  (void)state;
  struct socks5 *s = ATTACHMENT(key);
  struct auth_st *a = &s->client.auth;
  a->rb = &s->read_buffer;
  a->wb = &s->write_buffer;
  a->state = AUTH_VERSION;
  a->status = 0xFF;
  buffer_reset(a->rb);
  buffer_reset(a->wb);
}

unsigned auth_read(struct selector_key *key) {
  struct socks5 *s = ATTACHMENT(key);
  struct auth_st *a = &s->client.auth;
  size_t nbytes;
  uint8_t *ptr = buffer_write_ptr(a->rb, &nbytes);
  ssize_t n = recv(key->fd, ptr, nbytes, 0);

  if (n <= 0)
    return ERROR;
  buffer_write_adv(a->rb, n);

  // TODO: emprolijar
  static uint8_t idx = 0;
  while (buffer_can_read(a->rb) && a->state != AUTH_DONE &&
         a->state != AUTH_ERROR) {
    uint8_t byte = buffer_read(a->rb);
    switch (a->state) {
    case AUTH_VERSION:
      a->state = (byte == 0x01) ? AUTH_ULEN : AUTH_ERROR;
      break;
    case AUTH_ULEN:
      a->ulen = byte;
      idx = 0;
      a->state = (byte == 0) ? AUTH_ERROR : AUTH_UNAME;
      break;
    case AUTH_UNAME:
      a->username[idx++] = byte;
      if (idx >= a->ulen) {
        a->username[idx] = 0;
        a->state = AUTH_PLEN;
      }
      break;
    case AUTH_PLEN:
      a->plen = byte;
      idx = 0;
      a->state = (byte == 0) ? AUTH_ERROR : AUTH_PASSWD;
      break;
    case AUTH_PASSWD:
      a->password[idx++] = byte;
      if (idx >= a->plen) {
        a->password[idx] = 0;
        a->state = AUTH_DONE;
      }
      break;
    }
  }

  if (a->state == AUTH_ERROR) {
    buffer_write(a->wb, 0x01);
    buffer_write(a->wb, 0xFF);
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_WRITE;
  }

  if (a->state == AUTH_DONE) {
    a->status = 0xFF;
    for (int i = 0; i < MAX_USERS && socks5args.users[i].name; i++) {
      if (strcmp(a->username, socks5args.users[i].name) == 0 &&
          strcmp(a->password, socks5args.users[i].pass) == 0) {
        a->status = 0x00;
        s->username = strdup(a->username);
        fprintf(stdout, "User '%s' authenticated\n", a->username);
        break;
      }
    }
    if (a->status != 0x00)
      fprintf(stderr, "Auth failed for '%s'\n", a->username);

    buffer_write(a->wb, 0x01);
    buffer_write(a->wb, a->status);
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_WRITE;
  }
  return AUTH_READ;
}

unsigned auth_write(struct selector_key *key) {
  struct socks5 *s = ATTACHMENT(key);
  struct auth_st *a = &s->client.auth;
  size_t nbytes;
  uint8_t *ptr = buffer_read_ptr(a->wb, &nbytes);
  ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

  if (n <= 0)
    return ERROR;
  buffer_read_adv(a->wb, n);

  if (!buffer_can_read(a->wb)) {
    if (a->status == 0x00) {
      selector_set_interest_key(key, OP_READ);
      return REQUEST_READ;
    }
    return ERROR;
  }
  return AUTH_WRITE;
}
