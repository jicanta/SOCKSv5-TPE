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
#include "hello_parser.h"

extern struct socks5args socks5args;

// =============================================================================
// HELLO
//implementa la negociación inicial de métodos de autenticación y realiza la transición hacia las siguientes etapas del flujo SOCKSv5.
// =============================================================================


static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    bool auth_required = (socks5args.users[0].name != NULL);
    uint8_t *selected = (uint8_t *)p->data;
    if (method == SOCKS_AUTH_NONE && !auth_required) {
        *selected = SOCKS_AUTH_NONE;
    } else if (method == SOCKS_AUTH_USERPASS) {
        *selected = SOCKS_AUTH_USERPASS;
    }
}

void hello_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct hello_st *h = &s->client.hello;
    h->rb = &s->read_buffer;
    h->wb = &s->write_buffer;
    h->method = SOCKS_AUTH_NO_ACCEPTABLE;  
    hello_parser_init(&h->parser);  
    h->parser.data = &h->method;  
    h->parser.on_authentication_method = on_hello_method;  
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

    bool error = false;
    enum hello_state st = hello_consume(h->rb, &h->parser, &error);  

    if (error || st == HELLO_ERROR)
        return ERROR;

    if (hello_is_done(st, NULL)) {
        uint8_t reply_method = (h->method == SOCKS_AUTH_NO_ACCEPTABLE) ? SOCKS_AUTH_NO_ACCEPTABLE : h->method;
        if (hello__build_reply(h->wb, reply_method) == -1) {
            return ERROR;  
        }
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
