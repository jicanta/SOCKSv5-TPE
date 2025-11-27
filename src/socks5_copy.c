#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "socks5_internal.h"
#include "selector.h"

// =============================================================================
// COPY
// =============================================================================

void copy_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    buffer_reset(&s->read_buffer); buffer_reset(&s->write_buffer);
    
    s->client.copy = (struct copy_st){ .fd = &s->client_fd, .rb = &s->read_buffer, .wb = &s->write_buffer, .duplex = OP_READ|OP_WRITE, .other = &s->origin.copy };
    s->origin.copy = (struct copy_st){ .fd = &s->origin_fd, .rb = &s->write_buffer, .wb = &s->read_buffer, .duplex = OP_READ|OP_WRITE, .other = &s->client.copy };
    
    selector_set_interest(key->s, s->client_fd, OP_READ);
    selector_set_interest(key->s, s->origin_fd, OP_READ);
}

static struct copy_st *get_copy_ptr(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    return (key->fd == s->client_fd) ? &s->client.copy : &s->origin.copy;
}

static void compute_interests(fd_selector sel, struct copy_st *c) {
    fd_interest ret = OP_NOOP;
    if ((c->duplex & OP_READ) && buffer_can_write(c->rb)) ret |= OP_READ;
    if ((c->duplex & OP_WRITE) && buffer_can_read(c->wb)) ret |= OP_WRITE;
    selector_set_interest(sel, *c->fd, ret);
}

unsigned copy_read(struct selector_key *key) {
    struct copy_st *c = get_copy_ptr(key);
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(c->rb, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        shutdown(*c->fd, SHUT_RD); c->duplex &= ~OP_READ;
        if (*c->other->fd >= 0) { shutdown(*c->other->fd, SHUT_WR); c->other->duplex &= ~OP_WRITE; }
        if (c->duplex == OP_NOOP && c->other->duplex == OP_NOOP) return DONE;
    } else {
        buffer_write_adv(c->rb, n);
    }
    compute_interests(key->s, c); compute_interests(key->s, c->other);
    return COPY;
}

unsigned copy_write(struct selector_key *key) {
    struct copy_st *c = get_copy_ptr(key);
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(c->wb, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        shutdown(*c->fd, SHUT_WR); c->duplex &= ~OP_WRITE;
        if (*c->other->fd >= 0) { shutdown(*c->other->fd, SHUT_RD); c->other->duplex &= ~OP_READ; }
        if (c->duplex == OP_NOOP && c->other->duplex == OP_NOOP) return DONE;
    } else {
        buffer_read_adv(c->wb, n);
    }
    compute_interests(key->s, c); compute_interests(key->s, c->other);
    return COPY;
}
