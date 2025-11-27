#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "socks5_internal.h"
#include "args.h"
#include "selector.h"

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
    
    if (n <= 0) return ERROR;
    buffer_write_adv(h->rb, n);
    
    while (buffer_can_read(h->rb) && h->state != HELLO_DONE && h->state != HELLO_ERROR) {
        uint8_t byte = buffer_read(h->rb);
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
                if (byte == SOCKS_AUTH_NONE && !auth_required) h->method = SOCKS_AUTH_NONE;
                else if (byte == SOCKS_AUTH_USERPASS) h->method = SOCKS_AUTH_USERPASS;
                
                if (--h->methods_remaining == 0) h->state = HELLO_DONE;
                break;
            }
        }
    }
    
    if (h->state == HELLO_ERROR) return ERROR;
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
    
    if (n <= 0) return ERROR;
    buffer_read_adv(h->wb, n);
    
    if (!buffer_can_read(h->wb)) {
        selector_set_interest_key(key, OP_READ);
        if (h->method == SOCKS_AUTH_NO_ACCEPTABLE) return ERROR;
        return (h->method == SOCKS_AUTH_USERPASS) ? AUTH_READ : REQUEST_READ;
    }
    return HELLO_WRITE;
}

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
    
    if (n <= 0) return ERROR;
    buffer_write_adv(a->rb, n);
    
    static uint8_t idx = 0;
    while (buffer_can_read(a->rb) && a->state != AUTH_DONE && a->state != AUTH_ERROR) {
        uint8_t byte = buffer_read(a->rb);
        switch (a->state) {
            case AUTH_VERSION: a->state = (byte == 0x01) ? AUTH_ULEN : AUTH_ERROR; break;
            case AUTH_ULEN: a->ulen = byte; idx = 0; a->state = (byte == 0) ? AUTH_ERROR : AUTH_UNAME; break;
            case AUTH_UNAME: 
                a->username[idx++] = byte; 
                if (idx >= a->ulen) { a->username[idx] = 0; a->state = AUTH_PLEN; } 
                break;
            case AUTH_PLEN: a->plen = byte; idx = 0; a->state = (byte == 0) ? AUTH_ERROR : AUTH_PASSWD; break;
            case AUTH_PASSWD:
                a->password[idx++] = byte;
                if (idx >= a->plen) { a->password[idx] = 0; a->state = AUTH_DONE; }
                break;
        }
    }
    
    if (a->state == AUTH_ERROR) {
        buffer_write(a->wb, 0x01); buffer_write(a->wb, 0xFF);
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
        if (a->status != 0x00) fprintf(stderr, "Auth failed for '%s'\n", a->username);
        
        buffer_write(a->wb, 0x01); buffer_write(a->wb, a->status);
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
    
    if (n <= 0) return ERROR;
    buffer_read_adv(a->wb, n);
    
    if (!buffer_can_read(a->wb)) {
        if (a->status == 0x00) { selector_set_interest_key(key, OP_READ); return REQUEST_READ; }
        return ERROR;
    }
    return AUTH_WRITE;
}

// =============================================================================
// REQUEST
// =============================================================================

static unsigned request_start_resolve(struct selector_key *key);
static unsigned request_start_connect(struct selector_key *key);

void request_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    r->rb = &s->read_buffer;
    r->wb = &s->write_buffer;
    r->state = REQUEST_VERSION;
    r->reply = SOCKS_REPLY_GENERAL_FAILURE;
    buffer_reset(r->rb);
    buffer_reset(r->wb);
}

unsigned request_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(r->rb, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) return ERROR;
    buffer_write_adv(r->rb, n);
    
    while (buffer_can_read(r->rb) && r->state != REQUEST_DONE && r->state != REQUEST_ERROR) {
        uint8_t byte = buffer_read(r->rb);
        switch (r->state) {
            case REQUEST_VERSION: r->state = (byte == SOCKS_VERSION) ? REQUEST_CMD : REQUEST_ERROR; break;
            case REQUEST_CMD: 
                r->cmd = byte; 
                if (byte != SOCKS_CMD_CONNECT) { r->reply = SOCKS_REPLY_CMD_NOT_SUPPORTED; r->state = REQUEST_ERROR; }
                else r->state = REQUEST_RSV;
                break;
            case REQUEST_RSV: r->state = REQUEST_ATYP; break;
            case REQUEST_ATYP:
                r->atyp = byte; r->addr_index = 0;
                if (byte == SOCKS_ATYP_IPV4 || byte == SOCKS_ATYP_IPV6 || byte == SOCKS_ATYP_DOMAIN) r->state = REQUEST_DSTADDR;
                else { r->reply = SOCKS_REPLY_ATYP_NOT_SUPPORTED; r->state = REQUEST_ERROR; }
                break;
            case REQUEST_DSTADDR:
                if (r->atyp == SOCKS_ATYP_IPV4) {
                    ((uint8_t *)&r->dest_addr.ipv4)[r->addr_index++] = byte;
                    if (r->addr_index >= 4) { r->state = REQUEST_DSTPORT; r->addr_index = 0; }
                } else if (r->atyp == SOCKS_ATYP_IPV6) {
                    r->dest_addr.ipv6.s6_addr[r->addr_index++] = byte;
                    if (r->addr_index >= 16) { r->state = REQUEST_DSTPORT; r->addr_index = 0; }
                } else if (r->atyp == SOCKS_ATYP_DOMAIN) {
                    if (r->addr_index == 0) { r->fqdn_len = byte; r->addr_index = 1; }
                    else {
                        r->dest_addr.fqdn[r->addr_index - 1] = byte;
                        if (++r->addr_index > r->fqdn_len) {
                            r->dest_addr.fqdn[r->fqdn_len] = 0;
                            r->state = REQUEST_DSTPORT; r->addr_index = 0;
                        }
                    }
                }
                break;
            case REQUEST_DSTPORT:
                if (r->addr_index == 0) { r->dest_port = byte << 8; r->addr_index = 1; }
                else { r->dest_port |= byte; r->state = REQUEST_DONE; }
                break;
        }
    }
    
    if (r->state == REQUEST_ERROR) goto send_reply;
    if (r->state == REQUEST_DONE) return (r->atyp == SOCKS_ATYP_DOMAIN) ? request_start_resolve(key) : request_start_connect(key);
    return REQUEST_READ;

send_reply:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION); buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00); buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned request_start_resolve(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP };
    char port_str[6]; snprintf(port_str, sizeof(port_str), "%u", r->dest_port);
    
    int err = getaddrinfo(r->dest_addr.fqdn, port_str, &hints, &s->origin_resolution);
    if (err != 0 || s->origin_resolution == NULL) {
        r->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        buffer_reset(r->wb);
        buffer_write(r->wb, SOCKS_VERSION); buffer_write(r->wb, r->reply);
        buffer_write(r->wb, 0x00); buffer_write(r->wb, SOCKS_ATYP_IPV4);
        for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_WRITE;
    }
    s->current_origin_addr = s->origin_resolution;
    return request_start_connect(key);
}

static unsigned request_start_connect(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    
    if (s->origin_resolution) {
        if (!s->current_origin_addr) { r->reply = SOCKS_REPLY_HOST_UNREACHABLE; goto error; }
        memcpy(&addr, s->current_origin_addr->ai_addr, s->current_origin_addr->ai_addrlen);
        addr_len = s->current_origin_addr->ai_addrlen;
    } else if (r->atyp == SOCKS_ATYP_IPV4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        sin->sin_family = AF_INET; sin->sin_addr = r->dest_addr.ipv4; sin->sin_port = htons(r->dest_port);
        addr_len = sizeof(*sin);
    } else if (r->atyp == SOCKS_ATYP_IPV6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        sin6->sin6_family = AF_INET6; sin6->sin6_addr = r->dest_addr.ipv6; sin6->sin6_port = htons(r->dest_port);
        addr_len = sizeof(*sin6);
    }
    
    int origin_fd = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (origin_fd < 0 || selector_fd_set_nio(origin_fd) < 0) {
        if (origin_fd >= 0) close(origin_fd);
        r->reply = SOCKS_REPLY_GENERAL_FAILURE; goto error;
    }
    
    if (connect(origin_fd, (struct sockaddr *)&addr, addr_len) < 0 && errno != EINPROGRESS) {
        close(origin_fd);
        if (s->origin_resolution && (s->current_origin_addr = s->current_origin_addr->ai_next)) return request_start_connect(key);
        r->reply = SOCKS_REPLY_CONNECTION_REFUSED; goto error;
    }
    
    s->origin_fd = origin_fd;
    s->references++;
    if (selector_register(key->s, origin_fd, &socks5_handler, OP_WRITE, s) != SELECTOR_SUCCESS) {
        s->references--; close(origin_fd); s->origin_fd = -1;
        r->reply = SOCKS_REPLY_GENERAL_FAILURE; goto error;
    }
    selector_set_interest_key(key, OP_NOOP);
    return REQUEST_CONNECTING;

error:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION); buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00); buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

unsigned request_resolving(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    if (s->origin_resolution) {
        s->current_origin_addr = s->origin_resolution;
        return request_start_connect(key);
    }
    return ERROR;
}

unsigned request_connecting(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    if (key->fd != s->origin_fd) return REQUEST_CONNECTING;
    
    int error = 0; socklen_t len = sizeof(error);
    if (getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        selector_unregister_fd(key->s, s->origin_fd); close(s->origin_fd); s->origin_fd = -1; s->references--;
        if (s->origin_resolution && (s->current_origin_addr = s->current_origin_addr->ai_next)) {
            selector_set_interest(key->s, s->client_fd, OP_READ);
            return request_start_connect(key);
        }
        r->reply = SOCKS_REPLY_CONNECTION_REFUSED;
        buffer_reset(r->wb);
        buffer_write(r->wb, SOCKS_VERSION); buffer_write(r->wb, r->reply);
        buffer_write(r->wb, 0x00); buffer_write(r->wb, SOCKS_ATYP_IPV4);
        for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
        selector_set_interest(key->s, s->client_fd, OP_WRITE);
        return REQUEST_WRITE;
    }
    
    r->reply = SOCKS_REPLY_SUCCEEDED;
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION); buffer_write(r->wb, SOCKS_REPLY_SUCCEEDED);
    buffer_write(r->wb, 0x00); buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00); // Simplified bind addr
    
    char dest_str[256] = "unknown";
    if (r->atyp == SOCKS_ATYP_DOMAIN) snprintf(dest_str, sizeof(dest_str), "%s", r->dest_addr.fqdn);
    else if (r->atyp == SOCKS_ATYP_IPV4) inet_ntop(AF_INET, &r->dest_addr.ipv4, dest_str, sizeof(dest_str));
    
    fprintf(stdout, "Access: %s -> %s:%d\n", s->username ? s->username : "anon", dest_str, r->dest_port);
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
    selector_set_interest(key->s, s->origin_fd, OP_NOOP);
    return REQUEST_WRITE;
}

unsigned request_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(r->wb, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) return ERROR;
    buffer_read_adv(r->wb, n);
    
    if (!buffer_can_read(r->wb)) return (r->reply == SOCKS_REPLY_SUCCEEDED) ? COPY : ERROR;
    return REQUEST_WRITE;
}

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
