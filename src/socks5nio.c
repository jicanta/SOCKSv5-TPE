#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socks5nio.h"
#include "selector.h"
#include "stm.h"
#include "args.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

extern struct socks5args socks5args;

// =============================================================================
// Connection Pool
// =============================================================================

static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 *pool = NULL;
static unsigned active_connections = 0;

static struct socks5 *socks5_new(int client_fd) {
    struct socks5 *s = NULL;
    
    if (pool != NULL) {
        s = pool;
        pool = pool->next;
        pool_size--;
    } else {
        s = calloc(1, sizeof(struct socks5));
        if (s == NULL) {
            return NULL;
        }
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
    if (s == NULL) return;
    
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
    }
    
    if (s->username != NULL) {
        free(s->username);
        s->username = NULL;
    }
    
    free(s);
}

static void socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    
    if (s->references == 1) {
        if (s->origin_resolution != NULL) {
            freeaddrinfo(s->origin_resolution);
            s->origin_resolution = NULL;
        }
        
        if (s->username != NULL) {
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
// Forward Declarations
// =============================================================================

static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);

static void auth_read_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);

static void request_read_init(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_start_resolve(struct selector_key *key);
static unsigned request_start_connect(struct selector_key *key);
static unsigned request_resolving(struct selector_key *key);
static unsigned request_connecting(struct selector_key *key);
static unsigned request_write(struct selector_key *key);

static void copy_init(const unsigned state, struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);

static void done_arrival(const unsigned state, struct selector_key *key);
static void error_arrival(const unsigned state, struct selector_key *key);

// =============================================================================
// State Machine Definition
// =============================================================================

static const struct state_definition client_states[] = {
    {
        .state = HELLO_READ,
        .on_arrival = hello_read_init,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    {
        .state = AUTH_READ,
        .on_arrival = auth_read_init,
        .on_read_ready = auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLVING,
        .on_block_ready = request_resolving,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_write_ready = request_connecting,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    {
        .state = DONE,
        .on_arrival = done_arrival,
    },
    {
        .state = ERROR,
        .on_arrival = error_arrival,
    },
};

// =============================================================================
// Connection Handlers
// =============================================================================

static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void socksv5_block(struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

const struct fd_handler *socks5_get_handler(void) {
    return &socks5_handler;
}

void socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        fprintf(stderr, "accept() failed: %s\n", strerror(errno));
        return;
    }
    
    if (active_connections >= 500) {
        fprintf(stderr, "Connection limit reached, rejecting client\n");
        close(client_fd);
        return;
    }
    
    if (selector_fd_set_nio(client_fd) < 0) {
        fprintf(stderr, "Failed to set client socket non-blocking\n");
        close(client_fd);
        return;
    }
    
    struct socks5 *s = socks5_new(client_fd);
    if (s == NULL) {
        fprintf(stderr, "Failed to allocate connection state\n");
        close(client_fd);
        return;
    }
    
    memcpy(&s->client_addr, &client_addr, client_addr_len);
    s->client_addr_len = client_addr_len;
    
    s->stm.initial = HELLO_READ;
    s->stm.max_state = ERROR;
    s->stm.states = client_states;
    stm_init(&s->stm);
    
    if (selector_register(key->s, client_fd, &socks5_handler, OP_READ, s) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Failed to register client socket\n");
        socks5_destroy(s);
        close(client_fd);
        return;
    }
    
    active_connections++;
    fprintf(stdout, "New client connection accepted (fd=%d)\n", client_fd);
}

static void socksv5_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (s == NULL || s->done) return;
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
    
    active_connections--;
}

static void socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_read(stm, key);
    
    if (st == DONE || st == ERROR) {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_write(stm, key);
    
    if (st == DONE || st == ERROR) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_block(stm, key);
    
    if (st == DONE || st == ERROR) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

// =============================================================================
// HELLO State Handlers
// =============================================================================

static void hello_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct hello_st *h = &s->client.hello;
    
    h->rb = &s->read_buffer;
    h->wb = &s->write_buffer;
    h->state = HELLO_VERSION;
    h->method = SOCKS_AUTH_NO_ACCEPTABLE;
}

static unsigned hello_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct hello_st *h = &s->client.hello;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(h->rb, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_write_adv(h->rb, n);
    
    while (buffer_can_read(h->rb) && h->state != HELLO_DONE && h->state != HELLO_ERROR) {
        uint8_t byte = buffer_read(h->rb);
        
        switch (h->state) {
            case HELLO_VERSION:
                if (byte != SOCKS_VERSION) {
                    h->state = HELLO_ERROR;
                } else {
                    h->version = byte;
                    h->state = HELLO_NMETHODS;
                }
                break;
                
            case HELLO_NMETHODS:
                h->nmethods = byte;
                h->methods_remaining = byte;
                if (byte == 0) {
                    h->state = HELLO_DONE;
                } else {
                    h->state = HELLO_METHODS;
                }
                break;
                
            case HELLO_METHODS:
                // Check if we have users configured
                bool auth_required = false;
                if (socks5args.users[0].name != NULL) {
                    auth_required = true;
                }

                if (byte == SOCKS_AUTH_NONE && !auth_required) {
                    h->method = SOCKS_AUTH_NONE;
                } else if (byte == SOCKS_AUTH_USERPASS) {
                    if (auth_required || h->method == SOCKS_AUTH_NO_ACCEPTABLE) {
                        h->method = SOCKS_AUTH_USERPASS;
                    }
                }
                
                h->methods_remaining--;
                if (h->methods_remaining == 0) {
                    h->state = HELLO_DONE;
                }
                break;
                
            default:
                break;
        }
    }
    
    if (h->state == HELLO_ERROR) {
        return ERROR;
    }
    
    if (h->state == HELLO_DONE) {
        bool auth_required = false;
        if (socks5args.users[0].name != NULL) {
            auth_required = true;
        }

        if (auth_required && h->method == SOCKS_AUTH_NONE) {
             // If we found USERPASS previously, it would be set. If not, it remains NO_ACCEPTABLE or NONE (if we allowed it, but we didn't)
             // Actually, if auth_required is true, we only accept USERPASS.
             // If the client didn't offer USERPASS, h->method will be NO_ACCEPTABLE (initialized)
             // unless we set it to NONE which we don't if auth_required.
             // Wait, my logic above:
             // if (byte == SOCKS_AUTH_NONE && !auth_required) -> sets NONE
             // if (byte == SOCKS_AUTH_USERPASS) -> sets USERPASS
             // So if auth_required is true, NONE is ignored.
             // If USERPASS is offered, it is set.
             // If neither, it remains NO_ACCEPTABLE.
        }
        
        buffer_write(h->wb, SOCKS_VERSION);
        buffer_write(h->wb, h->method);
        
        selector_set_interest_key(key, OP_WRITE);
        return HELLO_WRITE;
    }
    
    return HELLO_READ;
}

static unsigned hello_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct hello_st *h = &s->client.hello;
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(h->wb, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_read_adv(h->wb, n);
    
    if (!buffer_can_read(h->wb)) {
        if (h->method == SOCKS_AUTH_NO_ACCEPTABLE) {
            return ERROR;
        } else if (h->method == SOCKS_AUTH_USERPASS) {
            selector_set_interest_key(key, OP_READ);
            return AUTH_READ;
        } else {
            selector_set_interest_key(key, OP_READ);
            return REQUEST_READ;
        }
    }
    
    return HELLO_WRITE;
}

// =============================================================================
// AUTH State Handlers
// =============================================================================

static void auth_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct auth_st *a = &s->client.auth;
    
    a->rb = &s->read_buffer;
    a->wb = &s->write_buffer;
    a->state = AUTH_VERSION;
    a->ulen = 0;
    a->plen = 0;
    a->status = 0xFF;
    
    buffer_reset(a->rb);
    buffer_reset(a->wb);
}

static unsigned auth_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct auth_st *a = &s->client.auth;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(a->rb, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_write_adv(a->rb, n);
    
    static uint8_t idx = 0;
    
    while (buffer_can_read(a->rb) && a->state != AUTH_DONE && a->state != AUTH_ERROR) {
        uint8_t byte = buffer_read(a->rb);
        
        switch (a->state) {
            case AUTH_VERSION:
                if (byte != 0x01) {
                    a->state = AUTH_ERROR;
                } else {
                    a->version = byte;
                    a->state = AUTH_ULEN;
                }
                break;
                
            case AUTH_ULEN:
                a->ulen = byte;
                idx = 0;
                if (byte == 0) {
                    a->state = AUTH_ERROR;
                } else {
                    a->state = AUTH_UNAME;
                }
                break;
                
            case AUTH_UNAME:
                a->username[idx++] = byte;
                if (idx >= a->ulen) {
                    a->username[idx] = '\0';
                    a->state = AUTH_PLEN;
                }
                break;
                
            case AUTH_PLEN:
                a->plen = byte;
                idx = 0;
                if (byte == 0) {
                    a->state = AUTH_ERROR;
                } else {
                    a->state = AUTH_PASSWD;
                }
                break;
                
            case AUTH_PASSWD:
                a->password[idx++] = byte;
                if (idx >= a->plen) {
                    a->password[idx] = '\0';
                    a->state = AUTH_DONE;
                }
                break;
                
            default:
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
        
        for (int i = 0; i < MAX_USERS; i++) {
            if (socks5args.users[i].name == NULL) break;
            if (strcmp(a->username, socks5args.users[i].name) == 0 &&
                strcmp(a->password, socks5args.users[i].pass) == 0) {
                a->status = 0x00;
                s->username = strdup(a->username);
                fprintf(stdout, "User '%s' authenticated\n", a->username);
                break;
            }
        }
        
        if (a->status != 0x00) {
            fprintf(stderr, "Authentication failed for user '%s'\n", a->username);
        }
        
        buffer_write(a->wb, 0x01);
        buffer_write(a->wb, a->status);
        
        selector_set_interest_key(key, OP_WRITE);
        return AUTH_WRITE;
    }
    
    return AUTH_READ;
}

static unsigned auth_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct auth_st *a = &s->client.auth;
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(a->wb, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_read_adv(a->wb, n);
    
    if (!buffer_can_read(a->wb)) {
        if (a->status == 0x00) {
            selector_set_interest_key(key, OP_READ);
            return REQUEST_READ;
        } else {
            return ERROR;
        }
    }
    
    return AUTH_WRITE;
}

// =============================================================================
// REQUEST State Handlers
// =============================================================================

static void request_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    r->rb = &s->read_buffer;
    r->wb = &s->write_buffer;
    r->state = REQUEST_VERSION;
    r->addr_index = 0;
    r->reply = SOCKS_REPLY_GENERAL_FAILURE;
    
    buffer_reset(r->rb);
    buffer_reset(r->wb);
}

static unsigned request_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(r->rb, &nbytes);
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_write_adv(r->rb, n);
    
    while (buffer_can_read(r->rb) && r->state != REQUEST_DONE && r->state != REQUEST_ERROR) {
        uint8_t byte = buffer_read(r->rb);
        
        switch (r->state) {
            case REQUEST_VERSION:
                if (byte != SOCKS_VERSION) {
                    r->state = REQUEST_ERROR;
                    r->reply = SOCKS_REPLY_GENERAL_FAILURE;
                } else {
                    r->version = byte;
                    r->state = REQUEST_CMD;
                }
                break;
                
            case REQUEST_CMD:
                r->cmd = byte;
                if (byte != SOCKS_CMD_CONNECT) {
                    r->state = REQUEST_ERROR;
                    r->reply = SOCKS_REPLY_CMD_NOT_SUPPORTED;
                } else {
                    r->state = REQUEST_RSV;
                }
                break;
                
            case REQUEST_RSV:
                r->rsv = byte;
                r->state = REQUEST_ATYP;
                break;
                
            case REQUEST_ATYP:
                r->atyp = byte;
                r->addr_index = 0;
                
                if (byte == SOCKS_ATYP_IPV4) {
                    r->state = REQUEST_DSTADDR;
                } else if (byte == SOCKS_ATYP_DOMAIN) {
                    r->state = REQUEST_DSTADDR;
                } else if (byte == SOCKS_ATYP_IPV6) {
                    r->state = REQUEST_DSTADDR;
                } else {
                    r->state = REQUEST_ERROR;
                    r->reply = SOCKS_REPLY_ATYP_NOT_SUPPORTED;
                }
                break;
                
            case REQUEST_DSTADDR:
                if (r->atyp == SOCKS_ATYP_IPV4) {
                    ((uint8_t *)&r->dest_addr.ipv4)[r->addr_index++] = byte;
                    if (r->addr_index >= 4) {
                        r->state = REQUEST_DSTPORT;
                        r->addr_index = 0;
                    }
                } else if (r->atyp == SOCKS_ATYP_IPV6) {
                    r->dest_addr.ipv6.s6_addr[r->addr_index++] = byte;
                    if (r->addr_index >= 16) {
                        r->state = REQUEST_DSTPORT;
                        r->addr_index = 0;
                    }
                } else if (r->atyp == SOCKS_ATYP_DOMAIN) {
                    if (r->addr_index == 0) {
                        r->fqdn_len = byte;
                        r->addr_index = 1;
                    } else {
                        r->dest_addr.fqdn[r->addr_index - 1] = byte;
                        r->addr_index++;
                        if (r->addr_index > r->fqdn_len) {
                            r->dest_addr.fqdn[r->fqdn_len] = '\0';
                            r->state = REQUEST_DSTPORT;
                            r->addr_index = 0;
                        }
                    }
                }
                break;
                
            case REQUEST_DSTPORT:
                if (r->addr_index == 0) {
                    r->dest_port = byte << 8;
                    r->addr_index = 1;
                } else {
                    r->dest_port |= byte;
                    r->state = REQUEST_DONE;
                }
                break;
                
            default:
                break;
        }
    }
    
    if (r->state == REQUEST_ERROR) {
        goto send_reply;
    }
    
    if (r->state == REQUEST_DONE) {
        if (r->atyp == SOCKS_ATYP_DOMAIN) {
            return request_start_resolve(key);
        } else {
            return request_start_connect(key);
        }
    }
    
    return REQUEST_READ;

send_reply:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION);
    buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00);
    buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

struct resolve_data {
    fd_selector selector;
    int client_fd;
    char fqdn[256];
    uint16_t port;
};

static unsigned request_start_resolve(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    struct resolve_data *data = malloc(sizeof(*data));
    if (data == NULL) {
        r->reply = SOCKS_REPLY_GENERAL_FAILURE;
        goto error;
    }
    
    data->selector = key->s;
    data->client_fd = s->client_fd;
    strncpy(data->fqdn, r->dest_addr.fqdn, sizeof(data->fqdn) - 1);
    data->fqdn[sizeof(data->fqdn) - 1] = '\0';
    data->port = r->dest_port;
    
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", r->dest_port);
    
    int err = getaddrinfo(r->dest_addr.fqdn, port_str, &hints, &s->origin_resolution);
    free(data);
    
    if (err != 0 || s->origin_resolution == NULL) {
        fprintf(stderr, "DNS resolution failed for %s: %s\n", r->dest_addr.fqdn, gai_strerror(err));
        r->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        goto error;
    }
    
    s->current_origin_addr = s->origin_resolution;
    
    return request_start_connect(key);
    
error:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION);
    buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00);
    buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned request_start_connect(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    
    if (s->origin_resolution != NULL) {
        struct addrinfo *ai = s->current_origin_addr;
        if (ai == NULL) {
            r->reply = SOCKS_REPLY_HOST_UNREACHABLE;
            goto error;
        }
        memcpy(&addr, ai->ai_addr, ai->ai_addrlen);
        addr_len = ai->ai_addrlen;
    } else if (r->atyp == SOCKS_ATYP_IPV4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = r->dest_addr.ipv4;
        sin->sin_port = htons(r->dest_port);
        addr_len = sizeof(struct sockaddr_in);
    } else if (r->atyp == SOCKS_ATYP_IPV6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = r->dest_addr.ipv6;
        sin6->sin6_port = htons(r->dest_port);
        addr_len = sizeof(struct sockaddr_in6);
    } else {
        r->reply = SOCKS_REPLY_ATYP_NOT_SUPPORTED;
        goto error;
    }
    
    int origin_fd = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (origin_fd < 0) {
        fprintf(stderr, "Failed to create origin socket: %s\n", strerror(errno));
        r->reply = SOCKS_REPLY_GENERAL_FAILURE;
        goto error;
    }
    
    if (selector_fd_set_nio(origin_fd) < 0) {
        close(origin_fd);
        r->reply = SOCKS_REPLY_GENERAL_FAILURE;
        goto error;
    }
    
    int ret = connect(origin_fd, (struct sockaddr *)&addr, addr_len);
    
    if (ret < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "connect() failed: %s\n", strerror(errno));
        close(origin_fd);
        
        if (s->origin_resolution != NULL && s->current_origin_addr != NULL) {
            s->current_origin_addr = s->current_origin_addr->ai_next;
            if (s->current_origin_addr != NULL) {
                return request_start_connect(key);
            }
        }
        
        r->reply = SOCKS_REPLY_CONNECTION_REFUSED;
        goto error;
    }
    
    s->origin_fd = origin_fd;
    
    s->references++;
    if (selector_register(key->s, origin_fd, &socks5_handler, OP_WRITE, s) != SELECTOR_SUCCESS) {
        s->references--;
        close(origin_fd);
        s->origin_fd = -1;
        r->reply = SOCKS_REPLY_GENERAL_FAILURE;
        goto error;
    }
    
    selector_set_interest_key(key, OP_NOOP);
    return REQUEST_CONNECTING;
    
error:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION);
    buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00);
    buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned request_resolving(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (s->origin_resolution != NULL) {
        s->current_origin_addr = s->origin_resolution;
        return request_start_connect(key);
    }
    
    s->client.request.reply = SOCKS_REPLY_HOST_UNREACHABLE;
    
    buffer_reset(&s->write_buffer);
    buffer_write(&s->write_buffer, SOCKS_VERSION);
    buffer_write(&s->write_buffer, s->client.request.reply);
    buffer_write(&s->write_buffer, 0x00);
    buffer_write(&s->write_buffer, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(&s->write_buffer, 0x00);
    
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned request_connecting(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    if (key->fd == s->origin_fd) {
        int error = 0;
        socklen_t len = sizeof(error);
        
        if (getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            fprintf(stderr, "Connect failed: %s\n", strerror(error ? error : errno));
            
            selector_unregister_fd(key->s, s->origin_fd);
            close(s->origin_fd);
            s->origin_fd = -1;
            s->references--;
            
            if (s->origin_resolution != NULL && s->current_origin_addr != NULL) {
                s->current_origin_addr = s->current_origin_addr->ai_next;
                if (s->current_origin_addr != NULL) {
                    selector_set_interest(key->s, s->client_fd, OP_READ);
                    return request_start_connect(key);
                }
            }
            
            r->reply = SOCKS_REPLY_CONNECTION_REFUSED;
            goto send_error;
        }
        
        fprintf(stdout, "Connected to origin (fd=%d)\n", s->origin_fd);
        
        r->reply = SOCKS_REPLY_SUCCEEDED;
        
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        getsockname(s->origin_fd, (struct sockaddr *)&local_addr, &local_len);
        
        buffer_reset(r->wb);
        buffer_write(r->wb, SOCKS_VERSION);
        buffer_write(r->wb, SOCKS_REPLY_SUCCEEDED);
        buffer_write(r->wb, 0x00);
        
        if (local_addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&local_addr;
            buffer_write(r->wb, SOCKS_ATYP_IPV4);
            uint8_t *ip = (uint8_t *)&sin->sin_addr;
            for (int i = 0; i < 4; i++) buffer_write(r->wb, ip[i]);
            buffer_write(r->wb, (ntohs(sin->sin_port) >> 8) & 0xFF);
            buffer_write(r->wb, ntohs(sin->sin_port) & 0xFF);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local_addr;
            buffer_write(r->wb, SOCKS_ATYP_IPV6);
            for (int i = 0; i < 16; i++) buffer_write(r->wb, sin6->sin6_addr.s6_addr[i]);
            buffer_write(r->wb, (ntohs(sin6->sin6_port) >> 8) & 0xFF);
            buffer_write(r->wb, ntohs(sin6->sin6_port) & 0xFF);
        }
        
        char dest_str[256];
        if (r->atyp == SOCKS_ATYP_DOMAIN) {
            snprintf(dest_str, sizeof(dest_str), "%s", r->dest_addr.fqdn);
        } else if (r->atyp == SOCKS_ATYP_IPV4) {
            inet_ntop(AF_INET, &r->dest_addr.ipv4, dest_str, sizeof(dest_str));
        } else {
            inet_ntop(AF_INET6, &r->dest_addr.ipv6, dest_str, sizeof(dest_str));
        }
        fprintf(stdout, "Access: %s -> %s:%d\n", s->username ? s->username : "anonymous", dest_str, r->dest_port);
        
        selector_set_interest(key->s, s->client_fd, OP_WRITE);
        selector_set_interest(key->s, s->origin_fd, OP_NOOP);
        
        return REQUEST_WRITE;
    }
    
    return REQUEST_CONNECTING;
    
send_error:
    buffer_reset(r->wb);
    buffer_write(r->wb, SOCKS_VERSION);
    buffer_write(r->wb, r->reply);
    buffer_write(r->wb, 0x00);
    buffer_write(r->wb, SOCKS_ATYP_IPV4);
    for (int i = 0; i < 6; i++) buffer_write(r->wb, 0x00);
    
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned request_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *r = &s->client.request;
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(r->wb, &nbytes);
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        return ERROR;
    }
    buffer_read_adv(r->wb, n);
    
    if (!buffer_can_read(r->wb)) {
        if (r->reply == SOCKS_REPLY_SUCCEEDED) {
            return COPY;
        } else {
            return ERROR;
        }
    }
    
    return REQUEST_WRITE;
}

// =============================================================================
// COPY State Handlers
// =============================================================================

static void copy_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    
    buffer_reset(&s->read_buffer);
    buffer_reset(&s->write_buffer);
    
    struct copy_st *c = &s->client.copy;
    struct copy_st *o = &s->origin.copy;
    
    c->fd = &s->client_fd;
    c->rb = &s->read_buffer;
    c->wb = &s->write_buffer;
    c->duplex = OP_READ | OP_WRITE;
    c->other = o;
    
    o->fd = &s->origin_fd;
    o->rb = &s->write_buffer;
    o->wb = &s->read_buffer;
    o->duplex = OP_READ | OP_WRITE;
    o->other = c;
    
    selector_set_interest(key->s, s->client_fd, OP_READ);
    selector_set_interest(key->s, s->origin_fd, OP_READ);
}

static struct copy_st *get_copy_ptr(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (key->fd == s->client_fd) {
        return &s->client.copy;
    } else {
        return &s->origin.copy;
    }
}

static fd_interest compute_interests(fd_selector sel, struct copy_st *c) {
    fd_interest ret = OP_NOOP;
    
    if ((c->duplex & OP_READ) && buffer_can_write(c->rb)) {
        ret |= OP_READ;
    }
    if ((c->duplex & OP_WRITE) && buffer_can_read(c->wb)) {
        ret |= OP_WRITE;
    }
    
    if (ret == OP_NOOP) {
        if (c->other->duplex == OP_NOOP) {
            return OP_NOOP;
        }
    }
    
    selector_set_interest(sel, *c->fd, ret);
    return ret;
}

static unsigned copy_read(struct selector_key *key) {
    struct copy_st *c = get_copy_ptr(key);
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(c->rb, &nbytes);
    
    ssize_t n = recv(key->fd, ptr, nbytes, 0);
    
    if (n <= 0) {
        shutdown(*c->fd, SHUT_RD);
        c->duplex = INTEREST_OFF(c->duplex, OP_READ);
        
        if (*c->other->fd >= 0) {
            shutdown(*c->other->fd, SHUT_WR);
            c->other->duplex = INTEREST_OFF(c->other->duplex, OP_WRITE);
        }
        
        if (c->duplex == OP_NOOP && c->other->duplex == OP_NOOP) {
            return DONE;
        }
    } else {
        buffer_write_adv(c->rb, n);
    }
    
    compute_interests(key->s, c);
    compute_interests(key->s, c->other);
    
    return COPY;
}

static unsigned copy_write(struct selector_key *key) {
    struct copy_st *c = get_copy_ptr(key);
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(c->wb, &nbytes);
    
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n <= 0) {
        shutdown(*c->fd, SHUT_WR);
        c->duplex = INTEREST_OFF(c->duplex, OP_WRITE);
        
        if (*c->other->fd >= 0) {
            shutdown(*c->other->fd, SHUT_RD);
            c->other->duplex = INTEREST_OFF(c->other->duplex, OP_READ);
        }
        
        if (c->duplex == OP_NOOP && c->other->duplex == OP_NOOP) {
            return DONE;
        }
    } else {
        buffer_read_adv(c->wb, n);
    }
    
    compute_interests(key->s, c);
    compute_interests(key->s, c->other);
    
    return COPY;
}

static void done_arrival(const unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
    // fprintf(stdout, "Connection completed successfully\n");
}

static void error_arrival(const unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
    // fprintf(stderr, "Connection terminated with error\n");
}
