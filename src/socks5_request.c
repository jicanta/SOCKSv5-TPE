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
#include "logger.h"

extern struct socks5args socks5args;

// =============================================================================
// REQUEST
// =============================================================================

static unsigned request_start_resolve(struct selector_key* key);
static unsigned request_start_connect(struct selector_key* key);

static unsigned request_marshall_reply(struct selector_key* key,
                                       uint8_t reply_code) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;

  r->reply = reply_code;
  buffer_reset(r->wb);
  buffer_write(r->wb, SOCKS_VERSION);
  buffer_write(r->wb, reply_code);
  buffer_write(r->wb, SOCKS_RSV);
  buffer_write(r->wb, SOCKS_ATYP_IPV4);
  for (int i = 0; i < SOCKS_IPV4_ADDR_SIZE + SOCKS_PORT_SIZE; i++)
    buffer_write(r->wb, 0x00);

  selector_set_interest(key->s, s->client_fd, OP_WRITE);
  return REQUEST_WRITE;
}

void request_read_init(const unsigned state, struct selector_key* key) {
  (void)state;
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;
  r->rb = &s->read_buffer;
  r->wb = &s->write_buffer;
  r->state = REQUEST_VERSION;
  r->reply = SOCKS_REPLY_GENERAL_FAILURE;
  buffer_reset(r->rb);
  buffer_reset(r->wb);
}

static void request_process_version(struct request_st* r, uint8_t byte) {
  r->state = (byte == SOCKS_VERSION) ? REQUEST_CMD : REQUEST_ERROR;
}

static void request_process_cmd(struct request_st* r, uint8_t byte) {
  r->cmd = byte;
  if (byte != SOCKS_CMD_CONNECT) {
    r->reply = SOCKS_REPLY_CMD_NOT_SUPPORTED;
    r->state = REQUEST_ERROR;
  } else {
    r->state = REQUEST_RSV;
  }
}

static void request_process_rsv(struct request_st* r, uint8_t byte) {
  (void)byte;
  r->state = REQUEST_ATYP;
}

static void request_process_atyp(struct request_st* r, uint8_t byte) {
  r->atyp = byte;
  r->addr_index = 0;
  if (byte == SOCKS_ATYP_IPV4 || byte == SOCKS_ATYP_IPV6 ||
      byte == SOCKS_ATYP_DOMAIN) {
    r->state = REQUEST_DSTADDR;
  } else {
    r->reply = SOCKS_REPLY_ATYP_NOT_SUPPORTED;
    r->state = REQUEST_ERROR;
  }
}

static void request_process_dstaddr(struct request_st* r, uint8_t byte) {
  if (r->atyp == SOCKS_ATYP_IPV4) {
    ((uint8_t*)&r->dest_addr.ipv4)[r->addr_index++] = byte;
    if (r->addr_index >= SOCKS_IPV4_ADDR_SIZE) {
      r->state = REQUEST_DSTPORT;
      r->addr_index = 0;
    }
  } else if (r->atyp == SOCKS_ATYP_IPV6) {
    r->dest_addr.ipv6.s6_addr[r->addr_index++] = byte;
    if (r->addr_index >= SOCKS_IPV6_ADDR_SIZE) {
      r->state = REQUEST_DSTPORT;
      r->addr_index = 0;
    }
  } else if (r->atyp == SOCKS_ATYP_DOMAIN) {
    if (r->addr_index == 0) {
      r->fqdn_len = byte;
      r->addr_index = 1;
    } else {
      r->dest_addr.fqdn[r->addr_index - 1] = byte;
      if (++r->addr_index > r->fqdn_len) {
        r->dest_addr.fqdn[r->fqdn_len] = 0;
        r->state = REQUEST_DSTPORT;
        r->addr_index = 0;
      }
    }
  }
}

static void request_process_dstport(struct request_st* r, uint8_t byte) {
  if (r->addr_index == 0) {
    r->dest_port = byte << 8;
    r->addr_index = 1;
  } else {
    r->dest_port |= byte;
    r->state = REQUEST_DONE;
  }
}

// EXAMPLE REQUEST PACKET
//+----+-----+-------+------+----------+----------+
//|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//+----+-----+-------+------+----------+----------+
//| 1  |  1  | X'00' |  1   | Variable |    2     |
//+----+-----+-------+------+----------+----------+

unsigned request_read(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;
  size_t nbytes;
  uint8_t* ptr = buffer_write_ptr(r->rb, &nbytes);
  ssize_t n = recv(key->fd, ptr, nbytes, 0);

  if (n <= 0) return ERROR;
  buffer_write_adv(r->rb, n);

  while (buffer_can_read(r->rb) && r->state != REQUEST_DONE &&
         r->state != REQUEST_ERROR) {
    uint8_t byte = buffer_read(r->rb);
    switch (r->state) {
      case REQUEST_VERSION:
        request_process_version(r, byte);
        break;
      case REQUEST_CMD:
        request_process_cmd(r, byte);
        break;
      case REQUEST_RSV:
        request_process_rsv(r, byte);
        break;
      case REQUEST_ATYP:
        request_process_atyp(r, byte);
        break;
      case REQUEST_DSTADDR:
        request_process_dstaddr(r, byte);
        break;
      case REQUEST_DSTPORT:
        request_process_dstport(r, byte);
        break;
      default:
        break;
    }
  }

  if (r->state == REQUEST_ERROR) return request_marshall_reply(key, r->reply);
  if (r->state == REQUEST_DONE)
    return (r->atyp == SOCKS_ATYP_DOMAIN) ? request_start_resolve(key)
                                          : request_start_connect(key);
  return REQUEST_READ;
}

static unsigned request_start_resolve(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;
  struct addrinfo hints = {.ai_family = AF_UNSPEC,
                           .ai_socktype = SOCK_STREAM,
                           .ai_protocol = IPPROTO_TCP};
  char port_str[SOCKS_PORT_STR_LEN];
  snprintf(port_str, sizeof(port_str), "%u", r->dest_port);

  int err =
      getaddrinfo(r->dest_addr.fqdn, port_str, &hints, &s->origin_resolution);
  if (err != 0 || s->origin_resolution == NULL) {
    return request_marshall_reply(key, SOCKS_REPLY_HOST_UNREACHABLE);
  }
  s->current_origin_addr = s->origin_resolution;
  return request_start_connect(key);
}

static int setup_address(struct socks5* s, struct request_st* r,
                         struct sockaddr_storage* addr, socklen_t* addr_len) {
  memset(addr, 0, sizeof(*addr));
  *addr_len = 0;

  if (s->origin_resolution) {
    if (!s->current_origin_addr) {
      return -1;
    }
    memcpy(addr, s->current_origin_addr->ai_addr,
           s->current_origin_addr->ai_addrlen);
    *addr_len = s->current_origin_addr->ai_addrlen;
  } else if (r->atyp == SOCKS_ATYP_IPV4) {
    struct sockaddr_in* sin = (struct sockaddr_in*)addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = r->dest_addr.ipv4;
    sin->sin_port = htons(r->dest_port);
    *addr_len = sizeof(*sin);
  } else if (r->atyp == SOCKS_ATYP_IPV6) {
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = r->dest_addr.ipv6;
    sin6->sin6_port = htons(r->dest_port);
    *addr_len = sizeof(*sin6);
  }
  return 0;
}

static int create_socket(int family) {
  int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) return -1;
  if (selector_fd_set_nio(fd) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static unsigned request_start_connect(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;
  struct sockaddr_storage addr;
  socklen_t addr_len = 0;

  if (setup_address(s, r, &addr, &addr_len) < 0) {
    return request_marshall_reply(key, SOCKS_REPLY_HOST_UNREACHABLE);
  }

  int origin_fd = create_socket(addr.ss_family);
  if (origin_fd < 0) {
    return request_marshall_reply(key, SOCKS_REPLY_GENERAL_FAILURE);
  }

  if (connect(origin_fd, (struct sockaddr*)&addr, addr_len) < 0 &&
      errno != EINPROGRESS) {
    close(origin_fd);
    if (s->origin_resolution &&
        (s->current_origin_addr = s->current_origin_addr->ai_next))
      return request_start_connect(key);
    return request_marshall_reply(key, SOCKS_REPLY_CONNECTION_REFUSED);
  }

  s->origin_fd = origin_fd;
  s->references++;
  if (selector_register(key->s, origin_fd, &socks5_handler, OP_WRITE, s) !=
      SELECTOR_SUCCESS) {
    s->references--;
    close(origin_fd);
    s->origin_fd = -1;
    return request_marshall_reply(key, SOCKS_REPLY_GENERAL_FAILURE);
  }
  selector_set_interest_key(key, OP_NOOP);
  return REQUEST_CONNECTING;
}

unsigned request_resolving(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  if (s->origin_resolution) {
    s->current_origin_addr = s->origin_resolution;
    return request_start_connect(key);
  }
  return ERROR;
}

unsigned request_connecting(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;

  if (key->fd != s->origin_fd) return REQUEST_CONNECTING;

  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
      error != 0) {
    selector_unregister_fd(key->s, s->origin_fd);
    close(s->origin_fd);
    s->origin_fd = -1;
    s->references--;
    if (s->origin_resolution &&
        (s->current_origin_addr = s->current_origin_addr->ai_next)) {
      selector_set_interest(key->s, s->client_fd, OP_READ);
      return request_start_connect(key);
    }
    return request_marshall_reply(key, SOCKS_REPLY_CONNECTION_REFUSED);
  }

  for (int i = 0; i < SOCKS_IPV4_ADDR_SIZE + SOCKS_PORT_SIZE; i++)
    buffer_write(r->wb, 0x00);

  char dest_str[SOCKS_DOMAIN_MAX_LEN] = "unknown";
  if (r->atyp == SOCKS_ATYP_DOMAIN)
    snprintf(dest_str, sizeof(dest_str), "%s", r->dest_addr.fqdn);
  else if (r->atyp == SOCKS_ATYP_IPV4)
    inet_ntop(AF_INET, &r->dest_addr.ipv4, dest_str, sizeof(dest_str));

  logger_access(s->username, &s->client_addr, dest_str, r->dest_port, true);
  selector_set_interest(key->s, s->client_fd, OP_WRITE);
  selector_set_interest(key->s, s->origin_fd, OP_NOOP);
  return request_marshall_reply(key, SOCKS_REPLY_SUCCEEDED);
}

unsigned request_write(struct selector_key* key) {
  struct socks5* s = ATTACHMENT(key);
  struct request_st* r = &s->client.request;
  size_t nbytes;
  uint8_t* ptr = buffer_read_ptr(r->wb, &nbytes);
  ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

  if (n <= 0) return ERROR;
  buffer_read_adv(r->wb, n);

  if (!buffer_can_read(r->wb))
    return (r->reply == SOCKS_REPLY_SUCCEEDED) ? COPY : ERROR;
  return REQUEST_WRITE;
}
