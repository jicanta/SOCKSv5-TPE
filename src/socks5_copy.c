#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5_internal.h"

#include "metrics.h"

// =============================================================================
// COPY
// =============================================================================

static void update_selector_interests(fd_selector sel, struct copy_st* conn) {
  fd_interest interest = OP_NOOP;

  if ((conn->duplex & OP_READ) && buffer_can_write(conn->rb)) {
    interest |= OP_READ;
  }

  if ((conn->duplex & OP_WRITE) && buffer_can_read(conn->wb)) {
    interest |= OP_WRITE;
  }

  selector_set_interest(sel, *conn->fd, interest);
}

static struct copy_st* get_connection_state(struct selector_key* key) {
  struct socks5* data = ATTACHMENT(key);
  if (key->fd == data->client_fd) {
    return &data->client.copy;
  } else {
    return &data->origin.copy;
  }
}

static unsigned handle_read_eof(struct copy_st* conn) {
  shutdown(*conn->fd, SHUT_RD);
  conn->duplex &= ~OP_READ;

  if (*conn->other->fd != -1) {
    shutdown(*conn->other->fd, SHUT_WR);
    conn->other->duplex &= ~OP_WRITE;
  }

  if (conn->duplex == OP_NOOP && conn->other->duplex == OP_NOOP) {
    return DONE;
  }
  return COPY;
}

static unsigned handle_write_error(struct copy_st* conn) {
  shutdown(*conn->fd, SHUT_WR);
  conn->duplex &= ~OP_WRITE;

  if (*conn->other->fd != -1) {
    shutdown(*conn->other->fd, SHUT_RD);
    conn->other->duplex &= ~OP_READ;
  }

  if (conn->duplex == OP_NOOP && conn->other->duplex == OP_NOOP) {
    return DONE;
  }
  return COPY;
}

void copy_init(const unsigned state, struct selector_key* key) {
  (void)state;
  struct socks5* data = ATTACHMENT(key);

  buffer_reset(&data->read_buffer);
  buffer_reset(&data->write_buffer);

  data->client.copy = (struct copy_st){.fd = &data->client_fd,
                                       .rb = &data->read_buffer,
                                       .wb = &data->write_buffer,
                                       .duplex = OP_READ | OP_WRITE,
                                       .other = &data->origin.copy};

  data->origin.copy = (struct copy_st){.fd = &data->origin_fd,
                                       .rb = &data->write_buffer,
                                       .wb = &data->read_buffer,
                                       .duplex = OP_READ | OP_WRITE,
                                       .other = &data->client.copy};

  selector_set_interest(key->s, data->client_fd, OP_READ);
  selector_set_interest(key->s, data->origin_fd, OP_READ);
}

unsigned copy_read(struct selector_key* key) {
  struct copy_st* conn = get_connection_state(key);
  size_t capacity;

  uint8_t* write_ptr = buffer_write_ptr(conn->rb, &capacity);

  ssize_t bytes_read = recv(key->fd, write_ptr, capacity, 0);

  if (bytes_read <= 0) {
    return handle_read_eof(conn);
  } else {
    buffer_write_adv(conn->rb, bytes_read);
    
    struct socks5* data = ATTACHMENT(key);
    if (key->fd == data->client_fd) {
        metrics_add_bytes_received(bytes_read);
    }
  }

  update_selector_interests(key->s, conn);
  update_selector_interests(key->s, conn->other);

  return COPY;
}

unsigned copy_write(struct selector_key* key) {
  struct copy_st* conn = get_connection_state(key);
  size_t pending_bytes;

  uint8_t* read_ptr = buffer_read_ptr(conn->wb, &pending_bytes);

  ssize_t bytes_sent = send(key->fd, read_ptr, pending_bytes, MSG_NOSIGNAL);

  if (bytes_sent <= 0) {
    return handle_write_error(conn);
  } else {
    buffer_read_adv(conn->wb, bytes_sent);
  
    struct socks5* data = ATTACHMENT(key);
    if (key->fd == data->client_fd) {
        metrics_add_bytes_sent(bytes_sent);
    }
  }

  update_selector_interests(key->s, conn);
  update_selector_interests(key->s, conn->other);

  return COPY;
}
