#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "selector.h"
#include "socks5_internal.h"

// =============================================================================
// COPY STATE
//
// This file implements the transparent proxying phase (COPY).
// Data is read from one socket and written to the other.
//
// The flow is controlled by 'struct copy_st' which manages:
// - The file descriptor (fd)
// - The read buffer (rb) - where we read data INTO
// - The write buffer (wb) - where we write data FROM
// - The other side of the connection (other)
// =============================================================================

/**
 * Determines which events (READ/WRITE) we should monitor for a given connection.
 *
 * Flow Control Logic:
 * 1. Monitor OP_READ only if we have space in the read buffer.
 * 2. Monitor OP_WRITE only if we have data in the write buffer.
 */
static void update_selector_interests(fd_selector sel, struct copy_st *conn) {
  fd_interest interest = OP_NOOP;

  // If we are still allowed to read, and there is space in the buffer
  if ((conn->duplex & OP_READ) && buffer_can_write(conn->rb)) {
    interest |= OP_READ;
  }

  // If we are still allowed to write, and there is data to send
  if ((conn->duplex & OP_WRITE) && buffer_can_read(conn->wb)) {
    interest |= OP_WRITE;
  }

  selector_set_interest(sel, *conn->fd, interest);
}

/**
 * Helper to retrieve the copy state (client or origin) based on the triggering
 * fd.
 */
static struct copy_st *get_connection_state(struct selector_key *key) {
  struct socks5 *data = ATTACHMENT(key);
  if (key->fd == data->client_fd) {
    return &data->client.copy;
  } else {
    return &data->origin.copy;
  }
}

/**
 * Handles the closing of a connection direction (Read EOF).
 *
 * When we read 0 bytes (EOF), it means the peer has stopped sending.
 * We should:
 * 1. Stop reading from this socket (SHUT_RD).
 * 2. Stop writing to the other socket (SHUT_WR) - propagating the FIN.
 */
static unsigned handle_read_eof(struct copy_st *conn) {
  // 1. Close read side of this connection
  shutdown(*conn->fd, SHUT_RD);
  conn->duplex &= ~OP_READ;

  // 2. Close write side of the other connection
  if (*conn->other->fd != -1) {
    shutdown(*conn->other->fd, SHUT_WR);
    conn->other->duplex &= ~OP_WRITE;
  }

  // If both sides are completely closed, we are done
  if (conn->duplex == OP_NOOP && conn->other->duplex == OP_NOOP) {
    return DONE;
  }
  return COPY;
}

/**
 * Handles write errors.
 *
 * If we fail to write, the connection is broken. We close the write side
 * of this connection and the read side of the other.
 */
static unsigned handle_write_error(struct copy_st *conn) {
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

void copy_init(const unsigned state, struct selector_key *key) {
  (void)state;
  struct socks5 *data = ATTACHMENT(key);

  // Reset buffers for reuse
  buffer_reset(&data->read_buffer);
  buffer_reset(&data->write_buffer);

  // Initialize Client State
  // Client reads into read_buffer, writes from write_buffer
  data->client.copy = (struct copy_st){.fd = &data->client_fd,
                                       .rb = &data->read_buffer,
                                       .wb = &data->write_buffer,
                                       .duplex = OP_READ | OP_WRITE,
                                       .other = &data->origin.copy};

  // Initialize Origin State
  // Origin reads into write_buffer (swapped), writes from read_buffer (swapped)
  data->origin.copy = (struct copy_st){.fd = &data->origin_fd,
                                       .rb = &data->write_buffer,
                                       .wb = &data->read_buffer,
                                       .duplex = OP_READ | OP_WRITE,
                                       .other = &data->client.copy};

  // Register initial interests
  selector_set_interest(key->s, data->client_fd, OP_READ);
  selector_set_interest(key->s, data->origin_fd, OP_READ);
}

unsigned copy_read(struct selector_key *key) {
  struct copy_st *conn = get_connection_state(key);
  size_t capacity;

  // Prepare buffer for writing
  uint8_t *write_ptr = buffer_write_ptr(conn->rb, &capacity);

  // Perform the read
  ssize_t bytes_read = recv(key->fd, write_ptr, capacity, 0);

  if (bytes_read <= 0) {
    return handle_read_eof(conn);
  } else {
    buffer_write_adv(conn->rb, bytes_read);
  }

  // Update interests for both sides
  // (We might have filled the read buffer, or provided data for the other side
  // to write)
  update_selector_interests(key->s, conn);
  update_selector_interests(key->s, conn->other);

  return COPY;
}

unsigned copy_write(struct selector_key *key) {
  struct copy_st *conn = get_connection_state(key);
  size_t pending_bytes;

  // Prepare buffer for reading
  uint8_t *read_ptr = buffer_read_ptr(conn->wb, &pending_bytes);

  // Perform the write
  ssize_t bytes_sent = send(key->fd, read_ptr, pending_bytes, MSG_NOSIGNAL);

  if (bytes_sent <= 0) {
    return handle_write_error(conn);
  } else {
    buffer_read_adv(conn->wb, bytes_sent);
  }

  // Update interests for both sides
  // (We might have drained the write buffer, or freed up space for the other
  // side to read)
  update_selector_interests(key->s, conn);
  update_selector_interests(key->s, conn->other);

  return COPY;
}
