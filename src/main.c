#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "args.h"
#include "selector.h"
#include "socks5nio.h"
#include "metrics.h"
#include "management.h"
#include "logger.h"

// =============================================================================
// Global State
// =============================================================================

static bool done = false;
struct socks5args socks5args;

// =============================================================================
// Signal Handlers
// =============================================================================

static void sigterm_handler(const int signal) {
  (void)signal;
  LOG_INFO("Received signal %d, initiating shutdown...\n", signal);
  done = true;
}

static void sigusr1_handler(const int signal) {
  (void)signal;
  metrics_print(stdout);
}

// =============================================================================
// Socket Setup Functions
// =============================================================================

static int create_udp_socket(const char *addr, unsigned short port) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_ERROR("Failed to create management socket: %s\n", strerror(errno));
        return -1;
    }

    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        LOG_WARNING("Failed to set SO_REUSEADDR on management socket: %s\n", strerror(errno));
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        LOG_ERROR("Invalid management address: %s\n", addr);
        close(sock);
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("Failed to bind management socket to %s:%hu: %s\n", 
            addr, port, strerror(errno));
        close(sock);
        return -1;
    }

    if (selector_fd_set_nio(sock) < 0) {
        LOG_ERROR("Failed to set management socket non-blocking: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static int create_passive_socket(const char* addr, unsigned short port,
                                 int family, bool dual_stack) {
  int sock = -1;
  int ret = -1;

  sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    LOG_ERROR("Failed to create socket: %s\n", strerror(errno));
    return -1;
  }

  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    LOG_WARNING("Failed to set SO_REUSEADDR: %s\n", strerror(errno));
  }

  if (family == AF_INET6) {
    int v6only = dual_stack ? 0 : 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) <
        0) {
      LOG_WARNING("Failed to set IPV6_V6ONLY: %s\n", strerror(errno));
    }
  }

  struct sockaddr_storage sa;
  socklen_t sa_len;
  memset(&sa, 0, sizeof(sa));

  if (family == AF_INET) {
    struct sockaddr_in* sa4 = (struct sockaddr_in*)&sa;
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons(port);
    if (addr == NULL || strcmp(addr, "0.0.0.0") == 0) {
      sa4->sin_addr.s_addr = INADDR_ANY;
    } else {
      if (inet_pton(AF_INET, addr, &sa4->sin_addr) != 1) {
        LOG_ERROR("Invalid IPv4 address: %s\n", addr);
        goto fail;
      }
    }
    sa_len = sizeof(struct sockaddr_in);
  } else {
    struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&sa;
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(port);
    if (addr == NULL || strcmp(addr, "::") == 0 ||
        strcmp(addr, "0.0.0.0") == 0) {
      sa6->sin6_addr = in6addr_any;
    } else {
      if (inet_pton(AF_INET6, addr, &sa6->sin6_addr) != 1) {
        LOG_ERROR("Invalid IPv6 address: %s\n", addr);
        goto fail;
      }
    }
    sa_len = sizeof(struct sockaddr_in6);
  }

  if (bind(sock, (struct sockaddr*)&sa, sa_len) < 0) {
    LOG_ERROR("Failed to bind to %s:%hu: %s\n", addr ? addr : "ANY", port,
            strerror(errno));
    goto fail;
  }

  if (listen(sock, SOMAXCONN) < 0) {
    LOG_ERROR("Failed to listen: %s\n", strerror(errno));
    goto fail;
  }

  if (selector_fd_set_nio(sock) < 0) {
    LOG_ERROR("Failed to set non-blocking mode: %s\n", strerror(errno));
    goto fail;
  }

  ret = sock;
  sock = -1;

fail:
  if (sock >= 0) {
    close(sock);
  }
  return ret;
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  close(STDIN_FILENO);

  parse_args(argc, argv, &socks5args);
  // Initialize logging
  logger_init(NULL, LOG_INFO);
  metrics_init();

  LOG_INFO("==============================================\n");
  LOG_INFO("       SOCKSv5 Proxy Server Arrancando\n");
  LOG_INFO("==============================================\n");
  LOG_INFO("SOCKS:      %s:%hu\n", socks5args.socks_addr,
          socks5args.socks_port);
  LOG_INFO("MANAGEMENT: %s:%hu\n", socks5args.mng_addr,
          socks5args.mng_port);
  LOG_INFO("==============================================\n");

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigterm_handler;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGTERM, &sa, NULL) < 0 || sigaction(SIGINT, &sa, NULL) < 0) {
    LOG_ERROR("Failed to set signal handlers\n");
    return 1;
  }

  // Handle SIGUSR1 to print metrics
  sa.sa_handler = sigusr1_handler;
  if (sigaction(SIGUSR1, &sa, NULL) < 0) {
    LOG_ERROR("Failed to set SIGUSR1 handler\n");
  }

  signal(SIGPIPE, SIG_IGN);

  const struct selector_init selector_config = {
      .signal = SIGALRM,
      .select_timeout =
          {
              .tv_sec = 10,
              .tv_nsec = 0,
          },
  };

  if (selector_init(&selector_config) != SELECTOR_SUCCESS) {
    LOG_ERROR("Failed to initialize selector\n");
    return 1;
  }

  fd_selector selector = selector_new(1024);
  if (selector == NULL) {
    LOG_ERROR("Failed to create selector\n");
    selector_close();
    return 1;
  }

  int socks_fd_v4 = -1;
  int socks_fd_v6 = -1;
  int mng_fd = -1;
  int ret = 0;

  socks_fd_v6 =
      create_passive_socket("::", socks5args.socks_port, AF_INET6, true);

  if (socks_fd_v6 >= 0) {
    LOG_INFO("Listening on [::]:%-5hu (dual-stack IPv4/IPv6)\n",
            socks5args.socks_port);
  } else {
    LOG_INFO("Dual-stack not available, falling back to IPv4-only\n");
    socks_fd_v4 = create_passive_socket(socks5args.socks_addr,
                                        socks5args.socks_port, AF_INET, false);
    if (socks_fd_v4 < 0) {
      LOG_ERROR("Failed to create SOCKS listening socket\n");
      ret = 1;
      goto cleanup;
    }
    LOG_INFO("Listening on %s:%-5hu (IPv4)\n", socks5args.socks_addr,
            socks5args.socks_port);
  }

  static const struct fd_handler socks5_passive_handler = {
      .handle_read = socksv5_passive_accept,
      .handle_write = NULL,
      .handle_close = NULL,
      .handle_block = NULL,
  };

  if (socks_fd_v6 >= 0) {
    if (selector_register(selector, socks_fd_v6, &socks5_passive_handler,
                          OP_READ, NULL) != SELECTOR_SUCCESS) {
      LOG_ERROR("Failed to register IPv6 SOCKS socket\n");
      ret = 1;
      goto cleanup;
    }
  }

  if (socks_fd_v4 >= 0) {
    if (selector_register(selector, socks_fd_v4, &socks5_passive_handler,
                          OP_READ, NULL) != SELECTOR_SUCCESS) {
      LOG_ERROR("Failed to register IPv4 SOCKS socket\n");
      ret = 1;
      goto cleanup;
    }
  }

  // Management Interface Setup
  mgmt_init();
  mng_fd = create_udp_socket(socks5args.mng_addr, socks5args.mng_port);
  if (mng_fd < 0) {
      LOG_ERROR("Failed to create management socket\n");
      ret = 1;
      goto cleanup;
  }
  
  static const struct fd_handler management_handler = {
      .handle_read = mgmt_handle_request,
      .handle_write = NULL,
      .handle_close = NULL,
      .handle_block = NULL,
  };

  if (selector_register(selector, mng_fd, &management_handler,
                        OP_READ, NULL) != SELECTOR_SUCCESS) {
      LOG_ERROR("Failed to register management socket\n");
      ret = 1;
      goto cleanup;
  }
  LOG_INFO("Management interface listening on %s:%hu\n", 
          socks5args.mng_addr, socks5args.mng_port);

  LOG_INFO("Server ready. Waiting for connections...\n");

  while (!done) {
    selector_status ss = selector_select(selector);
    if (ss != SELECTOR_SUCCESS) {
      if (errno == EINTR) {
        continue;
      }
      LOG_ERROR("Selector error: %s\n", selector_error(ss));
      ret = 1;
      break;
    }
  }

  LOG_INFO("Shutting down...\n");
  metrics_print(stdout);

cleanup:
  if (selector != NULL) {
    selector_destroy(selector);
  }
  selector_close();

  if (socks_fd_v4 >= 0) close(socks_fd_v4);
  if (socks_fd_v6 >= 0) close(socks_fd_v6);
  if (mng_fd >= 0) close(mng_fd);

  mgmt_cleanup();
  socksv5_pool_destroy();
  logger_close();

  return ret;
}
