/**
 * main.c - SOCKSv5 Proxy Server with Management Interface
 *
 * A concurrent, non-blocking SOCKSv5 proxy server implementing:
 * - RFC 1928 (SOCKSv5)
 * - RFC 1929 (Username/Password Authentication)
 *
 * Features:
 * - Dual-stack IPv4/IPv6 support
 * - Non-blocking I/O using selector (pselect)
 * - Support for 500+ concurrent connections
 * - Management protocol for configuration and metrics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "socks5nio.h"
#include "selector.h"
#include "args.h"

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
    fprintf(stdout, "Received signal %d, initiating shutdown...\n", signal);
    done = true;
}

// =============================================================================
// Socket Setup Functions
// =============================================================================

/**
 * Create and configure a passive (listening) TCP socket.
 * 
 * @param addr Address to bind to (IPv4 or IPv6)
 * @param port Port number
 * @param family AF_INET or AF_INET6
 * @param dual_stack If true and family is AF_INET6, enables dual-stack
 * @return Socket fd on success, -1 on failure
 */
static int create_passive_socket(const char *addr, unsigned short port, 
                                  int family, bool dual_stack) {
    int sock = -1;
    int ret = -1;
    
    // Create socket
    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    // Enable address reuse
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "Failed to set SO_REUSEADDR: %s\n", strerror(errno));
    }
    
    // For IPv6, optionally disable IPV6_V6ONLY to enable dual-stack
    if (family == AF_INET6) {
        int v6only = dual_stack ? 0 : 1;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
            fprintf(stderr, "Failed to set IPV6_V6ONLY: %s\n", strerror(errno));
        }
    }
    
    // Prepare address structure
    struct sockaddr_storage sa;
    socklen_t sa_len;
    memset(&sa, 0, sizeof(sa));
    
    if (family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        if (addr == NULL || strcmp(addr, "0.0.0.0") == 0) {
            sa4->sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, addr, &sa4->sin_addr) != 1) {
                fprintf(stderr, "Invalid IPv4 address: %s\n", addr);
                goto fail;
            }
        }
        sa_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        if (addr == NULL || strcmp(addr, "::") == 0 || strcmp(addr, "0.0.0.0") == 0) {
            sa6->sin6_addr = in6addr_any;
        } else {
            if (inet_pton(AF_INET6, addr, &sa6->sin6_addr) != 1) {
                fprintf(stderr, "Invalid IPv6 address: %s\n", addr);
                goto fail;
            }
        }
        sa_len = sizeof(struct sockaddr_in6);
    }
    
    // Bind socket
    if (bind(sock, (struct sockaddr *)&sa, sa_len) < 0) {
        fprintf(stderr, "Failed to bind to %s:%hu: %s\n", 
                  addr ? addr : "ANY", port, strerror(errno));
        goto fail;
    }
    
    // Listen with backlog for concurrent connections
    // Use SOMAXCONN or a large value for high concurrency
    if (listen(sock, SOMAXCONN) < 0) {
        fprintf(stderr, "Failed to listen: %s\n", strerror(errno));
        goto fail;
    }
    
    // Set non-blocking mode
    if (selector_fd_set_nio(sock) < 0) {
        fprintf(stderr, "Failed to set non-blocking mode: %s\n", strerror(errno));
        goto fail;
    }
    
    ret = sock;
    sock = -1;  // Prevent cleanup
    
fail:
// ...existing code...
    if (sock >= 0) {
        close(sock);
    }
    return ret;
}

// =============================================================================
// Main Entry Point
// =============================================================================

int main(int argc, char *argv[]) {
// ...existing code...
    
    // Disable buffering for stdout/stderr for immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    // Close stdin - we don't need it
    close(STDIN_FILENO);
    
    // Parse command line arguments
    parse_args(argc, argv, &socks5args);
    
    fprintf(stdout, "==============================================\n");
    fprintf(stdout, "       SOCKSv5 Proxy Server Starting\n");
    fprintf(stdout, "==============================================\n");
    fprintf(stdout, "SOCKS:      %s:%hu\n", socks5args.socks_addr, socks5args.socks_port);
    fprintf(stdout, "==============================================\n");
    
    // Set up signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTERM, &sa, NULL) < 0 || sigaction(SIGINT, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to set signal handlers\n");
        return 1;
    }
    
    // Ignore SIGPIPE (we handle write errors gracefully)
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize selector library
    const struct selector_init selector_config = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };
    
    if (selector_init(&selector_config) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Failed to initialize selector\n");
        return 1;
    }
    
    // Create selector instance
    fd_selector selector = selector_new(1024);
    if (selector == NULL) {
        fprintf(stderr, "Failed to create selector\n");
        selector_close();
        return 1;
    }
    
    int socks_fd_v4 = -1;
    int socks_fd_v6 = -1;
    int ret = 0;
    
    // Try to create IPv6 socket with dual-stack (handles both IPv4 and IPv6)
    socks_fd_v6 = create_passive_socket("::", socks5args.socks_port, AF_INET6, true);
    
    if (socks_fd_v6 >= 0) {
        fprintf(stdout, "Listening on [::]:%-5hu (dual-stack IPv4/IPv6)\n", socks5args.socks_port);
    } else {
        // Fall back to IPv4-only if IPv6 dual-stack fails
        fprintf(stdout, "Dual-stack not available, falling back to IPv4-only\n");
        socks_fd_v4 = create_passive_socket(socks5args.socks_addr, 
                                             socks5args.socks_port, AF_INET, false);
        if (socks_fd_v4 < 0) {
            fprintf(stderr, "Failed to create SOCKS listening socket\n");
            ret = 1;
            goto cleanup;
        }
        fprintf(stdout, "Listening on %s:%-5hu (IPv4)\n", socks5args.socks_addr, socks5args.socks_port);
    }
    
    // Create SOCKSv5 handler for passive socket
    static const struct fd_handler socks5_passive_handler = {
        .handle_read = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
        .handle_block = NULL,
    };
    
    // Register SOCKS socket(s) with selector
    if (socks_fd_v6 >= 0) {
        if (selector_register(selector, socks_fd_v6, &socks5_passive_handler,
                              OP_READ, NULL) != SELECTOR_SUCCESS) {
            fprintf(stderr, "Failed to register IPv6 SOCKS socket\n");
            ret = 1;
            goto cleanup;
        }
    }
    
    if (socks_fd_v4 >= 0) {
        if (selector_register(selector, socks_fd_v4, &socks5_passive_handler,
                              OP_READ, NULL) != SELECTOR_SUCCESS) {
            fprintf(stderr, "Failed to register IPv4 SOCKS socket\n");
            ret = 1;
            goto cleanup;
        }
    }
    
    fprintf(stdout, "Server ready. Waiting for connections...\n");
    
    // Main event loop
    while (!done) {
        selector_status ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            if (errno == EINTR) {
                continue;  // Signal interrupted, check done flag
            }
            fprintf(stderr, "Selector error: %s\n", selector_error(ss));
            ret = 1;
            break;
        }
    }
    
    fprintf(stdout, "Shutting down...\n");
    
cleanup:
    // Clean up resources
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    
    if (socks_fd_v4 >= 0) close(socks_fd_v4);
    if (socks_fd_v6 >= 0) close(socks_fd_v6);
    
    // Clean up connection pool
    socksv5_pool_destroy();
    
    return ret;
}

