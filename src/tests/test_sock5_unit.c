#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "socks5_internal.h"
#include "args.h"
#include "buffer.h"

// =============================================================================
// MOCKS (Stubs for dependencies)
// =============================================================================

// Global args required by socks5_auth.c
struct socks5args socks5args;

// Mock selector functions so we don't need the real selector library
selector_status selector_set_interest(fd_selector s, int fd, fd_interest i) { (void)s; (void)fd; (void)i; return SELECTOR_SUCCESS; }
selector_status selector_set_interest_key(struct selector_key *key, fd_interest i) { (void)key; (void)i; return SELECTOR_SUCCESS; }
selector_status selector_register(fd_selector s, int fd, const struct fd_handler *handler, fd_interest interest, void *data) { (void)s; (void)fd; (void)handler; (void)interest; (void)data; return SELECTOR_SUCCESS; }
selector_status selector_unregister_fd(fd_selector s, int fd) { (void)s; (void)fd; return SELECTOR_SUCCESS; }
int selector_fd_set_nio(int fd) { (void)fd; return 0; }

// Mock socks5_handler
const struct fd_handler socks5_handler = {
    .handle_read = NULL,
    .handle_write = NULL,
    .handle_close = NULL,
};

// =============================================================================
// TEST HARNESS
// =============================================================================

struct test_env {
    int client_fd; // We write to this (simulate client)
    int server_fd; // The function under test reads from this
    struct socks5 data;
    struct selector_key key;
};

void setup_env(struct test_env *env) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        perror("socketpair");
        exit(1);
    }
    env->client_fd = fds[0];
    env->server_fd = fds[1];
    
    // Initialize the socks5 struct
    memset(&env->data, 0, sizeof(env->data));
    buffer_init(&env->data.read_buffer, BUFFER_SIZE, env->data.read_buffer_data);
    buffer_init(&env->data.write_buffer, BUFFER_SIZE, env->data.write_buffer_data);
    
    // Setup the selector key
    env->key.fd = env->server_fd;
    env->key.data = &env->data;
    env->key.s = NULL; // Mock selector
}

void teardown_env(struct test_env *env) {
    close(env->client_fd);
    close(env->server_fd);
    if (env->data.username) free(env->data.username);
}

// Helper to write to socket and check error
void write_msg(int fd, const void *buf, size_t count) {
    if (write(fd, buf, count) < 0) {
        perror("write");
        exit(1);
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

void test_hello_read_no_auth() {
    printf("[TEST] hello_read (No Auth)... ");
    struct test_env env;
    setup_env(&env);
    
    // 1. Initialize State
    hello_read_init(HELLO_READ, &env.key);
    
    // 2. Simulate Client: Version 5, 1 Method, Method 0x00 (No Auth)
    uint8_t msg[] = { 0x05, 0x01, 0x00 };
    write_msg(env.client_fd, msg, sizeof(msg));
    
    // 3. Run Function
    unsigned ret = hello_read(&env.key);
    
    // 4. Assertions
    assert(ret == HELLO_WRITE);
    assert(env.data.client.hello.version == 0x05);
    assert(env.data.client.hello.method == 0x00); // Should select No Auth
    
    teardown_env(&env);
    printf("PASSED\n");
}

void test_hello_read_user_pass() {
    printf("[TEST] hello_read (User/Pass)... ");
    struct test_env env;
    setup_env(&env);
    
    // Configure server to require a user
    socks5args.users[0].name = "admin";
    socks5args.users[0].pass = "1234";
    
    hello_read_init(HELLO_READ, &env.key);
    
    // Client offers: No Auth (00) and User/Pass (02)
    uint8_t msg[] = { 0x05, 0x02, 0x00, 0x02 };
    write_msg(env.client_fd, msg, sizeof(msg));
    
    unsigned ret = hello_read(&env.key);
    
    assert(ret == HELLO_WRITE);
    assert(env.data.client.hello.method == 0x02); // Should select User/Pass
    
    // Reset args
    socks5args.users[0].name = NULL;
    teardown_env(&env);
    printf("PASSED\n");
}

void test_auth_read_success() {
    printf("[TEST] auth_read (Success)... ");
    struct test_env env;
    setup_env(&env);
    
    socks5args.users[0].name = "user";
    socks5args.users[0].pass = "pass";
    
    auth_read_init(AUTH_READ, &env.key);
    
    // Client sends: Ver 1, Ulen 4, "user", Plen 4, "pass"
    uint8_t msg[] = { 0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's' };
    write_msg(env.client_fd, msg, sizeof(msg));
    
    unsigned ret = auth_read(&env.key);
    
    assert(ret == AUTH_WRITE);
    assert(env.data.client.auth.status == 0x00); // Success
    assert(strcmp(env.data.username, "user") == 0);
    
    socks5args.users[0].name = NULL;
    teardown_env(&env);
    printf("PASSED\n");
}

void test_auth_read_failure() {
    printf("[TEST] auth_read (Wrong Password)... ");
    struct test_env env;
    setup_env(&env);
    
    socks5args.users[0].name = "user";
    socks5args.users[0].pass = "pass";
    
    auth_read_init(AUTH_READ, &env.key);
    
    // Client sends: Ver 1, Ulen 4, "user", Plen 4, "WRONG"
    uint8_t msg[] = { 0x01, 0x04, 'u', 's', 'e', 'r', 0x05, 'W', 'R', 'O', 'N', 'G' };
    write_msg(env.client_fd, msg, sizeof(msg));
    
    unsigned ret = auth_read(&env.key);
    
    assert(ret == AUTH_WRITE);
    assert(env.data.client.auth.status != 0x00); // Failure
    
    socks5args.users[0].name = NULL;
    teardown_env(&env);
    printf("PASSED\n");
}

void test_request_parse_ipv4() {
    printf("[TEST] request_read (IPv4 Parsing)... ");
    struct test_env env;
    setup_env(&env);
    
    request_read_init(REQUEST_READ, &env.key);
    
    // Client sends: Ver 5, Cmd 1 (Connect), Rsv 0, Atyp 1 (IPv4), 127.0.0.1, Port 80
    uint8_t msg[] = { 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    write_msg(env.client_fd, msg, sizeof(msg));
    
    // Note: request_read will try to connect() which might fail or succeed depending on the system.
    // We mainly want to verify it parsed the buffer correctly.
    request_read(&env.key);
    
    struct request_st *r = &env.data.client.request;
    
    assert(r->cmd == 0x01);
    assert(r->atyp == 0x01);
    assert(r->dest_port == 80);
    // Check IP: 127.0.0.1 is 0x7F000001
    assert(r->dest_addr.ipv4.s_addr == inet_addr("127.0.0.1"));
    
    teardown_env(&env);
    printf("PASSED\n");
}

int main() {
    printf("=== SOCKS5 Unit Tests ===\n");
    test_hello_read_no_auth();
    test_hello_read_user_pass();
    test_auth_read_success();
    test_auth_read_failure();
    test_request_parse_ipv4();
    printf("All tests passed.\n");
    return 0;
}