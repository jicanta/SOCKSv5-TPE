#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_PORT 8080
#define BUF_SIZE 4096
#define TIMEOUT_SEC 2

static void usage(const char *progname) {
    fprintf(stderr,
            "Usage: %s [OPTIONS] [COMMAND [ARGS...]]\n"
            "\n"
            "Options:\n"
            "  -L <addr>   Management server address (default: %s)\n"
            "  -P <port>   Management server port (default: %d)\n"
            "  -h          Show this help message\n"
            "\n"
            "Commands:\n"
            "  STATS              Show server statistics\n"
            "  USERS              List registered users\n"
            "  ADD <user>:<pass>  Add a new user\n"
            "  DEL <user>         Delete a user\n"
            "\n"
            "If no command is provided, interactive mode is started.\n",
            progname, DEFAULT_MNG_ADDR, DEFAULT_MNG_PORT);
    exit(1);
}

static int setup_socket(const char *addr, unsigned short port, struct sockaddr_storage *server_addr) {
    struct addrinfo hints, *res;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(addr, port_str, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "Error resolving address: %s\n", gai_strerror(err));
        return -1;
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }

    memcpy(server_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return sockfd;
}

static void send_command(int sockfd, struct sockaddr_storage *server_addr, const char *cmd) {
    socklen_t addr_len = sizeof(*server_addr);
    if (server_addr->ss_family == AF_INET) {
        addr_len = sizeof(struct sockaddr_in);
    } else if (server_addr->ss_family == AF_INET6) {
        addr_len = sizeof(struct sockaddr_in6);
    }

    ssize_t sent = sendto(sockfd, cmd, strlen(cmd), 0, (struct sockaddr *)server_addr, addr_len);
    if (sent < 0) {
        perror("sendto");
        return;
    }

    char buf[BUF_SIZE];
    ssize_t received = recvfrom(sockfd, buf, sizeof(buf) - 1, 0, NULL, NULL);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "Timeout waiting for response\n");
        } else {
            perror("recvfrom");
        }
        return;
    }

    buf[received] = '\0';
    printf("%s", buf);
}

int main(int argc, char *argv[]) {
    char *mng_addr = DEFAULT_MNG_ADDR;
    unsigned short mng_port = DEFAULT_MNG_PORT;

    int opt;
    while ((opt = getopt(argc, argv, "hL:P:")) != -1) {
        switch (opt) {
            case 'L':
                mng_addr = optarg;
                break;
            case 'P':
                mng_port = atoi(optarg);
                if (mng_port == 0) {
                     fprintf(stderr, "Invalid port: %s\n", optarg);
                     exit(1);
                }
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                usage(argv[0]);
        }
    }

    struct sockaddr_storage server_addr;
    int sockfd = setup_socket(mng_addr, mng_port, &server_addr);
    if (sockfd < 0) {
        exit(1);
    }

    if (optind < argc) {
        char cmd_buf[BUF_SIZE] = "";
        for (int i = optind; i < argc; i++) {
            strncat(cmd_buf, argv[i], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
            if (i < argc - 1) {
                strncat(cmd_buf, " ", sizeof(cmd_buf) - strlen(cmd_buf) - 1);
            }
        }
        send_command(sockfd, &server_addr, cmd_buf);
    } else {
        printf("Connected to %s:%d\n", mng_addr, mng_port);
        printf("Type 'help' for commands, 'exit' or 'quit' to quit.\n\n");

        char line[BUF_SIZE];
        while (1) {
            printf("mgmt> ");
            if (fgets(line, sizeof(line), stdin) == NULL) {
                break;
            }

            line[strcspn(line, "\n")] = 0;

            if (strlen(line) == 0) {
                continue;
            }

            if (strcasecmp(line, "quit") == 0 || strcasecmp(line, "exit") == 0 || strcasecmp(line, "q") == 0) {
                break;
            }

            send_command(sockfd, &server_addr, line);
        }
    }

    close(sockfd);
    return 0;
}
