// echo_server.c
// Servidor TCP bloqueante, maneja un cliente a la vez y le hace echo de todo lo que envía.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>         // close, read, write
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>     // struct sockaddr_in
#include <arpa/inet.h>      // inet_ntoa

#define BACKLOG 10          // tamaño de cola de listen()
#define BUF_SIZE 4096

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <puerto>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Puerto inválido: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    int server_fd = -1;
    int client_fd = -1;

    // 1) socket()
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        die("socket");
    }

    // Opcional: SO_REUSEADDR para poder reusar el puerto rápido al reiniciar
    int optval = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        die("setsockopt(SO_REUSEADDR)");
    }

    // 2) bind()
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        die("bind");
    }

    // 3) listen()
    if (listen(server_fd, BACKLOG) < 0) {
        die("listen");
    }

    printf("Echo server escuchando en puerto %d...\n", port);

    // Bucle principal: aceptar clientes de a uno
    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        memset(&client_addr, 0, sizeof(client_addr));

        // 4) accept() – bloquea hasta que llega un cliente
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            // Si es una señal/restart, podés ignorar algunos errores, pero por ahora salimos
            die("accept");
        }

        printf("Nuevo cliente desde %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // 5) Bucle de echo por cada cliente
        for (;;) {
            char buf[BUF_SIZE];

            ssize_t nread = read(client_fd, buf, sizeof(buf));
            if (nread < 0) {
                perror("read");
                break;  // cerramos el cliente
            } else if (nread == 0) {
                // EOF: el cliente cerró la conexión
                printf("Cliente cerró la conexión\n");
                break;
            }

            // "Echo": mandar de vuelta exactamente lo que recibimos
            ssize_t total_written = 0;
            while (total_written < nread) {
                ssize_t nw = write(client_fd, buf + total_written, nread - total_written);
                if (nw < 0) {
                    perror("write");
                    goto close_client;
                }
                total_written += nw;
            }
        }

close_client:
        close(client_fd);
        client_fd = -1;
        // Volvemos al for(;;) principal para aceptar otro cliente
    }

    // Nunca llegamos acá en este ejemplo, pero por prolijidad:
    close(server_fd);
    return EXIT_SUCCESS;
}
