// echo_server.c
// Servidor TCP bloqueante, maneja un cliente a la vez y le hace echo de todo lo
// que envía.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>  // inet_ntoa
#include <netinet/in.h> // struct sockaddr_in
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // close, read, write

#define BACKLOG 10 // tamaño de cola de listen()
#define BUF_SIZE 4096

// stdio.h, stdlib.h, string.h y errno.h: lo clasico de C para imprimir, manejar
// strings y errores unistd.h nos da close(), read(), write() y las típicas
// syscalls POSIX sys/socket.h, netinet/in.h, arpa/inet.h nos da todo lo
// vinculados a sockets como el struct sockaddr_in, constantes como AF_INET,
// etc. BACKLOG define cuantas conexiones puede tener en la cola el listen()
// antes de que las empiece a aceptar con accept(). BUF_SIZE es el tamaño del
// buffer con el que leemos del cliente

static void die(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  // el server espera un único argumento: el puerto donde va a escuchar
  // server_fd y client_fd son file descriptors. el de server es el socket
  // pasivo que escucha. el de client es el socket activo para hablar con 1
  // cliente
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
  // AF_INET son familias de direcciones IPV4.
  // SOCK_STREAM indica que es tipo TCP.
  // el server_fd es como un archivo especial por donde recibo conexiones de
  // red.
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    die("socket");
  }

  // Opcional: SO_REUSEADDR para poder reusar el puerto rápido al reiniciar
  int optval = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
      0) {
    die("setsockopt(SO_REUSEADDR)");
  }

  // 2) bind()
  // asigna ip:puerto.
  // el struct sockaddr_in representa una ip y un puerto.
  // bind() le dice al SO que este socket va a escuchar en esta ip y este puerto
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
  addr.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    die("bind");
  }

  // 3) listen()
  // el listen le dice al SO que arranque a escuchar conexiones entrantes en el
  // socket. despues del listen(), el socket es un socket pasivo.
  if (listen(server_fd, BACKLOG) < 0) {
    die("listen");
  }

  printf("Echo server escuchando en puerto %d...\n", port);

  // Bucle principal: aceptar clientes de a uno
  // bucle infinito: el server vive para siempre aceptando clientes
  // client_addr va a contener la IP:Puerto del cliente que se conecta.
  // accept() bloquea hasta que llega una nueva conexión.
  // devuelve un fd client_fd que es el canal para hablar con ese cliente.
  for (;;) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    // 4) accept() – bloquea hasta que llega un cliente
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
      // Si es una señal/restart, podés ignorar algunos errores, pero por ahora
      // salimos
      die("accept");
    }

    printf("Nuevo cliente desde %s:%d\n", inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port));

    // 5) Bucle de echo por cada cliente
    // mientras el cliente siga conectado, seguimos leyendo datos
    // el read bloquea.

    for (;;) {
      char buf[BUF_SIZE];

      ssize_t nread = read(client_fd, buf, sizeof(buf));
      if (nread < 0) {
        perror("read");
        break; // cerramos el cliente
      } else if (nread == 0) {
        // EOF: el cliente cerró la conexión
        printf("Cliente cerró la conexión\n");
        break;
      }

      // "Echo": mandar de vuelta exactamente lo que recibimos
      ssize_t total_written = 0;
      while (total_written < nread) {
        ssize_t nw =
            write(client_fd, buf + total_written, nread - total_written);
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
// este server usa I/O bloqueante.
// read() y accept() detienen todo hasta que pase algo.
// esto hace tmb que no pueda aceptar varios clientes (mientras leo de uno, no
// puedo aceptar a otros). para el TP vamos a tener que usar IO no bloqueante y
// un selector (como select o poll) vamos a poner todos los sockets en
// O_NONBLOCK