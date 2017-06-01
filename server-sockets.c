#include <errno.h>
#include <gssapi.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "server-sockets.h"

int
setup_server()
{
    int enable = 1;
    int call_val = 0;
    int srv_socket;
    struct sockaddr_in srv_addr;

    srv_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_socket == -1) {
        fprintf(stderr, "Error: socket connection error.\n");
        return -1;
    }

    setsockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    setsockopt(srv_socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(2025);
    srv_addr.sin_addr.s_addr = htons(INADDR_ANY);

    call_val = bind(srv_socket, (struct sockaddr *)&srv_addr,
                    sizeof(srv_addr));
    if (call_val == -1) {
        fprintf(stderr, "Error: binding to socket (%d:%s).\n", errno,
                strerror(errno));

        return -2;
    }

    call_val = listen(srv_socket, 100);
    if (call_val == -1) {
        fprintf(stderr, "Error: listening to socket (%d:%s).\n", errno,
                strerror(errno));

        return -3;
    }

    printf("Successfully listening on 2025...\n");

    return srv_socket;
}

int
server_client_handshake(int client_socket)
{
    char *data = NULL;
    ssize_t rw_length = 0;
    int call_val = 0;
    int exit_out = 0;

    data = malloc(sizeof(char *) * 1024 * 32)
    if (data == NULL) {
        fprintf(stderr, "Error: Malloc failed!\n");

        exit_out = 99;
        goto cleanup;
    }

    rw_length = read(client_socket, data, 1024 * 32);
    if (rw_length < 0 || rw_length < 4) {
        printf("Error reading from socket or invalid data.\n");

        exit_out = 1;
        goto cleanup;
    }


    call_value = strncmp(data, "auth", 4);
    if (call_value != 0) {
        printf("Client didn't get auth. Ignoring...\n");

        exit_out = 2;
    }

    printf("Got auth.\n");

    rw_length = write(client_socket, "ack\n", 4);
    if (rw_length < 0) {
        printf("Error: writing to socket (%d:%s).\n", errno, strerror(errno));
        exit_out = 3;
        goto cleanup;
    }

    printf("Received ack...\n");

cleanup:
    free(data);


    return exit_out;
}
