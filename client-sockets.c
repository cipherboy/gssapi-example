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

#include "client-sockets.h"

int
setup_client()
{
    int enable = 1;
    int call_val = 0;
    int client_socket_out = 0;
    struct sockaddr_in srv_addr;

    client_socket_out = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket_out == -1) {
        printf("Error: socket connection error.\n");
        return -1;
    }

    setsockopt(client_socket_out, IPPROTO_TCP,
               TCP_NODELAY, &enable, sizeof(int));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(2025);

    call_val = inet_pton(AF_INET, "192.168.122.49", &srv_addr.sin_addr);
    if (call_val == 0) {
        printf("Error: invalid address.\n");
        return -2;
    }

    call_val = connect(client_socket_out, (struct sockaddr *)&srv_addr,
                      sizeof(srv_addr));
    if (call_val == -1) {
        printf("Error: binding to socket (%d:%s).\n", errno, strerror(errno));
        return -3;
    }

    return client_socket_out;
}

int
client_handshake(int client_socket)
{
    char *data = NULL;
    ssize_t rw_length = 0;
    int exit_out = 0;

    rw_length = write(client_socket, "auth\0", 5);
    if (rw_length < 0) {
        printf("Error: writing to socket (%d:%s).\n", errno, strerror(errno));
        exit_out = 1;
        goto cleanup;
    }

    printf("Sent auth...\n");

    data = malloc(sizeof(char) * 1024 * 32);

    rw_length = read(client_socket, data, 1024 * 32);
    if (rw_length < 0 || rw_length < 3) {
        printf("Error reading from socket or invalid data.\n");
        exit_out = 2;
        goto cleanup;
    }

    if (strncmp(data, "ack", 3) != 0) {
        printf("Error: reading from socket (%d:%s).\n",
               errno, strerror(errno));
       exit_out = 3;
       goto cleanup;
    }

    printf("Received ack...\n");

cleanup:
    if (data != NULL) {
        free(data);
    }

    return exit_out;
}
