#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shared.h"

int
main()
{
    int enable = 1;
    int srv_socket;
    int client_socket;
    ssize_t rw_length;
    struct sockaddr_in srv_addr;
    char *data = malloc(sizeof(char) * 1024 * 32);

    srv_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_socket == -1) {
        printf("Error: socket connection error.\n");
        return 1;
    }

    setsockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(2025);
    srv_addr.sin_addr.s_addr = htons(INADDR_ANY);

    if (bind(srv_socket, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1) {
        printf("Error: binding to socket (%d:%s).\n", errno, strerror(errno));
        return 3;
    }

    if (listen(srv_socket, 10) == -1) {
        printf("Error: listening to socket (%d:%s).\n", errno, strerror(errno));
        return 4;
    }

    printf("Successfully listening on 2025...\n");

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_cred_id_t server_creds;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 4;
    }

    gss_name_t srv_cred_name;
    maj_stat = gss_inquire_cred(&min_stat, server_creds, &srv_cred_name, NULL, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 5;
    }

    gss_buffer_desc srv_exported_name;
    maj_stat = gss_display_name(&min_stat, srv_cred_name, &srv_exported_name, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 5;
    }

    printf("Server Name (%d): %s\n", srv_exported_name.length, srv_exported_name.value);

    while (1) {
        client_socket = accept(srv_socket, (struct sockaddr *)NULL, NULL);
        if (client_socket == -1) {
            printf("Error: accepting socket error (%d:%s).", errno, strerror(errno));
            return 5;
        }
        printf("Successfully accepted client:\n");

        rw_length = read(client_socket, data, 1024 * 32);
        if (strncmp(data, "auth", 4) != 0) {
            printf("Didn't send auth...\n");
            continue;
        }

        printf("Got auth.\n");

        rw_length = write(client_socket, "ack\n", 4);
        if (rw_length != 4) {
            printf("Error: Unable to write all data to socket.\n");
            break;
        }

        printf("Wrote ack.\n");
        printf("Beginning GSSAPI transmissions.\n");

        gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;

        gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
        gss_name_t client_name;
        do {
            receive_token_from_peer(&input_token, client_socket);
            maj_stat = gss_accept_sec_context(&min_stat, &ctx_handle, server_creds, &input_token, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &output_token, NULL, NULL, NULL);
            if (GSS_ERROR(maj_stat)) {
                printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
                print_error(maj_stat, min_stat);
                return 6;
            }

            if (output_token.length != 0) {
                printf("Have to send token (%d) to peer.\n", output_token.length);
                if (send_token_to_peer(&output_token, client_socket) != 0) {
                    return 7;
                }
                maj_stat = gss_release_buffer(&min_stat, &output_token);
                output_token.length = 0;
            }
        } while (maj_stat & GSS_S_CONTINUE_NEEDED);

        if (ctx_handle == GSS_C_NO_CONTEXT) {
            printf("Still no context... but done?\n");
        }

        maj_stat = gss_release_buffer(&min_stat, &input_token);
        printf("Context established on server!\n");

        gss_name_t src_name;
        gss_name_t target_name;
        maj_stat = gss_inquire_context(&min_stat, ctx_handle, &src_name, &target_name, NULL, NULL, NULL, NULL, NULL);
        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return 9;
        }

        gss_buffer_desc exported_name;
        maj_stat = gss_display_name(&min_stat, src_name, &exported_name, NULL);
        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return 10;
        }

        printf("Source Name (%d): %s\n", exported_name.length, exported_name.value);

        maj_stat = gss_release_buffer(&min_stat, &exported_name);

        maj_stat = gss_display_name(&min_stat, target_name, &exported_name, NULL);
        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return 10;
        }

        printf("Target Name (%d): %s\n", exported_name.length, exported_name.value);

        maj_stat = gss_release_buffer(&min_stat, &exported_name);

        maj_stat = gss_release_name(&min_stat, &target_name);
        maj_stat = gss_release_name(&min_stat, &src_name);
        maj_stat = gss_release_name(&min_stat, &client_name);

        maj_stat = gss_delete_sec_context(&min_stat, &ctx_handle, &output_token);
        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return 15;
        }

        if (output_token.length != 0) {
            printf("Have to send token (%d) to peer.\n", output_token.length);
            if (send_token_to_peer(&output_token, client_socket) != 0) {
                return 16;
            }
        }

        maj_stat = gss_release_buffer(&min_stat, &output_token);
        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return 17;
        }

        break;
    }

    maj_stat = gss_release_name(&min_stat, &srv_cred_name);
    maj_stat = gss_release_buffer(&min_stat, &srv_exported_name);
    maj_stat = gss_release_cred(&min_stat, &server_creds);
    free(data);
    close(srv_socket);

    return 0;
}
