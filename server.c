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
#include "server-sockets.h"

int
main()
{
    int srv_socket;
    int client_socket;
    int call_val = 0;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_cred_id_t server_creds;

    char *data = malloc(sizeof(char) * 1024 * 32);

    srv_socket = setup_server();
    if (srv_socket < 0) {
        fprintf(stderr, "Error setting up server. Exiting!\n");
        goto cleanup;
    }

    call_val = do_acquire_creds(&server_creds, GSS_C_ACCEPT);
    if (call_val != 0) {
        fprintf(stderr, "Error acquiring server creds. Exiting!\n");
        goto cleanup;
    }

    call_val = do_print_cred_name(server_creds);
    if (call_val != 0) {
        fprintf(stderr, "Error printing server cred name. Exiting!\n");
        goto cleanup;
    }

    while (1) {
        client_socket = accept(srv_socket, (struct sockaddr *)NULL, NULL);
        if (client_socket == -1) {
            printf("Error: accepting socket error (%d:%s).", errno, strerror(errno));
            return 5;
        }
        printf("Successfully accepted client:\n");

        call_val = server_client_handshake(client_socket);
        if (call_val != 0) {
            goto cleanup;
        }

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
