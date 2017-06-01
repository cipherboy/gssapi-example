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
#include "server-kerberos.h"

int
be_echo_server(gss_ctx_id_t ctx_handle, int client_socket)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    int exit_out = 0;

    gss_buffer_desc input_msg = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_msg = GSS_C_EMPTY_BUFFER;

    while (1) {
        maj_stat = gss_release_buffer(&min_stat, &input_msg);
        maj_stat = gss_release_buffer(&min_stat, &output_msg);

        receive_token_from_peer(&input_msg, client_socket);

        if (input_msg.length == 0) {
            goto cleanup;
        }

        maj_stat = gss_unwrap(&min_stat, ctx_handle, &input_msg, &output_msg,
                              NULL, NULL);

        if (GSS_ERROR(maj_stat)) {
            print_error(maj_stat, min_stat);
            exit_out = 1;
            goto cleanup;
        }

        printf("r: %.*s\n", (int)output_msg.length, (char *)output_msg.value);
    }

cleanup:
    maj_stat = gss_release_buffer(&min_stat, &input_msg);
    maj_stat = gss_release_buffer(&min_stat, &output_msg);

    return exit_out;
}

int
main()
{
    int srv_socket;
    int client_socket;
    int call_val = 0;

    OM_uint32 min_stat;
    gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;

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
            printf("Error: accepting socket error (%d:%s).", errno,
                   strerror(errno));
            goto cleanup;
        }
        printf("Successfully accepted client:\n");

        call_val = server_client_handshake(client_socket);
        if (call_val != 0) {
            goto cleanup;
        }

        printf("Beginning GSSAPI transmissions with client.\n");

        call_val = do_establish_server_context(&ctx_handle, server_creds,
                                               client_socket);
        if (call_val != 0) {
            goto cleanup;
        }

        printf("Context established on server!\n");
        call_val = do_print_context_names(ctx_handle);
        if (call_val != 0) {
            goto cleanup;
        }

        printf("Beginning life as an echo server...\n");
        be_echo_server(ctx_handle, client_socket);

        printf("Cleaning up!\n");
        do_cleanup_context(&ctx_handle, client_socket);

        close(client_socket);

        break;
    }

cleanup:
    gss_release_cred(&min_stat, &server_creds);

    close(srv_socket);

    return 0;
}
