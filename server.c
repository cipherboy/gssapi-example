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
main()
{
    int srv_socket;
    int client_socket;
    int call_val = 0;

    OM_uint32 min_stat;
    gss_cred_id_t server_creds;
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

        do_cleanup_context(&ctx_handle, client_socket);

        close(client_socket);

        break;
    }

cleanup:
    gss_release_cred(&min_stat, &server_creds);

    close(srv_socket);

    return 0;
}
