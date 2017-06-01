#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "client-sockets.h"
#include "client-kerberos.h"
#include "shared.h"

int
main()
{
    int client_socket;
    int call_val = 0;

    OM_uint32 min_stat;

    gss_cred_id_t creds;
    gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;

    client_socket = setup_client();
    if (client_socket < 0) {
        fprintf(stderr, "Error setting up client. Exiting!\n");
        goto cleanup;
    }

    call_val = client_handshake(client_socket);
    if (call_val != 0) {
        fprintf(stderr, "Error performing handshake. Exiting!\n");
        goto cleanup;
    }

    printf("Beginning GSSAPI transmissions.\n");

    /* Start by acquiring credentials from ccache */
    call_val = do_acquire_creds(&creds, GSS_C_INITIATE);
    if (call_val != 0) {
        fprintf(stderr, "Error getting creds. Exiting!\n");
        goto cleanup;
    }

    /* Display name of client user */
    call_val = do_print_cred_name(creds);
    if (call_val != 0) {
        fprintf(stderr, "Error getting creds. Exiting!\n");
        goto cleanup;
    }

    /* Establish context between client and server */
    call_val = do_establish_context(&ctx_handle, creds, client_socket);
    if (call_val != 0) {
        fprintf(stderr, "Error getting context. Exiting!\n");
        goto cleanup;
    }

    printf("Context established on client!\n");

cleanup:

    do_cleanup_context(&ctx_handle, client_socket);
    gss_release_cred(&min_stat, &creds);

    close(client_socket);
}
