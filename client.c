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

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>

int
be_echo_client(int client_socket, gss_ctx_id_t ctx_handle)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    char *message = NULL;
    int exit_out = 0;
    int conf_state = 0;
    int call_val = 0;

    gss_buffer_desc input_msg = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_msg = GSS_C_EMPTY_BUFFER;

    while (1) {
        free(message);
        maj_stat = gss_release_buffer(&min_stat, &input_msg);
        maj_stat = gss_release_buffer(&min_stat, &output_msg);

        message = NULL;

        message = readline("> ");
        if (message == NULL) {
            fprintf(stderr, "Error: return message from readline was NULL.\n");
            exit_out = 1;
            goto cleanup;
        }

        call_val = strncmp(message, "quit", 4);
        if (call_val == 0) {
            goto cleanup;
        }

        input_msg.length = strlen(message) + 1;
        input_msg.value = malloc(sizeof(char *) * input_msg.length);
        memcpy(input_msg.value, message, input_msg.length);

        maj_stat = gss_wrap(&min_stat, ctx_handle, 2025, GSS_C_QOP_DEFAULT,
                            &input_msg, &conf_state, &output_msg);

        if (GSS_ERROR(maj_stat)) {
            print_error(maj_stat, min_stat);
            exit_out = 2;
            goto cleanup;
        }

        if (conf_state == 0) {
            printf("Blast! No encryption allowed. Time to get out of here.\n");
            exit_out = 3;
            goto cleanup;
        }

        send_token_to_peer(&output_msg, client_socket);
    }

cleanup:
    free(message);
    maj_stat = gss_release_buffer(&min_stat, &input_msg);
    maj_stat = gss_release_buffer(&min_stat, &output_msg);

    return exit_out;
}

int
main()
{
    int client_socket;
    int call_val = 0;

    OM_uint32 min_stat;

    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
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

    printf("Beginning life as an echo client...\n");

    be_echo_client(client_socket, ctx_handle);

cleanup:

    do_cleanup_context(&ctx_handle, client_socket);
    gss_release_cred(&min_stat, &creds);

    close(client_socket);
}
