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
#include "shared.h"

int
main()
{
    int client_socket;
    char *data = malloc(sizeof(char) * 1024 * 32);
    int call_val = 0;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_cred_id_t creds;
    gss_name_t cred_name;
    gss_buffer_desc exported_name;

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

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_INITIATE, &creds, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 6;
    }

    maj_stat = gss_inquire_cred(&min_stat, creds, &cred_name,
                                NULL, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 6;
    }

    maj_stat = gss_display_name(&min_stat, cred_name, &exported_name, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 6;
    }

    printf("Name (%d): %s\n", exported_name.length, exported_name.value);

    int context_established = 0;
    gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    OM_uint32 flags_rec;

    gss_buffer_desc server_canonical_name;
    gss_name_t server_name;
    server_canonical_name.value = "TEST/kdc.cipherboy.com@CIPHERBOY.COM";
    server_canonical_name.length = 36;

    maj_stat = gss_import_name(&min_stat, &server_canonical_name,
                               GSS_C_NO_OID, &server_name);

    if (GSS_CALLING_ERROR(maj_stat)) {
        printf("GSS (name)_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        return 5;
    }

    while (!context_established) {
        maj_stat = gss_init_sec_context(&min_stat,
                                        creds,
                                        &ctx_handle,
                                        server_name,
                                        GSS_C_NO_OID,
                                        0, 0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token, NULL,
                                        &output_token, &flags_rec, NULL);

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
            if (GSS_ERROR(maj_stat)) {
                printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
                print_error(maj_stat, min_stat);
                return 17;
            }
        }

        if (maj_stat & GSS_S_CONTINUE_NEEDED) {
            receive_token_from_peer(&input_token, client_socket);
            printf("Received token (%d) from peer.\n", input_token.length);
        } else {
            context_established = 1;
        }
    }

    if (!context_established) {
        return 8;
    }
    printf("Context established on client!\n");

cleanup:
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

    maj_stat = gss_release_buffer(&min_stat, &exported_name);
    maj_stat = gss_release_buffer(&min_stat, &output_token);
    maj_stat = gss_release_name(&min_stat, &cred_name);
    maj_stat = gss_release_name(&min_stat, &server_name);
    maj_stat = gss_release_cred(&min_stat, &creds);

    free(data);
    close(client_socket);
}
