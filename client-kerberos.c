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
do_acquire_creds(gss_cred_id_t *creds) {
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_INITIATE, creds, NULL, NULL);

    if (GSS_ERROR(maj_stat)) {
        print_error(maj_stat, min_stat);
        return 1;
    }

    return 0;
}

int
do_print_cred_name(gss_cred_id_t creds) {
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_name_t cred_name = GSS_C_NO_NAME;
    gss_buffer_desc exported_name = GSS_C_EMPTY_BUFFER;
    int exit_out = 0;

    maj_stat = gss_inquire_cred(&min_stat, creds, &cred_name,
                                NULL, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        exit_out = 1;
        goto cleanup;
    }

    maj_stat = gss_display_name(&min_stat, cred_name, &exported_name, NULL);
    if (GSS_ERROR(maj_stat)) {
        printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
        print_error(maj_stat, min_stat);
        exit_out = 2;
        goto cleanup;
    }

    printf("Name (%zu): %s\n",
           exported_name.length, (char *)exported_name.value);

cleanup:
    maj_stat = gss_release_buffer(&min_stat, &exported_name);

    if (cred_name != GSS_C_NO_NAME) {
        maj_stat = gss_release_name(&min_stat, &cred_name);
    }

    return exit_out;
}

int
do_get_server_name(gss_name_t *server_name)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    gss_buffer_desc server_buff_name;
    server_buff_name.value = "TEST/kdc.cipherboy.com@CIPHERBOY.COM";
    server_buff_name.length = 36;

    maj_stat = gss_import_name(&min_stat, &server_buff_name,
                               GSS_C_NO_OID, server_name);

    if (GSS_CALLING_ERROR(maj_stat)) {
        print_error(maj_stat, min_stat);
        return 1;
    }

    return 0;
}

int
do_establish_context(gss_ctx_id_t *ctx_handle, gss_cred_id_t creds,
                     int client_socket)
{
    int context_established = 0;
    int call_value = 0;
    int exit_out = 0;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    OM_uint32 flags_rec;
    gss_name_t server_name;

    call_value = do_get_server_name(&server_name);
    if (call_value != 0) {
        return 1;
    }

    /* Per https://tools.ietf.org/html/rfc2744.html#section-5.19 */
    while (!context_established) {
        maj_stat = gss_init_sec_context(&min_stat,
                                        creds,
                                        ctx_handle,
                                        server_name,
                                        GSS_C_NO_OID,
                                        0, 0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token, NULL,
                                        &output_token, &flags_rec, NULL);

        if (GSS_ERROR(maj_stat)) {
            print_error(maj_stat, min_stat);
            exit_out = 2;
            goto cleanup;
        }

        if (output_token.length != 0) {
            if (send_token_to_peer(&output_token, client_socket) != 0) {
                exit_out = 3;
                goto cleanup;
            }

            gss_release_buffer(&min_stat, &output_token);
        }

        if (maj_stat & GSS_S_CONTINUE_NEEDED) {
            if (receive_token_from_peer(&input_token, client_socket) != 0) {
                exit_out = 4;
                goto cleanup;
            }
        } else {
            context_established = 1;
        }
    }

cleanup:
    maj_stat = gss_release_buffer(&min_stat, &output_token);

    return exit_out;
}

void
do_cleanup_context(gss_ctx_id_t *ctx_handle, int client_socket)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    if (*ctx_handle != GSS_C_NO_CONTEXT) {
        maj_stat = gss_delete_sec_context(&min_stat, ctx_handle,
                                          &output_token);

        if (GSS_ERROR(maj_stat)) {
            printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
            print_error(maj_stat, min_stat);
            return;
        }

        if (output_token.length != 0) {
            if (send_token_to_peer(&output_token, client_socket) != 0) {
                return;
            }
        }
    }
}
