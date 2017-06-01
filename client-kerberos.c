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
#include "client-kerberos.h"

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

    gss_name_t server_name = GSS_C_NO_NAME;

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
                                        &output_token, NULL, NULL);

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
    maj_stat = gss_release_name(&min_stat, &server_name);

    return exit_out;
}
