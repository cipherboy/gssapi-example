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

    gss_channel_bindings_t cb = GSS_C_NO_CHANNEL_BINDINGS;

    char *ip = "192.168.122.48";
    char *app_data = "magic";

    call_value = do_get_server_name(&server_name);
    if (call_value != 0) {
        return 1;
    }

    cb = calloc(sizeof(struct gss_channel_bindings_struct), 1);

    cb->initiator_addrtype = GSS_C_AF_NULLADDR;
    cb->initiator_address.length = 0;
    cb->acceptor_addrtype= GSS_C_AF_INET;
    cb->acceptor_address.length = strlen(ip);
    cb->acceptor_address.value = ip;
    cb->application_data.length = strlen(app_data);
    cb->application_data.value = app_data;

    /* Per https://tools.ietf.org/html/rfc2744.html#section-5.19 */
    while (!context_established) {
        maj_stat = gss_init_sec_context(&min_stat,
                                        creds,
                                        ctx_handle,
                                        server_name,
                                        GSS_C_NO_OID,
                                        GSS_C_MUTUAL_FLAG, 0,
                                        cb,
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


/* https://github.com/krb5/krb5/blob/master/src/tests/gssapi/common.c */
void
display_oid(const char *tag, gss_OID oid)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_oid_to_str(&minor, oid, &buf);
    if (GSS_ERROR(major)) {
        print_error(major, minor);
        return;
    }

    if (tag != NULL)
        printf("%s:\t", tag);
    printf("%.*s\n", (int)buf.length, (char *)buf.value);
    (void)gss_release_buffer(&minor, &buf);
}

int
do_print_mechs()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID_set mech_set;
    size_t pos = 0;
    gss_OID mech;

    maj_stat = gss_indicate_mechs(&min_stat, &mech_set);
    if (GSS_ERROR(maj_stat)) {
        print_error(maj_stat, min_stat);
        return 1;
    }

    printf("Printing Available Mechanisms (%zu):\n", mech_set->count);
    for (pos = 0; pos < mech_set->count; pos++) {
        mech = mech_set->elements + pos;
        display_oid("", mech);
    }
    printf("\n");

    gss_release_oid_set(&min_stat, &mech_set);
    return 0;
}
