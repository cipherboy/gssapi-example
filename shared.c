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
send_token_to_peer(gss_buffer_desc *token, int peer)
{
    ssize_t rw_length = 0;
    rw_length = write(peer, token->value, token->length);

    if (rw_length < 0) {
        printf("Error: writing to socket (%d:%s).\n",
               errno, strerror(errno));

        return 1;
    }

    printf("Sent %ld bytes.\n", rw_length);

    return 0;
}

int
receive_token_from_peer(gss_buffer_desc *token, int peer)
{
    ssize_t rw_length;

    token->length = 0;
    token->value = malloc(sizeof(char *) * 1024 * 32);
    rw_length = read(peer, token->value, 1024 * 32);

    if (rw_length < 0) {
        printf("Error: reading from socket (%d:%s).\n",
               errno, strerror(errno));

        free(token->value);
        token->value = NULL;
        return 1;
    } else if (rw_length == 0) {
        free(token->value);
        token->value = NULL;
    }

    printf("Read %ld bytes.\n", rw_length);
    token->length = rw_length;

    return 0;
}

int
do_acquire_creds(gss_cred_id_t *creds, gss_cred_usage_t usage) {
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                usage, creds, NULL, NULL);

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

void
print_error_int(char *prefix, int status_type, OM_uint32 status_value)
{
    OM_uint32 message_context;
    OM_uint32 maj_status;
    OM_uint32 min_status;
    gss_buffer_desc status_string;

    message_context = 0;
    do {
        maj_status = gss_display_status(&min_status, status_value,
                                        status_type, GSS_C_NO_OID,
                                        &message_context, &status_string);

        if (GSS_ERROR(maj_status)) {
            gss_release_buffer(&min_status, &status_string);
            return;
        }

        fprintf(stderr, "%s%.*s\n",
                prefix,
                (int)status_string.length,
                (char *)status_string.value);

        gss_release_buffer(&min_status, &status_string);
    } while (message_context != 0);
}

void print_error(OM_uint32 major, OM_uint32 minor)
{
    fprintf(stderr, "[GSS_ERROR: %u:%u]\n", major, minor);
    print_error_int("\tMajor: ", GSS_C_GSS_CODE, major);
    print_error_int("\tMinor: ", GSS_C_MECH_CODE, minor);
}
