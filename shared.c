#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

        return 1;
    }

    printf("Read %ld bytes.\n", rw_length);
    token->length = rw_length;

    return 0;
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
