#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "client-sockets.h"
#include "client-kerberos.h"
#include "shared.h"

/* https://github.com/cipherboy/krb5/blob/master/src/lib/gssapi/spnego/gssapiP_spnego.h#L91 */
/* Structure for context handle */
typedef struct {
	OM_uint32	magic_num;
	gss_buffer_desc DER_mechTypes;
	gss_OID_set mech_set;
	gss_OID internal_mech;  /* alias into mech_set->elements */
	gss_ctx_id_t ctx_handle;
	int mic_reqd;
	int mic_sent;
	int mic_rcvd;
	int firstpass;
	int mech_complete;
	int nego_done;
	int initiate;
	int opened;
	OM_uint32 ctx_flags;
	gss_name_t internal_name;
	gss_OID actual_mech;
} spnego_gss_ctx_id_rec, *spnego_gss_ctx_id_t;

int
setup_spnego_context(gss_ctx_id_t *context_handle)
{
    spnego_gss_ctx_id_rec *ctx;

    ctx = malloc(sizeof(spnego_gss_ctx_id_rec));
    if (ctx == NULL) {
        return 1;
    }

    memset(ctx, 0, sizeof(spnego_gss_ctx_id_rec));

    ctx->magic_num = 0x00000fed;
	ctx->ctx_handle = GSS_C_NO_CONTEXT;
	ctx->mech_set = NULL;
	ctx->internal_mech = NULL;
	ctx->DER_mechTypes.length = 0;
	ctx->DER_mechTypes.value = NULL;
	ctx->mic_reqd = 0;
	ctx->mic_sent = 0;
	ctx->mic_rcvd = 0;
	ctx->mech_complete = 0;
	ctx->nego_done = 0;
	ctx->opened = 0;
	ctx->initiate = GSS_C_INITIATE;
	ctx->internal_name = GSS_C_NO_NAME;
	ctx->actual_mech = GSS_C_NO_OID;

    *context_handle = (gss_ctx_id_t) ctx;
    return 0;
}

int
main()
{
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
    int call_val;
    int client_socket;
    OM_uint32 min_stat;

    call_val = setup_spnego_context(&ctx_handle);
    if (call_val != 0) {
        return 1;
    }


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


cleanup:

    do_cleanup_context(&ctx_handle, client_socket);
    gss_release_cred(&min_stat, &creds);

    close(client_socket);
}
