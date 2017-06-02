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

#include "shared.h"

int
setup_krb5_context(gss_ctx_id_t *context_handle)
{
    krb5_gss_ctx_id_rec *ctx;
    ctx = malloc(sizeof(krb5_gss_ctx_id_rec));
    if (ctx == NULL) {
        return 1;
    }

    /* Fill in context: https://github.com/cipherboy/krb5/blob/master/src/lib/gssapi/krb5/init_sec_context.c#L539 */
    memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
    ctx->magic = KG_CONTEXT;

    ctx->auth_context = (krb5_auth_context)calloc(1, sizeof(struct _krb5_auth_context));
    if (ctx->auth_context == NULL) {
        return 2;
    }

    /* krb5_auth_con_init: https://github.com/cipherboy/krb5/blob/master/src/lib/krb5/krb/auth_con.c#L32 */
    (*ctx->auth_context)->auth_context_flags =
        KRB5_AUTH_CONTEXT_DO_TIME |  KRB5_AUTH_CONN_INITIALIZED;

    (*ctx->auth_context)->checksum_func = NULL;
    (*ctx->auth_context)->checksum_func_data = NULL;
    (*ctx->auth_context)->negotiated_etype = ENCTYPE_NULL;
    (*ctx->auth_context)->magic = KV5M_AUTH_CONTEXT;

    /* https://github.com/cipherboy/krb5/blob/master/src/lib/gssapi/krb5/init_sec_context.c#L556 */
    ctx->initiate = 1;
    ctx->seed_init = 0;
    ctx->seqstate = 0;

    ctx->gss_flags = (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                                  GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
                                  GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG |
                                  GSS_C_DCE_STYLE | GSS_C_IDENTIFY_FLAG |
                                  GSS_C_EXTENDED_ERROR_FLAG | GSS_C_TRANS_FLAG);

    ctx->krb_times.endtime = 0;

    // Magic nulls? :)
    ctx->here = NULL;
    ctx->there = NULL;
    ctx->subkey = NULL;
    ctx->auth_context = NULL;

    ctx->enc = NULL;
    ctx->seq = NULL;
    ctx->have_acceptor_subkey = 0;

    // Return it!
    *context_handle = (gss_ctx_id_t) ctx;
    return 0;
}


int
main()
{
    gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
    int call_val;

    call_val = setup_krb5_context(&ctx_handle);
    if (call_val != 0) {
        return 1;
    }
}
