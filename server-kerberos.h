#ifndef __SERVER_KERBEROS_H__
#define __SERVER_KERBEROS_H__

int do_establish_server_context(gss_ctx_id_t* ctx_handle,
                                gss_cred_id_t server_creds, int client_socket);

int do_print_context_names(gss_ctx_id_t ctx_handle);

#endif
