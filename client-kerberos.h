#ifndef __CLIENT_KERBEROS_H__
#define __CLIENT_KERBEROS_H__

int do_get_server_name(gss_name_t *server_name);

int do_establish_context(gss_ctx_id_t *ctx_handle, gss_cred_id_t creds,
                         int client_socket);


#endif
