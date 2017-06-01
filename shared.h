#ifndef __SHARED_H__
#define __SHARED_H__

int send_token_to_peer(gss_buffer_desc *token, int peer);

int receive_token_from_peer(gss_buffer_desc *token, int peer);

int do_acquire_creds(gss_cred_id_t *creds, gss_cred_usage_t usage);

int do_print_cred_name(gss_cred_id_t creds);

void print_error(OM_uint32 major, OM_uint32 minor);

#endif
