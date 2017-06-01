#ifndef __SHARED_H__
#define __SHARED_H__

int
send_token_to_peer(
                   gss_buffer_desc *token,
                   int peer
                  );

int
receive_token_from_peer(
                        gss_buffer_desc *token,
                        int peer
                       );

void
print_error(
            OM_uint32 major,
            OM_uint32 minor
           );

#endif
