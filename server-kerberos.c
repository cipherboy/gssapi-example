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
