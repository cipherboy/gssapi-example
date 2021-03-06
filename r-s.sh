#!/bin/bash

gcc -pedantic -Og -ggdb -std=c99 -Wall -Werror -Wextra -fdiagnostics-color=always ./server.c  ./server-sockets.c ./server-kerberos.c ./shared.c -o bin/server -l gssapi_krb5 && ./bin/server ; echo $?
