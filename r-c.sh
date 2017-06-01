#!/bin/bash

gcc -pedantic -std=c99 -Wall -Werror -Wextra -fdiagnostics-color=always ./client.c ./client-sockets.c ./client-kerberos.c ./shared.c -o bin/client -l gssapi_krb5 && ./bin/client ; echo $?
