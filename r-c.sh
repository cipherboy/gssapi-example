#!/bin/bash

gcc -pedantic -Og -ggdb -std=c99 -Wall -Werror -Wextra -fdiagnostics-color=always ./client.c ./client-sockets.c ./client-kerberos.c ./shared.c -o bin/client -lgssapi_krb5 -lreadline && ./bin/client ; echo $?
