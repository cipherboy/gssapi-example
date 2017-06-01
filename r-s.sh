#!/bin/bash

gcc -pedantic -std=c99 -Wall -Werror -Wextra -fdiagnostics-color=always ./server.c ./shared.c -o bin/server -l gssapi_krb5 ; ./bin/server ; echo $?
