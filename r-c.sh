#!/bin/bash

gcc ./client.c ./client-sockets.c ./shared.c -o bin/client -l gssapi_krb5 && ./bin/client ; echo $?
