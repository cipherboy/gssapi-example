#!/bin/bash

gcc ./server.c ./shared.c -o bin/server -l gssapi_krb5 ; ./bin/server ; echo $?
