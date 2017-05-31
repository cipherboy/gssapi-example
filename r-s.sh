#!/bin/bash

clang-format -style="{UseTab: ForIndentation, IndentWidth: 8, ColumnLimit: 256}" ./*.c -i
gcc ./server.c -o bin/server -l gssapi_krb5 ; ./bin/server ; echo $?
