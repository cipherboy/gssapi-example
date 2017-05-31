#!/bin/bash

clang-format -style="{UseTab: ForIndentation, IndentWidth: 8, ColumnLimit: 256}" ./*.c -i
gcc ./client.c -o bin/client -l gssapi_krb5 && ./bin/client ; echo $?
