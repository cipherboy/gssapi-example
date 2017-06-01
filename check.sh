#!/bin/bash

oclint ./*.c

for i in *.c; do
	echo $i
	python ../krb5/src/util/cstyle-file.py $i
done
