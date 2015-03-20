#!/bin/sh

gcc -c -Wall awsrequest.c

gcc -o awstest -Wall -ljson-c -lcurl -lapr-1 -laprutil-1 -lcrypto awstest.c awsrequest.o
