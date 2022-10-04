#!/bin/bash

make getcert sendmsg recvmsg >/dev/null

echo
./tests/getcert_test.sh

echo
./tests/sendmsg_recmsg_test.sh
