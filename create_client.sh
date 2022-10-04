#!/bin/bash

rm -rf "$1"
mkdir "$1"

subDirs=(bin cert private ca)

for subdir in ${subDirs[@]}
do
	mkdir "$1"/$subdir
done

cp getcert "$1"/bin/
cp sendmsg "$1"/bin/
cp recvmsg "$1"/bin/
cp ca/intermediate/server/certs/ca-chain.cert.pem "$1"/ca/

exit
