#!/bin/bash

rm -rf server_tree
mkdir server_tree

subDirs=(bin mail certs private ca)

for subdir in ${subDirs[@]}
do
	mkdir server_tree/$subdir
done

cp server server_tree/bin/

cp user_hash.txt server_tree/private/user_pw.txt
cp ca/intermediate/certs/server.cert.pem server_tree/certs/
cp ca/intermediate/private/server.key.pem server_tree/private/
cp ca/intermediate/server/certs/ca-chain.cert.pem server_tree/ca/

exit