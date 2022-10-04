#!/bin/bash

getcert_should_return_cert_when_username_and_password_are_correct () {
	./create_client.sh addleness-tree
	cd addleness-tree
	OUTPUT=$(./bin/getcert 172.17.0.1 -i addleness -p Cardin_pwns)

	SUBSTRING="HTTP/1.1 200 OK"

	if [[ "${OUTPUT}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree
}

getcert_should_return_error_when_username_is_incorrect () { 
	./create_client.sh addleness-tree
	cd addleness-tree
	OUTPUT=$(./bin/getcert 172.17.0.1 -i wrong_name -p Cardin_pwns)

	SUBSTRING="HTTP/1.1 400 Bad Request"

	if [[ "${OUTPUT}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree
}

getcert_should_return_error_when_password_is_incorrect () { 
	./create_client.sh addleness-tree
	cd addleness-tree
	OUTPUT=$(./bin/getcert 172.17.0.1 -i addleness -p wrong_pwd)

	SUBSTRING="HTTP/1.1 400 Bad Request"

	if [[ "${OUTPUT}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree
}

test1=$(getcert_should_return_cert_when_username_and_password_are_correct)
test2=$(getcert_should_return_error_when_username_is_incorrect)
test3=$(getcert_should_return_error_when_password_is_incorrect)

echo "Test summary for getcert component:"
echo "Test 1 -" $test1
echo "Test 2 -" $test2
echo "Test 3 -" $test3
