#!/bin/bash

user_should_be_able_to_send_message () { 
	./create_client.sh addleness-tree
	./create_client.sh analects-tree
	cd addleness-tree
	./bin/getcert 172.17.0.1 -i addleness -p Cardin_pwns >/dev/null
	cd ../analects-tree
	./bin/getcert 172.17.0.1 -i analects -p pickerel_symbiosis >/dev/null
	cd ../addleness-tree

	SEND_MSG_OUTPUT=$(./bin/sendmsg 172.17.0.1 -p Cardin_pwns analects <<< Hello!!!)

	SUBSTRING="HTTP/1.1 200 OK"

	if [[ "${SEND_MSG_OUTPUT}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree analects-tree
}

user_should_be_able_to_receive_message () {
	./create_client.sh annalistic-tree
	./create_client.sh corector-tree
	cd annalistic-tree
	./bin/getcert 172.17.0.1 -i annalistic -p thickets_pimping >/dev/null
	cd ../corector-tree
	./bin/getcert 172.17.0.1 -i corector -p quadruplet_strawed >/dev/null
	cd ../annalistic-tree

	./bin/sendmsg 172.17.0.1 -p thickets_pimping corector <<< Hello >/dev/null
	cd ../corector-tree
	RECIEVED_MSG=$(./bin/recvmsg 172.17.0.1 -p quadruplet_strawed)

	SUBSTRING="Hello"

	if [[ "${RECIEVED_MSG}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf annalistic-tree corector-tree
}

message_should_be_deleted_from_server_after_receiving () {
	./create_client.sh whaledom-tree
	./create_client.sh wamara-tree
	cd whaledom-tree
	./bin/getcert 172.17.0.1 -i whaledom -p "petering_sounding's" >/dev/null
	cd ../wamara-tree
	./bin/getcert 172.17.0.1 -i wamara -p "stirrer_hewer's" >/dev/null
	cd ../whaledom-tree

	./bin/sendmsg 172.17.0.1 -p "petering_sounding's" wamara <<< Hello >/dev/null
	cd ../wamara-tree
	RECIEVED_MSG_1=$(./bin/recvmsg 172.17.0.1 -p "stirrer_hewer's")
	RECIEVED_MSG_2=$(./bin/recvmsg 172.17.0.1 -p "stirrer_hewer's")

	SUBSTRING=""

	if [[ "${RECIEVED_MSG_2}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf whaledom-tree wamara-tree
}

user_should_be_able_to_send_message_to_multiple_recipients () {
	./create_client.sh addleness-tree
	./create_client.sh analects-tree
	./create_client.sh durwaun-tree
	cd addleness-tree
	./bin/getcert 172.17.0.1 -i addleness -p Cardin_pwns >/dev/null
	cd ../analects-tree
	./bin/getcert 172.17.0.1 -i analects -p pickerel_symbiosis >/dev/null
	cd ../durwaun-tree
	./bin/getcert 172.17.0.1 -i durwaun -p hamlet_laudably >/dev/null
	cd ../addleness-tree

	SEND_MSG_OUTPUT=$(./bin/sendmsg 172.17.0.1 -p Cardin_pwns analects durwaun <<< Hello!!!)

	SUBSTRING="HTTP/1.1 200 OK"

	if [[ "${SEND_MSG_OUTPUT}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree analects-tree durwaun-tree
}

multiple_users_should_receive_message () {
	./create_client.sh exilic-tree
	./create_client.sh unrosed-tree
	./create_client.sh gorbellied-tree
	cd exilic-tree
	./bin/getcert 172.17.0.1 -i exilic -p service_barbing >/dev/null
	cd ../unrosed-tree
	./bin/getcert 172.17.0.1 -i unrosed -p shamed_Dow >/dev/null
	cd ../gorbellied-tree
	./bin/getcert 172.17.0.1 -i gorbellied -p "pinfeathers_Finnbogadottir's" >/dev/null
	cd ../exilic-tree

	./bin/sendmsg 172.17.0.1 -p service_barbing unrosed gorbellied <<< Hello >/dev/null

	cd ../unrosed-tree
	RECIEVED_MSG_1=$(./bin/recvmsg 172.17.0.1 -p shamed_Dow)

	cd ../gorbellied-tree
	RECIEVED_MSG_2=$(./bin/recvmsg 172.17.0.1 -p "pinfeathers_Finnbogadottir's")

	SUBSTRING="Hello"

	if [[ "${RECIEVED_MSG_1}" == *"$SUBSTRING"* ]] && [[ "${RECIEVED_MSG_2}" == *"$SUBSTRING"* ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf exilic-tree unrosed-tree gorbellied-tree
}

user_should_not_be_able_to_send_message_when_password_is_incorrect () { 
	./create_client.sh addleness-tree
	./create_client.sh analects-tree
	cd addleness-tree
	./bin/getcert 172.17.0.1 -i addleness -p Cardin_pwns >/dev/null
	cd ../analects-tree
	./bin/getcert 172.17.0.1 -i analects -p pickerel_symbiosis >/dev/null
	cd ../addleness-tree

	./bin/sendmsg 172.17.0.1 -p wrong-pwd analects <<< Hello!!! &> /dev/null

	ERROR_CODE=$?

	if [[ ${ERROR_CODE} == 134 ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf addleness-tree analects-tree
}

user_should_not_be_able_to_receive_message_when_password_is_incorrect () { 
	./create_client.sh annalistic-tree
	./create_client.sh corector-tree
	cd annalistic-tree
	./bin/getcert 172.17.0.1 -i annalistic -p thickets_pimping >/dev/null
	cd ../corector-tree
	./bin/getcert 172.17.0.1 -i corector -p quadruplet_strawed >/dev/null
	cd ../annalistic-tree

	./bin/sendmsg 172.17.0.1 -p thickets_pimping corector <<< Hello >/dev/null

	cd ../corector-tree
	./bin/recvmsg 172.17.0.1 -p wrong-pwd &> /dev/null

	ERROR_CODE=$?

	if [[ ${ERROR_CODE} == 134 ]]
	then
		echo "pass"
	else
		echo "fail"
	fi

	cd ..
	rm -rf annalistic-tree corector-tree
}


test1=$(user_should_be_able_to_send_message)
test2=$(user_should_be_able_to_receive_message)
test3=$(message_should_be_deleted_from_server_after_receiving)
test4=$(user_should_be_able_to_send_message_to_multiple_recipients)
test5=$(multiple_users_should_receive_message)
test6=$(user_should_not_be_able_to_send_message_when_password_is_incorrect)
test7=$(user_should_not_be_able_to_receive_message_when_password_is_incorrect)


echo "Test summary for sendmsg / recmsg components:"
echo "Test 1 -" $test1
echo "Test 2 -" $test2
echo "Test 3 -" $test3
echo "Test 4 -" $test4
echo "Test 5 -" $test5
echo "Test 6 -" $test6
echo "Test 7 -" $test7
