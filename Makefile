CC  = g++
CXX = g++ -O0 

INCLUDES = 

CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES) -std=c++11

LDFLAGS  = 
LDLIBS  = -lssl -lcrypto -lcrypt

executables = server client getcert sendmsg recvmsg
objects = server.o client.o getcert.o sendmsg.o recvmsg.o

.PHONY: default
default: server_tree client_tree


.PHONY: install
install: server getcert sendmsg recvmsg
	sudo apt-get install libssl-dev
	sudo apt update
	sudo apt install snapd
	sudo snap install docker
	getent group docker || sudo groupadd docker
	sudo usermod -aG docker $(USER)
	newgrp docker

build:
	yes | docker system prune -a
	docker build -t server_tree .

test:
	chmod -R 777 ./tests/ create_client.sh
	./tests/run_tests.sh

server_tree: server
	bash create_server.sh

client_tree: getcert sendmsg recvmsg
	bash create_client.sh $(TREE)

server: server.o

getcert: client.o getcert.o

sendmsg: client.o sendmsg.o

recvmsg: client.o recvmsg.o

getcert.o:

sendmsg.o:

recvmsg.o:

server.o: server.h mail.h

client.o: client.h

.PHONY: clean
clean:
	rm -rf *~ a.out core $(objects) $(executables)
	rm -rf client_tree server_tree

.PHONY: all
all: clean default
