/*
 * getcert.cpp
*/

#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <atomic>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "client.h"

void got_signal(int)
{
    printf("\nClean exit!\n");
}

int main (int argc, char **argv) {

    if(argc < 2){
        printf("Invalid usage\n");
        return 1;
    }

    struct sigaction sa;
    memset( &sa, 0, sizeof(sa) );
    sa.sa_handler = got_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGABRT,&sa,NULL);

    std::string hostname = argv[1];
    int port = 443;
    std::string caFile = "ca/ca-chain.cert.pem";

    std::string cert = "cert/client.cert.pem";
    std::string pvtKey = "private/private.key.pem";

    Client client(hostname, port, caFile, false, cert , pvtKey);

    if(!client.initializeCTX()){
        client.print_errors_and_abort("Error initializing CTX");
    }

    //STRICTLY FOR TESTING

    char *identity = NULL;
    if(argc >= 4 && std::string(argv[2]) == "-i"){
        identity = argv[3];
    }

    char *password = NULL;
    if(argc >= 6 && std::string(argv[4]) == "-p"){
        password = argv[5];
    }


    if(!client.loadCert(password, identity)){
        client.print_errors_and_abort("Error loading certificate");
    }

    std::string req = "POST cert HTTP/1.0";
    std::string body = client.load_publickey();

    std::string response = client.run(req, body, NULL);
    if(response == "Fail"){
        client.print_errors_and_abort("Error Getting response");
    }

    std::string copy = std::string(response.c_str(), strstr(response.c_str(), "\r\n"));

    std::strtok(&copy[0], " ");
    std::string statuscode = std::strtok(NULL, " ");
    if(statuscode == "200"){

        std::string body = std::string(strstr(response.c_str(), "\r\n\r\n") + 4);

        if(!client.saveCert(body)){
            client.print_errors_and_abort("Error saving certificate");
        }
    }


    std::cout << response << std::endl;

}

