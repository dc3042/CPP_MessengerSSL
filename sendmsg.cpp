/*
 * sendmsg.cpp
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

    Client client(hostname, port, caFile, true, cert , pvtKey);

    if(!client.initializeCTX()){
        client.print_errors_and_abort("Error initializing CTX");
    }

    //STRICTLY FOR TESTING

    char *password = NULL;
    if(argc >= 4 && std::string(argv[2]) == "-p"){
        password = argv[3];
    }

    if(!client.loadCert(password, NULL)){
        client.print_errors_and_abort("Error loading certificate");
    }

    std::string req = "GET cert HTTP/1.0";

    std::string body = "";
    
    int i;
    if(argc >= 4 && std::string(argv[2]) == "-p"){
        i = 4;
    }
    else{
        i = 2;
    }

    for(; i < argc; i++){

        body += argv[i];
        body += "\r\n";

    }

    std::string response = client.run(req, body, NULL);
    if(response == "Fail"){
        client.print_errors_and_abort("Error Getting response");
    }

    std::string copy = std::string(response.c_str(), strstr(response.c_str(), "\r\n"));


    std::strtok(&copy[0], " ");
    std::string statuscode = std::strtok(NULL, " ");
    if(statuscode == "200"){

        body = std::string(strstr(response.c_str(), "\r\n\r\n") + 4);

        BIO* bio;
        if(!(bio = BIO_new( BIO_s_mem()))){
            client.print_errors_and_abort("Error loading certificates");
        }

        if(BIO_write(bio, body.c_str(), body.size()) <= 0){
            BIO_free(bio);
            client.print_errors_and_abort("Error loading certificates");
        }

        STACK_OF(X509_INFO) *certstack;

        if(!(certstack = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL))){
            sk_X509_INFO_pop_free(certstack, X509_INFO_free);
            BIO_free(bio);
            client.print_errors_and_abort("Error loading certificates");
        }

        BIO_free(bio);

        std::istreambuf_iterator<char> start(std::cin);
        std::istreambuf_iterator<char> end;
        std::string message(start, end);

        std::string encrypted;
        std::string sign;

        for (int i = 0; i < sk_X509_INFO_num(certstack); i++) {

            try{
                X509_INFO *stack_item;
                if(!(stack_item = sk_X509_INFO_value(certstack, i))){
                    client.print_errors_and_throw("Error loading certificate item");
                }

                if(!(client.verifyCert(stack_item->x509))){
                    client.print_errors_and_throw("Invalid certificate");
                }

                encrypted = client.encode(message, stack_item->x509);
                sign = client.sign(encrypted);

                X509_NAME *certsubject = X509_get_subject_name(stack_item->x509);
                int rcpt_len = X509_NAME_get_text_by_NID(certsubject, NID_commonName, NULL, 256);

                if(rcpt_len == -1){
                    client.print_errors_and_throw("Error loading certificate item");
                }

                char *rcpt = (char *) malloc(rcpt_len + 1);

                if(!rcpt){
                    client.print_errors_and_throw("Error loading certificate item");
                }

                rcpt_len = X509_NAME_get_text_by_NID(certsubject, NID_commonName, rcpt, rcpt_len + 1);
                rcpt[rcpt_len] = 0;

                req = "POST mail/";
                req += rcpt;
                req += " HTTP/1.0";

                free(rcpt);

                char boundary_bytes[32];
                FILE *random = fopen("/dev/urandom", "rb");
                if(!random){
                    client.print_errors_and_throw("Error creating random boundary");
                }

                fread(boundary_bytes, 32, 1, random);
                fclose(random);

                for(int j = 0; j < 32; j++){
                    if(boundary_bytes[j] == '\n' || boundary_bytes[j] == 0 || boundary_bytes[j] == '\r'){
                        boundary_bytes[j] = 'a';
                    }
                }

                std::string boundary = "-------boundary" + std::string(boundary_bytes, 32);


                body = encrypted + boundary + sign;

                response = client.run(req, body, boundary_bytes);
                if(response == "Fail"){
                    client.print_errors_and_throw("Error Getting response");
                }
                std::cout << response << std::endl;

            }

            catch (const std::exception& ex){
                printf("Worker exited with exception:\n%s\n", ex.what());
            }
        }

        sk_X509_INFO_pop_free(certstack, X509_INFO_free);
    }

}

