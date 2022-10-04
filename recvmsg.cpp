/*
 * recvmsg.cpp
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
#include "mail.h"
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

    std::string req = "GET mail HTTP/1.0";

    std::string body = "";
    
    std::string response = client.run(req, body, NULL);

    if(response == "Fail"){
        client.print_errors_and_abort("Error Getting response");
    }

    std::string copy = std::string(response.c_str(), strstr(response.c_str(), "\r\n"));

    std::strtok(&copy[0], " ");
    std::string statuscode = std::strtok(NULL, " ");

    if(statuscode == "200"){


    	std::string headers = std::string(response.c_str(), strstr(response.c_str(), "\r\n\r\n"));

    	std::string body = std::string(response, response.find("\r\n\r\n") + 4);



        std::string mail_str(body, 0, sizeof(MAIL));
        MAIL mail;
        memcpy(&mail, (const void *)mail_str.c_str(), sizeof(MAIL));

        std::string content = std::string(body, sizeof(MAIL), mail.contentsize);
        std::string sig = std::string(body, sizeof(MAIL) + mail.contentsize, mail.sigsize);

        req = "GET cert HTTP/1.0";
        body = std::string((const char *)mail.sender) + "\r\n";

        response = client.run(req, body, NULL);
        if(response == "Fail"){
            client.print_errors_and_abort("Error Getting response");
        }

        copy = std::string(response.c_str(), strstr(response.c_str(), "\r\n"));

    	statuscode = std::string(copy, copy.find(" ") + 1, 3);
    	
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

	        X509 *x509;

	        if(!(x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL))){
		        BIO_free(bio);
		        X509_free(x509);
		        client.print_errors_and_abort("Error verifying signature");
		    }


		    try{

                if(!(client.verifyCert(x509))){
                    client.print_errors_and_throw("Invalid certificate");
                }

		    	if(client.verifysign(content, sig, x509)){

	        		std::string message = client.decode(content);

	        		std::cout<<message<<std::endl;

	        	}
	        	else{
	        		std::cout<< "verify failed" << std::endl;
	        	}
		    }
		    catch (const std::exception& ex) {
            	printf("Worker exited with exception:\n%s\n", ex.what());
            	BIO_free(bio);
		        X509_free(x509);
            }

            BIO_free(bio);
		    X509_free(x509);
        }
    }
}