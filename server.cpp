/*
 * server.cpp
*/

#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <atomic>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <crypt.h>
#include <dirent.h>
#include "server.h"
#include "mail.h"

void got_signal(int)
{
    printf("\nClean exit!\n");
}

[[noreturn]] void print_errors_and_abort(const char *message){
    
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    abort();
}

[[noreturn]] void print_errors_and_throw(const char *message){
    ERR_print_errors_fp(stderr);
    throw std::runtime_error(std::string(message));
}


Server::Server(int port, std::string certFile, std::string keyFile, std::string caFile){

	this->port = port;
	this->certFile = certFile;
	this->keyFile = keyFile;
    this->caFile = caFile;
	this->ssl = nullptr;
}

Server::~Server(){

    if(this->ssl){
        int sd = SSL_get_fd(this->ssl);       /* get socket connection */
        SSL_free(this->ssl);         /* release SSL state */
        close(sd);

    }

    SSL_free(this->ssl);
    close(this->sock);
    SSL_CTX_free(this->ctx);
}

void Server::run(){

    if(!openConnection()){
        print_errors_and_abort("Error opening socket");
    }

    if(!initializeCTX()){
        print_errors_and_abort("Error initializing CTX");
    }

    if(!loadCert()){
        print_errors_and_abort("Error loading certificate");
    }

	int clntsock;
    struct sockaddr_in clntaddr;
    socklen_t clntlen = sizeof(clntaddr);;

	while((clntsock = accept(this->sock,
                        (struct sockaddr *) &clntaddr, &clntlen)) > 0){
        
        BIO *sbio = BIO_new_socket(clntsock, BIO_NOCLOSE);

        this->ssl = SSL_new(ctx);
        SSL_set_bio(this->ssl, sbio, sbio);

        try{
            Servlet();
            this->ssl = NULL;
            this->good = false;
        }
        catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());

            SSL_free(this->ssl);
            close(clntsock);
            this->ssl = NULL;
            this->good = false;
        }
    }
}

void Server::Servlet(){

	if ( SSL_accept(this->ssl) < -1 ){ /* do SSL-protocol accept */
        print_errors_and_throw("error in SSL_accept");
	}
	else{

        X509 *cert = SSL_get_peer_certificate(this->ssl);
        std::string request = receive_http_message(cert);

        if(this->good){
            std::string response = getResponse(request);

            if(this->good){
                send_http_response(response);
            }
            else{
                send_http_bad("Message Load Failed\n");
            }
        }
		else{
            send_http_bad("Password Verification Failed\n");
        }

		int clntsock = SSL_get_fd(this->ssl);
        SSL_shutdown(this->ssl);
		SSL_free(this->ssl);
		close(clntsock);
	}
}

std::string Server::receive_some_data()
{
    char buf[1024];
    int len = SSL_read(this->ssl, buf, sizeof(buf));
    if (len > 0) {
        return std::string(buf, len);
    } 
    else if(len < 0){
        print_errors_and_throw("error in SSL_read");
    } 
    else{
        print_errors_and_throw("empty SSL_read");
    }
}

std::vector<std::string> Server::split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}


std::string Server::receive_http_message(X509 *cert){

    std::string headers = receive_some_data();
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += receive_some_data();
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    
    std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    std::string id;
    std::string pw;
    for (const std::string& line : split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                content_length = std::stoul(colon+1);
            }
            else if (header_name == "identity"){
                id = std::string(colon+1);
            }
            else if (header_name == "password"){
                pw = std::string(colon+1);
            }
        }
    }
    while (body.size() < content_length) {
        body += receive_some_data();
    }

    if(cert == NULL){
        verifyPassword(id, pw);
    }
    else{
        this->good = true;
        printf("Sent certificate\n");
        X509_free(cert);
    }

    return headers + "\r\n" + body;
}


void Server::verifyPassword(std::string& id, std::string& pw){

    printf("Sent password\n");

    std::fstream user_pw;

    user_pw.open("private/user_pw.txt", std::ios::in);

    if(!user_pw.is_open()){
        print_errors_and_throw("Error verifying password");
    }

    std::string line;

    while(getline(user_pw, line)){

        std::string name = std::strtok(&line[0], " ");
        std::string password_hash = std::strtok(NULL, " ");

        std::string salt = std::strtok(&password_hash[0], "&");
        std::string hash = std::strtok(&password_hash[0], "&");

        std::string hashed = crypt(pw.c_str(), salt.c_str());

        if(name == id && hash == hashed){
            this->good = true;
            return;
        }
    }
    user_pw.close();
}

void Server::send_http_response(const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length:" + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    SSL_write(this->ssl, response.data(), response.size());
    SSL_write(this->ssl, body.data(), body.size());

}

void Server::send_http_bad(const std::string& body)
{
    std::string response = "HTTP/1.1 400 Bad Request\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    SSL_write(this->ssl, response.data(), response.size());
    SSL_write(this->ssl, body.data(), body.size());

}

bool Server::openConnection(){

    this->sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(this->port);

    if (::bind(this->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0 )
    {
        return false;
    }

    if ( listen(this->sock, 10) != 0 )
    {

        return false;
    }

    return true;
}

bool Server::initializeCTX(){

	const SSL_METHOD *method;
    
    method = TLS_method();  /* create new server-method instance */
    this->ctx = SSL_CTX_new(method);   /* create new context from method */
    
    if (this->ctx == NULL )
    {
        return false;
    }

    SSL_CTX_set_mode(this->ctx, SSL_OP_NO_COMPRESSION | SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(this->ctx, SSL_VERIFY_PEER, NULL); /* request client certificate */

    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file((this->certFile).c_str()));

    if(SSL_CTX_load_verify_locations(this->ctx, (this->caFile).c_str(),
                                   NULL) <= 0){
        return false;
    }

    return true;
}

bool Server::loadCert(){

    char *pass = getpass("Enter password:");

    X509 *x;
    FILE *certfile;
    if(!(certfile = fopen((this->certFile).c_str(), "rb"))){

        free(pass);
        return false;

    }

    /* set the local certificate from CertFile */
    if ( !(x = PEM_read_X509(certfile, NULL , NULL, pass)))
    {
        free(pass);
        fclose(certfile);
        return false;
    }

    if(SSL_CTX_use_certificate(this->ctx, x) <= 0)
    {
        X509_free(x);
        free(pass);
        fclose(certfile);
        return false;
    }

    X509_free(x);
    fclose(certfile);

    EVP_PKEY *pkey;
    FILE *keyfile;
    if(!(keyfile = fopen((this->keyFile).c_str(), "rb"))){
        free(pass);
        return false;
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( !(pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, pass)))
    {
        free(pass);
        fclose(keyfile);
        return false;
    }

    if(SSL_CTX_use_PrivateKey(this->ctx, pkey) <= 0)
    {
        EVP_PKEY_free(pkey);
        free(pass);
        fclose(keyfile);
        return false;
    }

    EVP_PKEY_free(pkey);
    fclose(keyfile);

    /* verify private key */
    if ( !SSL_CTX_check_private_key(this->ctx) )
    {
        free(pass);
        return false;
    }

    this->pw = pass;
    free(pass);
    return true;
}


std::string Server::getResponse(std::string& request){

    std::cout << request << std::endl;

    std::string line = std::string(request.c_str(), strstr(request.c_str(), "\r\n"));

    std::string verb = std::strtok(&line[0], " ");

    if(verb == "POST"){


        std::string url = std::strtok(NULL, " ");

        if(url == "cert"){

            std::string headers = std::string(request.c_str(), strstr(request.c_str(), "\r\n\r\n"));
            headers += "\r\n";
            
            std::string id;
            for (const std::string& line : split_headers(headers)) {
                if (const char *colon = strchr(line.c_str(), ':')) {
                    auto header_name = std::string(&line[0], colon);
                    if (header_name == "identity"){
                        id = std::string(colon+1);
                    }
                }
            }

            std::string body = std::string(strstr(request.c_str(), "\r\n\r\n") + 4);

            return genCert(id, body);

        }

        else if(url.substr(0,4) == "mail"){

            std::string headers = std::string(request.c_str(), strstr(request.c_str(), "\r\n\r\n"));
            headers += "\r\n";

            std::string sender;
            size_t content_length = 0;
            std::string boundary;
            for (const std::string& line : split_headers(headers)) {
                if (const char *colon = strchr(line.c_str(), ':')) {
                    auto header_name = std::string(&line[0], colon);
                    if (header_name == "identity"){
                        sender = std::string(colon+1);
                    }
                    else if (header_name == "Content-Length") {
                        content_length = std::stoul(colon+1);
                    }
                    else if (header_name == "Boundary") {
                        boundary = "-------boundary" + std::string(colon+1, 32);
                    }
                }
            }

            std::string body = std::string(request, request.find("\r\n\r\n") + 4, content_length);

            std::string content = std::string(body, 0, body.find(boundary));
            std::string sig = std::string(body, body.find(boundary) + boundary.size());

            MAIL mail;
            memset(mail.sender, 0,  256);
            strncpy(mail.sender, sender.c_str(), sender.size());
            mail.contentsize = content.size();
            mail.sigsize = sig.size();

            std::ofstream mailbox;

            mailbox.open(url.c_str(), std::ios::app);

            if(!mailbox.is_open()){
                print_errors_and_throw("Error opening mailbox");
            }

            std::string mail_str((const char *)&mail, sizeof(mail));

            mailbox << mail_str << content << sig;

            mailbox.close();

            std::string response = "SUCCESS";

            return response;
        }

    } 

    else if(verb == "GET"){

        std::string url = std::strtok(NULL, " ");

        if(url == "cert"){

            std::string body = std::string(strstr(request.c_str(), "\r\n\r\n") + 4);

            std::vector<std::string> recipients;

            const char *start = body.c_str();
            while (const char *end = strstr(start, "\r\n")) {
                recipients.push_back(std::string(start, end));
                start = end + 2;
            }


            return loadRecCerts(recipients);

        }

        else if(url == "mail"){

            std::string headers = std::string(request.c_str(), strstr(request.c_str(), "\r\n\r\n"));
            headers += "\r\n";
            
            std::string id;
            for (const std::string& line : split_headers(headers)) {
                if (const char *colon = strchr(line.c_str(), ':')) {
                    auto header_name = std::string(&line[0], colon);
                    if (header_name == "identity"){
                        id = std::string(colon+1);
                    }
                }
            }

            std::string addr = url + "/" + id;
            
            std::fstream mailbox;

            mailbox.open(addr.c_str(), std::ios::in | std::ios::out | std::ios::app);

            if(!mailbox.is_open()){
                print_errors_and_throw("Error opening mailbox");
            }


            std::istreambuf_iterator<char> start(mailbox);
            std::istreambuf_iterator<char> end;
            std::string copy(start, end);
            mailbox.close();

            if(copy.size() == 0){
                this->good = false;
                return "";
            }

            std::string mail_str(copy, 0, sizeof(MAIL));
            MAIL mail;
            memcpy(&mail, (const void *)mail_str.c_str(), sizeof(MAIL));

            mail_str += std::string(copy, sizeof(MAIL), mail.contentsize);
            mail_str += std::string(copy, sizeof(MAIL) + mail.contentsize, mail.sigsize);

            copy.erase(0, sizeof(MAIL) + mail.contentsize + mail.sigsize);

            mailbox.open(addr.c_str(), std::ios::out);

            if(!mailbox.is_open()){
                print_errors_and_throw("Error opening mailbox");
            }

            mailbox << copy;
            mailbox.close();

            return mail_str;
        }

    }

    return "Hello World";

}

std::string Server::loadRecCerts(std::vector<std::string> recipients){

    std::string result = "";

    BIO* bio;
    X509 *cert;
    FILE *certfile;
    std::string certfilestr;

    for(int i = 0; i < (int) recipients.size(); i++){

        //Load Certificate
        bio = BIO_new( BIO_s_mem() );
        if(!bio){
            continue;
        }

        certfilestr = "certs/" + recipients[i] + ".cert.pem";
        
        if(!(certfile = fopen(certfilestr.c_str(), "rb"))){
            BIO_free(bio);
            continue;
        }

        /* get cert from certfile */
        if ( !(cert = PEM_read_X509(certfile, NULL , NULL, (void *)(this->pw).c_str())))
        {
            fclose(certfile);
            continue;
        }

        if(PEM_write_bio_X509(bio, cert)<=0){
            BIO_free(bio);
            X509_free(cert);
            continue;
        }

        long len = BIO_get_mem_data(bio, NULL);
        char *pem = (char *)malloc(len + 1);

        if (pem == NULL) {
            BIO_free(bio);
            X509_free(cert);
            continue;
        }

        pem[len] = 0;

        if (BIO_read(bio, pem, len) <= 0){
            BIO_free(bio);
            X509_free(cert);
            continue;
        }

        result += pem;
        BIO_free(bio);
        fclose(certfile);
        free(pem);
        X509_free(cert);
    }

    if(result.size() == 0){
        this->good = false;
    }

    return result;

}


std::string Server::genCert(std::string& id, std::string& body){

    BIO* bio = BIO_new( BIO_s_mem() );
    if(!bio){
        print_errors_and_abort("Error loading public key");
    }

    if(BIO_write( bio, body.c_str(), body.size()) <= 0){
        BIO_free(bio);
        print_errors_and_throw("Error loading public key");
    }

    EVP_PKEY* pkey;
    if(!(pkey = PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL ))){
        BIO_free(bio);
        print_errors_and_throw("Error loading public key");
    }

    //Load CA
    X509 *ca;
    FILE *cafile;
    if(!(cafile = fopen((this->certFile).c_str(), "rb"))){
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }

    /* get ca from CaFile */
    if ( !(ca = PEM_read_X509(cafile, NULL , NULL, (void *)(this->pw).c_str())))
    {
        fclose(cafile);
        print_errors_and_throw("Error creating certificate");
    }
    
    X509_NAME *ca_name = X509_get_subject_name(ca);

    fclose(cafile);


    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    X509_set_version(x509, 2);

    if(!x509)
    {
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);
    BIO_free(bio);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)id.c_str(), -1, -1, 0);

    X509_set_issuer_name(x509, ca_name);

    X509V3_CTX ctx;


    // Setting context of Extension
    X509V3_set_ctx( &ctx, ca, x509, NULL, NULL, 0);

    X509_EXTENSION *ex; // create a new extension

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_cert_type, "client, email");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_comment, "OpenSSL Generated Client Certificate");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "issuer,keyid");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical, nonRepudiation, digitalSignature, keyEncipherment");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "clientAuth,emailProtection");
    if( !ex ){
        X509_free(ca);
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);


    X509_free(ca);

    /* Load ca key*/
    EVP_PKEY *cakey;
    FILE *keyfile;
    if(!(keyfile = fopen((this->keyFile).c_str(), "rb"))){
        X509_free(x509);
        BIO_free(bio);
        print_errors_and_throw("Error creating certificate");
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( !(cakey = PEM_read_PrivateKey(keyfile, NULL, NULL, (void *)(this->pw).c_str())))
    {
        fclose(keyfile);
        print_errors_and_throw("Error creating certificate");
    }

    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, cakey, EVP_sha256()))
    {
        fclose(keyfile);
        X509_free(x509);
        X509_free(ca);
        print_errors_and_throw("Error creating certificate");
    }

    EVP_PKEY_free(cakey);
    fclose(keyfile);

    std::string address = "certs/" + id + ".cert.pem";
    FILE *x509_file;
    if(!(x509_file = fopen(address.c_str(), "wb"))){
        fclose(keyfile);
        BIO_free(bio);
        X509_free(x509);
        X509_free(ca);
        print_errors_and_throw("Error creating certificate");
    }
    
    /* Write the certificate to disk. */
    if(PEM_write_X509(x509_file, x509) <= 0){
        fclose(x509_file);
        X509_free(x509);
        print_errors_and_throw("Error saving certificate");
    }

    fclose(x509_file);


    bio = BIO_new(BIO_s_mem());
    if(!bio){
        X509_free(x509);
        print_errors_and_abort("Error loading certificate");
    }

    if(PEM_write_bio_X509(bio, x509)<=0){
        BIO_free(bio);
        X509_free(x509);
        print_errors_and_abort("Error loading certificate");
    }

    long len = BIO_get_mem_data(bio, NULL);
    char *pem = (char *)malloc(len + 1);

    if (pem == NULL) {
        BIO_free(bio);
        X509_free(x509);
        print_errors_and_abort("Error loading certificate");
    }

    pem[len] = 0;

    if (BIO_read(bio, pem, len) <= 0){
        BIO_free(bio);
        X509_free(x509);
        print_errors_and_abort("Error loading certificate");
    }

    std::string result = pem;
    BIO_free(bio);
    free(pem);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return result;  
}



int main (int argc, char **argv) {

    struct sigaction sa;
    memset( &sa, 0, sizeof(sa) );
    sa.sa_handler = got_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGABRT,&sa,NULL);

	// Instantiate Server object

    int port = 443;
    std::string certFile = "certs/server.cert.pem";
    std::string keyFile = "private/server.key.pem";
    std::string caFile = "ca/ca-chain.cert.pem";

	Server server = Server(port, certFile, keyFile, caFile);

    server.run();

    return 0;
}

