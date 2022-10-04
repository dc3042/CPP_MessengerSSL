/*
 * client.cpp
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
#include <openssl/pem.h>
#include <openssl/rsa.h>
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


Client::Client(std::string hostname, int port, std::string caFile, bool cert, std::string certFile, std::string pvtKey){

	this->hostname = hostname;
	this->port = port;
	this->caFile = caFile;
	this->ssl = NULL;
	this->cert = cert;

	this->certFile = certFile;
	this->pvtKey = pvtKey;
}

Client::~Client(){

    SSL_CTX_free(this->ctx);
}

std::string Client::run(std::string& req, std::string& body, const char *multipart_boundary){

    if(!openConnection()){
        print_errors_and_abort("Error opening socket");
    }

    BIO *sbio = BIO_new_socket(this->sock, BIO_NOCLOSE);

    this->ssl = SSL_new(ctx);
    SSL_set_bio(this->ssl, sbio, sbio);

    try{
        return Exchange(req, body, multipart_boundary);
    }
    catch (const std::exception& ex) {
        
        printf("Worker exited with exception:\n%s\n", ex.what());
        int serversock = SSL_get_fd(this->ssl);
        SSL_free(this->ssl);
        close(serversock);
        close(this->sock);
        return "Fail";
    }
}

std::string Client::Exchange(std::string& req, std::string& body, const char *multipart_boundary){

    std::string response;

	if ( SSL_connect(this->ssl) == -1 )   /* perform the connection */
        print_errors_and_throw("error in SSL_connect");
    else
    {

    	send_http_request(req, body, multipart_boundary);
    	response = receive_http_message();
    }

    int serversock = SSL_get_fd(this->ssl);
    SSL_free(this->ssl);
    close(serversock);
    close(this->sock);

    return response;
}

void Client::send_http_request(const std::string& line, const std::string& body, const char *multipart_boundary)
{
    std::string request = line + "\r\n";
    request += "Host:" + this->hostname + "\r\n";
    
    int body_size = body.size();
    if(body_size > 0){

        request += "Content-Length:" + std::to_string(body_size) + "\r\n";
    }

    request += "identity:" + this->id + "\r\n";

    if (!this->cert){

    	request += "password:" + this->pw + "\r\n";

    }

    if(multipart_boundary){

        request += "Boundary:" + std::string(multipart_boundary, 32) + "\r\n";
    }

    request += "\r\n";

    if(SSL_write(this->ssl, request.data(), request.size()) <= 0){
        print_errors_and_throw("error in SSL_write");
    } 

    if(body_size > 0){

        if(SSL_write(this->ssl, body.data(), body.size()) <= 0){
            print_errors_and_throw("error in SSL_write");
        }
    }

}

std::string Client::receive_some_data()
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
std::vector<std::string> Client::split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}


std::string Client::receive_http_message()
{
    std::string headers = receive_some_data();
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += receive_some_data();
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                content_length = std::stoul(colon+1);
            }
        }
    }
    while (body.size() < content_length) {
        body += receive_some_data();
    }
    return headers + "\r\n" + body;
}


bool Client::openConnection(){

    this->sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr((this->hostname).c_str());
    addr.sin_port = htons(this->port);

    if (::connect(this->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0 )
    {
        return false;
    }

    return true;
}

bool Client::initializeCTX(){

	const SSL_METHOD *method;
    method = TLS_method();  /* create new client-method instance */
    this->ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( this->ctx == NULL )
    {
        return false;
    }

    SSL_CTX_set_verify(this->ctx, SSL_VERIFY_PEER, NULL); /* Verify server certificate */
    SSL_CTX_load_verify_locations(this->ctx, (this->caFile).c_str(),
                                   (this->caFile).c_str()); /* Set trusted ca-chain*/

    return true;
}

bool Client::loadCert(char *password, char *identity){


	if(this->cert){

        char *pass;

        if(!password){
            pass = getpass("Enter password:");

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
            
            X509_NAME *name = X509_get_subject_name(x);
            char *namestr = X509_NAME_oneline(name, NULL, 0);
            this-> id = std::string(strstr(namestr, "CN=") + 3);
            free(namestr);
            X509_free(x);
            fclose(certfile);

            if(SSL_CTX_use_certificate_file(this->ctx, (this->certFile).c_str(), SSL_FILETYPE_PEM) <= 0)
            {
                free(pass);
                return false;
            }

            FILE *keyfile;

            if(!(keyfile = fopen((this->pvtKey).c_str(), "rb"))){
                free(pass);
                return false;
            }

            EVP_PKEY *pvtkey;

            if(!(pvtkey = PEM_read_PrivateKey(keyfile, NULL, NULL, pass))){
                free(pass);
                return false;
            }

            if ( SSL_CTX_use_PrivateKey(this->ctx, pvtkey) <= 0 )
            {
                EVP_PKEY_free(pvtkey);
                free(pass);
                return false;
            }

            fclose(keyfile);
            EVP_PKEY_free(pvtkey);

            /* verify private key */
            if ( !SSL_CTX_check_private_key(this->ctx) )
            {
                free(pass);
                return false;
            }

            this->pw = pass;
            free(pass);
        }
        else{

            pass = password;

            X509 *x;
            FILE *certfile;
            if(!(certfile = fopen((this->certFile).c_str(), "rb"))){
                return false;
            }

            /* set the local certificate from CertFile */
            if ( !(x = PEM_read_X509(certfile, NULL , NULL, pass)))
            {
                fclose(certfile);
                return false;
            }
            
            X509_NAME *name = X509_get_subject_name(x);
            char *namestr = X509_NAME_oneline(name, NULL, 0);
            this-> id = std::string(strstr(namestr, "CN=") + 3);
            free(namestr);
            X509_free(x);
            fclose(certfile);

            if(SSL_CTX_use_certificate_file(this->ctx, (this->certFile).c_str(), SSL_FILETYPE_PEM) <= 0)
            {
                return false;
            }

            FILE *keyfile;

            if(!(keyfile = fopen((this->pvtKey).c_str(), "rb"))){
                return false;
            }

            EVP_PKEY *pvtkey;

            if(!(pvtkey = PEM_read_PrivateKey(keyfile, NULL, NULL, pass))){
                free(pass);
                return false;
            }

            if ( SSL_CTX_use_PrivateKey(this->ctx, pvtkey) <= 0 )
            {
                EVP_PKEY_free(pvtkey);
                return false;
            }

            fclose(keyfile);
            EVP_PKEY_free(pvtkey);

            /* verify private key */
            if ( !SSL_CTX_check_private_key(this->ctx) )
            {
                return false;
            }

            this->pw = pass;
        }


	}

    else{

        if(!identity){
            std::cout << "Enter ID:";
            getline(std::cin, this->id);

        }
        
        else{
            this->id = identity;
        }

        char *pass;

        if(!password){
            pass = getpass("Enter password:");
            this->pw = pass;
            free(pass);
        }
        else{
            this->pw = password;
        }
    }

    return true;
}


std::string Client::load_publickey(){

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx;

    if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))){
        print_errors_and_abort("Error loading public key");
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0){
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0){
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    FILE *keyfile;

    if(!(keyfile = fopen((this->pvtKey).c_str(), "wb"))){
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    if(PEM_write_PrivateKey(keyfile, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, (void *)(this->pw).c_str()) <= 0){
        fclose(keyfile);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    fclose(keyfile);

    BIO* bio;

    if(!(bio = BIO_new(BIO_s_mem()))){
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    if(PEM_write_bio_PUBKEY(bio, pkey)<=0){
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    long len = BIO_get_mem_data(bio, NULL);
    char *pem = (char *)malloc(len + 1);
    if (pem == NULL) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    pem[len] = 0;

    if (BIO_read(bio, pem, len) <= 0){
        BIO_free(bio);
        free(pem);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        print_errors_and_abort("Error loading public key");
    }

    std::string result = pem;
    BIO_free(bio);
    free(pem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return result;
}

bool Client::saveCert(std::string body){

    BIO* bio = BIO_new( BIO_s_mem() );
    if(!bio){
        return false;
    }

    if(BIO_write( bio, body.c_str(), body.size()) <= 0){
        BIO_free(bio);
        return false;
    }

    X509 *x509;

    if(!(x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL))){
        BIO_free(bio);
        X509_free(x509);
        return false;
    }

    FILE *x509_file = fopen((this->certFile).c_str(), "wb");

    if(PEM_write_X509(x509_file, x509) <= 0){
        fclose(x509_file);
        X509_free(x509);
        print_errors_and_throw("Error saving certificate");
    }
 
    BIO_free(bio);
    fclose(x509_file);
    X509_free(x509);
    return true;
}

std::string Client::encode(std::string message, X509 *x509){


    EVP_PKEY *pkey;

    if(!(pkey = X509_get_pubkey(x509))){
        print_errors_and_throw("Error encrypting message");
    }

    EVP_PKEY_CTX *pctx;
    if(!(pctx = EVP_PKEY_CTX_new(pkey, NULL))){
        EVP_PKEY_free(pkey);
        print_errors_and_throw("Error encrypting message");
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        print_errors_and_throw("Error encrypting message");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        print_errors_and_throw("Error encrypting message");
    }

    size_t outlen;

    if (EVP_PKEY_encrypt(pctx, NULL, &outlen, (unsigned char *) message.c_str(), message.size()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        print_errors_and_throw("Error encrypting message");
    }

    unsigned char *out = (unsigned char *) malloc(outlen);

    if (!out){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        print_errors_and_throw("Error encrypting message");
    }

    if (EVP_PKEY_encrypt(pctx, out, &outlen, (unsigned char *) message.c_str(), message.size()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        free(out);
        print_errors_and_throw("Error encrypting message");
    }

    std::string result((const char *)out, outlen);
    free(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

std::string Client::decode(std::string message){

    FILE *keyfile;

    if(!(keyfile = fopen((this->pvtKey).c_str(), "rb"))){
        print_errors_and_throw("Error decrypting message");
    }

    EVP_PKEY *pvtkey;

    if(!(pvtkey = PEM_read_PrivateKey(keyfile, NULL, NULL, (void *)(this->pw).c_str()))){
        fclose(keyfile);
        print_errors_and_throw("Error decrypting message");
    }

    fclose(keyfile);

    EVP_PKEY_CTX *pctx;
    if(!(pctx = EVP_PKEY_CTX_new(pvtkey, NULL))){
        EVP_PKEY_free(pvtkey);
        print_errors_and_throw("Error decrypting message");
    }

    if (EVP_PKEY_decrypt_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pvtkey);
        print_errors_and_throw("Error decrypting message");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pvtkey);
        print_errors_and_throw("Error encrypting message");
    }

    size_t outlen;

    if (EVP_PKEY_decrypt(pctx, NULL, &outlen, (unsigned char *) message.c_str(), message.size()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pvtkey);
        print_errors_and_throw("Error encrypting message");
    }

    unsigned char *out = (unsigned char *) malloc(outlen);

    if (!out){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pvtkey);
        print_errors_and_throw("Error encrypting message");
    }

    if (EVP_PKEY_decrypt(pctx, out, &outlen, (unsigned char *) message.c_str(), message.size()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pvtkey);
        free(out);
        print_errors_and_throw("Error encrypting message");
    }

    std::string result((const char *)out, outlen);
    free(out);
    EVP_PKEY_free(pvtkey);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

std::string Client::sign(std::string message){


    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    if(!(mdctx = EVP_MD_CTX_new())){
        print_errors_and_throw("Error signing message");
    }

    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error signing message");
    }

    if(EVP_DigestUpdate(mdctx, message.c_str(), message.size()) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error signing message");
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];

    if(EVP_DigestFinal_ex(mdctx, md_value, &md_len) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error signing message");
    }
    EVP_MD_CTX_free(mdctx);

    FILE *keyfile;

    if(!(keyfile = fopen((this->pvtKey).c_str(), "rb"))){
        print_errors_and_throw("Error signing message");
    }

    EVP_PKEY *signing_key;

    if(!(signing_key = PEM_read_PrivateKey(keyfile, NULL, NULL, (void *)(this->pw).c_str()))){
        fclose(keyfile);
        print_errors_and_throw("Error signing message");
    }

    fclose(keyfile);

    EVP_PKEY_CTX *pctx;
    if(!(pctx = EVP_PKEY_CTX_new(signing_key, NULL))){
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    if (EVP_PKEY_sign_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    size_t siglen;

    if (EVP_PKEY_sign(pctx, NULL, &siglen, md_value, md_len) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    unsigned char *sig = (unsigned char *) malloc(siglen);
    if (!sig){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error encrypting message");
    }

    if (EVP_PKEY_sign(pctx, sig, &siglen, md_value, md_len) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error signing message");
    }

    std::string result((const char *)sig, siglen);
    free(sig);
    EVP_PKEY_free(signing_key);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

bool Client::verifyCert(X509 *x509){

    X509_STORE_CTX *xctx = NULL;

    if(!(xctx = X509_STORE_CTX_new())){
        print_errors_and_throw("Error verifying certificate");
    }

    X509_STORE *store = NULL;

    if(!(store = X509_STORE_new())){
        X509_STORE_CTX_free(xctx);
        print_errors_and_throw("Error verifying certificate");
    }

    if(X509_STORE_load_locations(store, (this->caFile).c_str(), (this->caFile).c_str()) <= 0){
        X509_STORE_CTX_free(xctx);
        X509_STORE_free(store);
        print_errors_and_throw("Error verifying certificate");
    }

    if(X509_STORE_CTX_init(xctx, store, x509, NULL) <= 0){
        X509_STORE_CTX_free(xctx);
        X509_STORE_free(store);
        print_errors_and_throw("Error verifying certificate");
    }

    int ret;

    if((ret = X509_verify_cert(xctx)) < 0){
        X509_STORE_CTX_free(xctx);
        X509_STORE_free(store);
        print_errors_and_throw("Error verifying certificate");
    }

    X509_STORE_CTX_free(xctx);
    X509_STORE_free(store);

    return (ret == 1);

}

bool Client::verifysign(std::string message, std::string sig, X509 *x509){

    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    if(!(mdctx = EVP_MD_CTX_new())){
        print_errors_and_throw("Error verifying signature");
    }

    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error verifying signature");
    }

    if(EVP_DigestUpdate(mdctx, message.c_str(), message.size()) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error verifying signature");
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];

    if(EVP_DigestFinal_ex(mdctx, md_value, &md_len) <= 0){
        EVP_MD_CTX_free(mdctx);
        print_errors_and_throw("Error verifying signature");
    }
    EVP_MD_CTX_free(mdctx);


    EVP_PKEY *signing_key;

    if(!(signing_key = X509_get_pubkey(x509))){
        print_errors_and_throw("Error verifying signature");
    }

    EVP_PKEY_CTX *pctx;
    if(!(pctx = EVP_PKEY_CTX_new(signing_key, NULL))){
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error verifying signature");
    }

    if (EVP_PKEY_verify_init(pctx) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error verifying signature");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error verifying signature");
    }

    if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()) <= 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error verifying signature");
    }

    size_t siglen = sig.size();

    int ret = EVP_PKEY_verify(pctx, (unsigned char *)sig.c_str(), siglen, md_value, md_len);

    if(ret < 0){
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(signing_key);
        print_errors_and_throw("Error verifying signature");
    }

    EVP_PKEY_free(signing_key);
    EVP_PKEY_CTX_free(pctx);
    return (ret == 1);
}


/**
int main (int argc, char **argv) {

	struct sigaction sa;
    memset( &sa, 0, sizeof(sa) );
    sa.sa_handler = got_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGABRT,&sa,NULL);

    std::string hostname = argv[1];
    int port = atoi(argv[2]);

    std::string caFile = "ca/intermediate/certs/ca-chain.cert.pem";
    bool cert = (atoi(argv[3]) == 1);
    
    std::string certFile = "ca/intermediate/certs/client.cert.pem";
    std::string pvtKey = "ca/intermediate/private/client.key.pem";
    std::string pubKey = "ca/intermediate/public/client.key.pem";


    // Instantiate Client object with certificate (1) / password (0)
    Client client = Client(hostname, port, caFile, cert, certFile, pvtKey, pubKey);

    if(!client.initializeCTX()){
        print_errors_and_abort("Error initializing CTX");
    }

    if(!client.loadCert()){
        print_errors_and_abort("Error loading certificate");
    }


    std::string req = "GET / HTTP/1.1";
    std::string body = client.load_publickey();

    std::string response = client.run(req, body);

    std::cout << response << std::endl;

    response = client.run(req, body);

    std::cout << response << std::endl;

    return 0;

}
**/

