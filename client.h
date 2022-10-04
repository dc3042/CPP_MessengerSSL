/*
 * client.h
 */

#ifndef __CLIENT_H__
#define __CLIENT_H__

class Client{

	public:

		// constructor
		Client(std::string hostname, int port, std::string caFile, bool cert, std::string certFile, std::string pvtKey);

		~Client();

		std::string run(std::string& req, std::string& body, const char *multipart_boundary);

		// Open socket
		bool openConnection();

		// Initiliaze context for SSL
		bool initializeCTX();

		// load id/pw or certificate
		bool loadCert(char *password, char *identity);

		// load public key as string
		std::string load_publickey();

		// save cert from response
		bool saveCert(std::string body);

		std::string encode(std::string message, X509 *x509);

		std::string decode(std::string message);

		std::string sign(std::string message);

		bool verifysign(std::string message, std::string sig, X509 *x509);

		bool verifyCert(X509 *x509);

		std::vector<std::string> split_headers(const std::string& text);

		[[noreturn]] void print_errors_and_abort(const char *message){
    
		    fprintf(stderr, "%s\n", message);
		    ERR_print_errors_fp(stderr);
		    abort();
		}

		[[noreturn]] void print_errors_and_throw(const char *message){
		    ERR_print_errors_fp(stderr);
		    throw std::runtime_error(std::string(message));
		}

	private:

		std::string Exchange(std::string& req, std::string& body, const char *multipart_boundary);

		std::string receive_some_data();

		std::string receive_http_message();

		void send_http_request(const std::string& line, const std::string& body, const char *multipart_boundary);
		
		// Class variables
		std::string id;
		std::string pw;
		std::string hostname;
	    int sock; // socket fd
	    int port; // port number
	    bool cert; // has certificate
	    std::string caFile; // address of trusted CA chain
	    std::string certFile; // address of certificate
	    std::string pvtKey; // address of private key
	    SSL_CTX *ctx; // CTX for ssl connection
	    SSL *ssl;
};

#endif