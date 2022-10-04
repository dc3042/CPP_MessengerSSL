/*
 * server.h
 */

#ifndef __SERVER_H__
#define __SERVER_H__

class Server{

	public:

		// constructor
		Server(int port, std::string certFile, std::string keyFile, std::string caFile);

		~Server();

		void run();

	private:

		// Open socket
		bool openConnection();

		// Initiliaze context for SSL
		bool initializeCTX();

		// Load serverside certificate
		bool loadCert();

		std::string receive_some_data();

		std::vector<std::string> split_headers(const std::string& text);

		std::string receive_http_message(X509 *cert);

		void send_http_response(const std::string& body);

		void send_http_bad(const std::string& body);

		// Verify and server connection
		void Servlet();

		void verifyPassword(std::string& id, std::string& pw);

		std::string getResponse(std::string& request);

		std::string loadRecCerts(std::vector<std::string> recipients);

		std::string genCert(std::string& id, std::string& body);

		
		// Class variables
	    int sock; // socket fd
	    int port; // port number
	    std::string certFile; // address of certificate
		std::string keyFile; // address of private key
		std::string caFile;
		std::string pw;
	    SSL_CTX *ctx; // context for ssl connection
	    SSL *ssl;
	    bool good = false; // if 
};


#endif