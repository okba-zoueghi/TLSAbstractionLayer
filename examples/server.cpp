#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>


#define PORT 						           4433
#define CERTIFICATE_PATH			     "./ca/intermediate/certs/server.cert.pem"
#define PRIVATE_KEY_PATH 			     "./ca/intermediate/private/server.key.pem"
#define CHAIN_OF_TRUST_CERT_PATH	 "./ca/intermediate/certs/ca-chain.cert.pem"
#define MSG 						           "Hello world\n"

using namespace TLSAbstractionLayer;


int main(int argc, char **argv)
{

  int listen_sock = 0;
	int handshake = 0;
	struct sockaddr_in addr;

	//Create socket, bind and listen for connections
	addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sock < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }
	else
	{
		printf("Socket created, sock fd: %d\n",listen_sock);
	}

  if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
  }

  if (listen(listen_sock, 1) < 0)
  {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
  }


    /* Handle connections */
    while(1)
    {
      struct sockaddr_in addr;
      uint len = sizeof(addr);
	    printf("Listening for connections ...\n");
      int client_sock = accept(listen_sock, (struct sockaddr*)&addr, &len);
      if (client_sock < 0)
      {
          perror("Unable to accept");
          exit(EXIT_FAILURE);
      }
  		else
  		{
  			printf("Accepted connection, TCP handshake established\n");
  		}

      std::string pk = PRIVATE_KEY_PATH;
      std::string cert = CERTIFICATE_PATH;
      std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
      std::list<std::string> l;
      bool verifyPeerCerificate = true;

      OpenSSLSecureEndPoint tlsServer(Protocol::TLS,
                                        ProtocolVersion::V_1_1,
                                        ProtocolVersion::V_1_3,
                                        EndPointRole::SERVER,
                                        verifyPeerCerificate,client_sock, pk, cert, cacert, l);

      tlsServer.setup();

      int res = tlsServer.doHandshake();

      tlsServer.send(MSG,sizeof(MSG));

      close(client_sock);
		  printf("Connection closed\n");
    }

    close(listen_sock);
}
