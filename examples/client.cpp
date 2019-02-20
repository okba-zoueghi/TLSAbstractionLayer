#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>

#define SERVER_PORT               4433
#define SERVER_IP                 "192.168.0.4"
#define CERTIFICATE_PATH			    "./ca/intermediate/certs/client.cert.pem"
#define PRIVATE_KEY_PATH 			    "./ca/intermediate/private/client.key.pem"
#define CHAIN_OF_TRUST_CERT_PATH	"./ca/intermediate/certs/ca-chain.cert.pem"

using namespace TLSAbstractionLayer;

int main(int argc, char **argv)
{
  int sock = 0;
  char msg[100] ={0};

	//Fill in server details
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(SERVER_PORT);
  server.sin_addr.s_addr = inet_addr(SERVER_IP);

	//Initialize the library
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();


	//Create socket
  sock = socket(AF_INET , SOCK_STREAM , 0);
	if (sock == -1)
	{
		printf("Could not create socket\n");
	}
	else
	{
		printf("Socket created, sock fd: %d\n",sock);
	}

	//Connect socket
	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		perror("connect failed. Error");
		return 1;
	}
	else
	{
		printf("TCP handshake established\n");
	}

  std::string pk = PRIVATE_KEY_PATH;
  std::string cert = CERTIFICATE_PATH;
  std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
  std::list<std::string> l;
  bool verifyPeerCerificate = true;

   //TLS v1.1 ciphers
   l.push_back(TLS_RSA_WITH_AES_128_CBC_SHA);

   //TLS v1.2 ciphers
   l.push_back(TLS_RSA_WITH_AES_256_GCM_SHA384);
   l.push_back(TLS_RSA_WITH_AES_128_GCM_SHA256);
   l.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);

   //TLS v1.3 ciphers
   l.push_back(TLS_AES_128_CCM_SHA256);
   l.push_back(TLS_CHACHA20_POLY1305_SHA256);

  OpenSSLSecureEndPoint tlsClient(Protocol::TLS,
                                  ProtocolVersion::V_1_1,
                                  ProtocolVersion::V_1_3,
                                  EndPointRole::CLIENT,
                                  verifyPeerCerificate,sock, pk, cert, cacert, l);

  tlsClient.setup();

  int res = tlsClient.doHandshake();

  if (res == HandshakeState::ESTABLISHED) {
    printf("Handshake established\n");
    tlsClient.receive(msg,100);
    printf("message : %s\n",msg);
  }
  else if(res == HandshakeState::FAILED)
  {
    printf("Handshake failed\n");
  }
    close(sock);

}
