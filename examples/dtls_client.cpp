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
  sock = socket(AF_INET , SOCK_DGRAM , 0);
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
		printf("Socket connected\n");
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

  OpenSSLSecureEndPoint tlsClient(Protocol::DTLS,
                                  ProtocolVersion::V_1_1,
                                  ProtocolVersion::V_1_2,
                                  EndPointRole::CLIENT,
                                  verifyPeerCerificate,sock, pk, cert, cacert, l);

  int s = tlsClient.setupTLS();
  if (s == -1) {
    printf("TLS setup failed\n");
    return -1;
  }

  s = tlsClient.setupIO(SOCKET);
  if (s == -1) {
    printf("IO setup failed\n");
    return -1;
  }

  int res = tlsClient.doHandshake();

  s = tlsClient.setupIO(BUFFER);
  if (s == -1) {
    printf("IO setup failed\n");
    return -1;
  }

  if (res == HandshakeState::ESTABLISHED) {
    printf("Handshake established\n");
    char encMsg[1000];
    int ret = recv(sock,encMsg,1000,0);
    printf("Received --> encMsg : %s, encMsgSize : %d\n",encMsg,ret);

    char * clearMsg;
    ret = tlsClient.readFromBuffer(encMsg,ret,&clearMsg);

    //tlsClient.receive(msg,100);
    printf("Decrypted message --> clearMsg : %s, clearMsgsize : %d\n",clearMsg,ret);
  }
  else if(res == HandshakeState::FAILED)
  {
    printf("Handshake failed\n");
  }
    close(sock);

}
