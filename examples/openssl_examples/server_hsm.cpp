#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>


#define PORT 						           4433
#define CERTIFICATE_PATH			     "../../ca/intermediate/certs/server.cert.pem"
#define CHAIN_OF_TRUST_CERT_PATH	 "../../ca/intermediate/certs/ca-chain.cert.pem"
#define MSG 						           "Hello world"

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


      std::string cert = CERTIFICATE_PATH;
      std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
      bool verifyPeerCerificate = true;
      std::list<std::string> l;
      std::string privateKeyId = "0:01";
      std::string privateKeyPin = "0000";

      OpenSSLSecureEndPoint tlsServer;

      /* Set protocol and role */
      tlsServer.setProtocol(Protocol::TLS);
      tlsServer.setEndPointRole(EndPointRole::SERVER);
      /* Set protocol and role */

      /* Configure certificates */
      tlsServer.setEndPointCertPath(cert);
      tlsServer.setChainOfTrustCertPath(cacert);
      tlsServer.setPeerVerify(verifyPeerCerificate);
      /* Configure certificates */

      /* Configure ciher suites */
      l.push_back(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
      tlsServer.setCipherSuiteList(l);
      /* Configure ciher suites */

      /* Configure TLS version */
      tlsServer.setMinProtocolVersion(ProtocolVersion::V_1_2);
      tlsServer.setMaxProtocolVersion(ProtocolVersion::V_1_2);
      /* Configure TLS version */

      /* Configure HSM attributes */
      tlsServer.setPrivateKeySource(PrivateKeySource::FROM_HSM);
      tlsServer.setHSMPrivateKeyId(privateKeyId);
      tlsServer.setHSMPrivateKeyPin(privateKeyPin);
      /* Configure HSM attributes */

      /* Set socket fd */
      tlsServer.setSocketFileDescriptor(client_sock);
      /* Set socket fd */

      int s = tlsServer.setupTLS();
      if (s == -1) {
        printf("TLS setup failed\n");
        return -1;
      }

      s = tlsServer.setupIO(SOCKET);
      if (s == -1) {
        printf("IO setup failed\n");
        return -1;
      }

      int res = tlsServer.doHandshake();

      s = tlsServer.setupIO(BUFFER);
      if (s == -1) {
        printf("IO setup failed\n");
        return -1;
      }

      if (res == HandshakeState::ESTABLISHED) {
        printf("Plain text message  --> clearMsg : %s, clearMsgsize: %d\n",MSG,sizeof(MSG));

        char * encMsg;
        int ret = tlsServer.writeToBuffer(MSG,sizeof(MSG),&encMsg);
        printf("Encrypted message --> encMsg :%s, size: %d\n",encMsg,ret);
        send(client_sock,encMsg,ret,0);
      }
      else if(res == HandshakeState::FAILED)
      {
        printf("Handshake failed\n");
      }
      close(client_sock);
		  printf("Connection closed\n");
    }

    close(listen_sock);
}
