#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>

#define SERVER_PORT               4433
#define SERVER_IP                 "127.0.0.1"
#define CERTIFICATE_PATH			    "../../certificates/client.chain.cert.pem"
#define CHAIN_OF_TRUST_CERT_PATH	"../../certificates/ca.cert.pem"

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


  std::string cert = CERTIFICATE_PATH;
  std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
  bool verifyPeerCerificate = true;
  std::list<std::string> l;
  std::string privateKeyId = "1:02";
  std::string privateKeyPin = "0000";

  OpenSSLSecureEndPoint tlsClient;

  /* Set protocol and role */
  tlsClient.setProtocol(Protocol::TLS);
  tlsClient.setEndPointRole(EndPointRole::CLIENT);
  /* Set protocol and role */

  /* Configure certificates */
  tlsClient.setEndPointCertPath(cert);
  tlsClient.setChainOfTrustCertPath(cacert);
  tlsClient.setPeerVerify(verifyPeerCerificate);
  /* Configure certificates */

  /* Configure ciher suites */
  l.push_back(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
  l.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  l.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  l.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
  tlsClient.setCipherSuiteList(l);
  /* Configure ciher suites */

  /* Configure TLS version */
  tlsClient.setMinProtocolVersion(ProtocolVersion::V_1_2);
  tlsClient.setMaxProtocolVersion(ProtocolVersion::V_1_2);
  /* Configure TLS version */

  /* Configure HSM attributes */
  tlsClient.setPrivateKeySource(PrivateKeySource::FROM_HSM);
  tlsClient.setHSMPrivateKeyId(privateKeyId);
  tlsClient.setHSMPrivateKeyPin(privateKeyPin);
  /* Configure HSM attributes */

  /* Set socket fd */
  tlsClient.setSocketFileDescriptor(sock);
  /* Set socket fd */

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
