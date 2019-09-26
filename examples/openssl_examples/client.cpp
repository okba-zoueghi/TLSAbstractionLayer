#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>
#include <TLSAbstractionLayer/WolfSSLSecureEndPoint.hpp>


#define SERVER_PORT               4433
#define SERVER_IP                 "127.0.0.1"
#define CERTIFICATE_PATH			    "../../ca/intermediate/certs/client.cert.pem"
#define PRIVATE_KEY_PATH 			    "../../ca/intermediate/private/client.key.pem"
#define CHAIN_OF_TRUST_CERT_PATH	"../../ca/intermediate/certs/ca-chain.cert.pem"

enum ReceiveTlsPacketState {RECEIVE_HEADER, RECEIVE_APPLICATION_DATA, TLS_PROCESS_DATA,
  CLOSE_CONNECTION, HANDLE_SOCK_ERROR, HANDLE_TLS_ERROR};


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

  std::string pk = PRIVATE_KEY_PATH;
  std::string cert = CERTIFICATE_PATH;
  std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
  bool verifyPeerCerificate = true;
  std::list<std::string> l;

  //TLSAbstractionLayer::OpenSSLSecureEndPoint tlsClient;
  TLSAbstractionLayer::WolfSSLSecureEndPoint tlsClient;

  /* Set protocol and role */
  tlsClient.setProtocol(TLSAbstractionLayer::Protocol::TLS);
  tlsClient.setEndPointRole(TLSAbstractionLayer::EndPointRole::CLIENT);
  /* Set protocol and role */

  /* Configure certificates */
  tlsClient.setEndPointCertPath(cert);
  tlsClient.setChainOfTrustCertPath(cacert);
  tlsClient.setPeerVerify(verifyPeerCerificate);
  /* Configure certificates */

  /* Configure ciher suites */
  l.push_back(TLSAbstractionLayer::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
  // l.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  // l.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  // l.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
  tlsClient.setCipherSuiteList(l);
  /* Configure ciher suites */

  /* Configure TLS version */
  tlsClient.setMinProtocolVersion(TLSAbstractionLayer::ProtocolVersion::V_1_2);
  tlsClient.setMaxProtocolVersion(TLSAbstractionLayer::ProtocolVersion::V_1_2);
  /* Configure TLS version */

  /* Set private key from a file */
  tlsClient.setPrivateKeySource(TLSAbstractionLayer::PrivateKeySource::FROM_FILE);
  tlsClient.setPrivateKeyPath(pk);
  /* Set private key from a file */

  /* Set socket fd */
  tlsClient.setSocketFileDescriptor(sock);
  /* Set socket fd */

  int s = tlsClient.setupTLS();
  if (s == -1) {
    printf("TLS setup failed\n");
    return -1;
  }

  s = tlsClient.setupIO(TLSAbstractionLayer::IO::SOCKET);
  if (s == -1) {
    printf("IO setup failed\n");
    return -1;
  }

  int res = tlsClient.doHandshake();

  s = tlsClient.setupIO(TLSAbstractionLayer::IO::BUFFER);
  if (s == -1) {
    printf("IO setup failed\n");
    return -1;
  }

  if (res == TLSAbstractionLayer::HandshakeState::ESTABLISHED) {
    printf("Handshake established\n");

    /* Max TLS message size to receive is 1000 bytes */
    char encMsg[1000];
    /* Max TLS message size to receive is 1000 bytes */

    /* Variable to store the size of the TLS message (header + application data) */
    unsigned int tlsMessageSize;

    /* Variable to store the length of the application data */
    unsigned int tlsAppDatalength;

    int ret;
    int length;
    char * clearMsg;

    ReceiveTlsPacketState state = RECEIVE_HEADER;

    while (1) {

      switch (state) {

        case RECEIVE_HEADER:
        printf("RECEIVE_HEADER\n");
          /* Receive only the header to determine the encrypted application data size */
          ret = 0;
          length = 0;

          do {
            ret = recv(sock,encMsg + length, TLSAbstractionLayer::TLS_HEADER_SIZE - length,0);
            length += ret;
          } while( (length < TLSAbstractionLayer::TLS_HEADER_SIZE) && (ret != 0) && (ret < 0) );

          if (ret < 0) {
            state = HANDLE_SOCK_ERROR;
          }
          else if (ret == 0) {
            state = CLOSE_CONNECTION;
          }
          else{
            state = RECEIVE_APPLICATION_DATA;
          }
          break;

        case RECEIVE_APPLICATION_DATA:
        printf("RECEIVE_APPLICATION_DATA\n");
          /* Retrieve the size of the application data from the header */
          tlsAppDatalength = (encMsg[3] << 8) + encMsg[4];

          length = 0;

          /* Receive the remaining message (the application data) */
          do {
            ret = recv(sock, encMsg + TLSAbstractionLayer::TLS_HEADER_SIZE + length, tlsAppDatalength - length,0);
            length += ret;
          } while( (length < tlsAppDatalength) && (ret != 0) && (ret < 0) );

          if (ret < 0) {
            state = HANDLE_SOCK_ERROR;
          }
          else if (ret == 0) {
            state = CLOSE_CONNECTION;
          }
          else{
            /* Calculate the total message size (header + application data) */
            tlsMessageSize = TLSAbstractionLayer::TLS_HEADER_SIZE + tlsAppDatalength;
            printf("Received --> encMsgSize : %d\n", tlsMessageSize);
            state = TLS_PROCESS_DATA;
          }
          break;

        case TLS_PROCESS_DATA:
        printf("TLS_PROCESS_DATA\n");
          /* Process the received TLS message (decrypt the check MAC) */
          ret = tlsClient.readFromBuffer(encMsg, tlsMessageSize, &clearMsg);
          if (ret < 0) {
            state = HANDLE_TLS_ERROR;
          }
          else{
            printf("Decrypted message --> clearMsg : %s, clearMsgsize : %d\n",clearMsg,ret);
            state = RECEIVE_HEADER;
          }
          break;

        case HANDLE_SOCK_ERROR:
        printf("HANDLE_SOCK_ERROR\n");
          /* Here handle socket errors, in this example we close the connection*/
          state = CLOSE_CONNECTION;
          break;

        case HANDLE_TLS_ERROR:
        printf("HANDLE_TLS_ERROR\n");
          /* Here handle TLS errors, in this example we close the connection*/
          state = CLOSE_CONNECTION;
          break;

        case CLOSE_CONNECTION:
        printf("CLOSE_CONNECTION\n");
          close(sock);
          exit(0);
      }
    }
  }
  else if(res == TLSAbstractionLayer::HandshakeState::FAILED)
  {
    printf("Handshake failed\n");
  }

  close(sock);

}
