#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>


#define PORT 						           4433
#define CERTIFICATE_PATH			    "../../certificates/server.chain.cert.pem"
#define PRIVATE_KEY_PATH 			    "../../keys/server.key.pem"
#define CHAIN_OF_TRUST_CERT_PATH	"../../certificates/ca.cert.pem"
#define MSG 						           "Hello world"

using namespace TLSAbstractionLayer;

void udp_accept(int * listen_sock, int * client_sock, struct sockaddr_storage * client_addr);

int main(int argc, char **argv)
{

  int listen_sock = 0;
	int handshake = 0;
	struct sockaddr_in addr;

  //Create socket, bind and listen for connections
	addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  listen_sock = socket(AF_INET, SOCK_DGRAM , 0);

  if (listen_sock < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }
	else
	{
		printf("Socket created, sock fd: %d\n",listen_sock);
	}

  int n = 1;
  if( setsockopt( listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &n, sizeof( n ) ) != 0 )
  {
    perror("Unable to set socket option SO_REUSEADDR");
    exit(EXIT_FAILURE);
  }

  if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	   perror("Unable to bind");
	   exit(EXIT_FAILURE);
  }

    /* Handle connections */
    while(1)
    {
      printf("Listening for connections ...\n");
      int client_sock = -1;
      struct sockaddr_storage client_addr;

      udp_accept(&listen_sock, &client_sock, &client_addr);
      if (client_sock < 0) {
          perror("Unable to accept");
          exit(EXIT_FAILURE);
      }
      else
      {
        printf("Accepted connection\n");
      }

      std::string pk = PRIVATE_KEY_PATH;
      std::string cert = CERTIFICATE_PATH;
      std::string cacert = CHAIN_OF_TRUST_CERT_PATH;
      bool verifyPeerCerificate = true;
      std::list<std::string> l;

      OpenSSLSecureEndPoint tlsServer;

      /* Set protocol and role */
      tlsServer.setProtocol(Protocol::DTLS);
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

      /* Set private key from a file */
      tlsServer.setPrivateKeySource(PrivateKeySource::FROM_FILE);
      tlsServer.setPrivateKeyPath(pk);
      /* Set private key from a file */

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

void udp_accept(int * listen_sock, int * client_sock, struct sockaddr_storage * client_addr)
{
  int ret;
  socklen_t n;
  char buf[1] = { 0 };

  ret = (int) recvfrom(*listen_sock, buf, sizeof( buf ), MSG_PEEK, (struct sockaddr *) client_addr, &n );

  if (ret < 0) {
    perror("Accept failed");
    exit(EXIT_FAILURE);
  }

  if( connect( *listen_sock, (struct sockaddr *) client_addr, n ) != 0 ){
    perror("Failed to connect client socket");
    exit(EXIT_FAILURE);
  }

  *client_sock = *listen_sock;
  *listen_sock = -1;

  struct sockaddr_storage local_addr;
  int one = 1;

  n = sizeof( struct sockaddr_storage );
  if( getsockname( *client_sock, (struct sockaddr *) &local_addr, &n ) != 0 ||
      ( *listen_sock = (int) socket( local_addr.ss_family, SOCK_DGRAM, 0 ) ) < 0 ||
      setsockopt( *listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof( one ) ) != 0 ){

      perror("Failed to create new socket to listen to new connections");
      exit(EXIT_FAILURE);
  }

  if( bind(*listen_sock, (struct sockaddr *) &local_addr, n ) != 0 ){
    perror("Failed to bind the new socket");
    exit(EXIT_FAILURE);
  }
}
