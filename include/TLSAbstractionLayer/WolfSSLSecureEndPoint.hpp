#ifndef WolfSSLSecureEndPoint_H
#define WolfSSLSecureEndPoint_H

/* TLSAbstractionLayer */
#include <TLSAbstractionLayer/SecureEndPoint.hpp>

/* WolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

/* Utilities */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>

#define TLS_DEBUG 1

namespace TLSAbstractionLayer {

  typedef struct IOCTX
  {
    char * msg;
    size_t msgSize;
  } IOCTX;

  class WolfSSLSecureEndPoint : public SecureEndPoint{

  private:
    WOLFSSL_CTX *ctx;
	  WOLFSSL *ssl;
    IOCTX *sendCTX;
    IOCTX *recvCTX;

  public:

    WolfSSLSecureEndPoint();

    WolfSSLSecureEndPoint (Protocol p,
                          ProtocolVersion minV,
                          ProtocolVersion maxV,
                          EndPointRole epr,
                          bool b,
                          int sockfd,
                          std::string pkp,
                          std::string epcp,
                          std::string cotcp,
                          std::list<std::string> csl);

    WolfSSLSecureEndPoint (const WolfSSLSecureEndPoint&);

    WolfSSLSecureEndPoint& operator=(const WolfSSLSecureEndPoint&);

    ~WolfSSLSecureEndPoint ();

    int setupTLS();
    int setupIO(IO);
    int doHandshake();
    int send(const char *, size_t);
    int receive(char *, size_t);
    int writeToBuffer(const char *,size_t size, char **);
    int readFromBuffer(const char *,size_t size,char **);
  private:
    int setupProtocolAndVersion();
    int setupPeerVerification();
    int setupCredentials();
    int setupCiphersuiteList();
    int CreateSSLObject();
  };

} /* TLSAbstractionLayer */

#endif
