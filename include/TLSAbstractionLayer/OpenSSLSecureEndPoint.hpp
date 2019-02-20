#ifndef OpenSSLSecureEndPoint_H
#define OpenSSLSecureEndPoint_H


#include <TLSAbstractionLayer/SecureEndPoint.hpp>
#include <TLSAbstractionLayer/opensslCipherSuites.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

namespace TLSAbstractionLayer {

  class OpenSSLSecureEndPoint : public SecureEndPoint{

  private:
    SSL_CTX *ctx;
	  SSL *ssl;

  public:

    OpenSSLSecureEndPoint();

    OpenSSLSecureEndPoint (Protocol p,
                          ProtocolVersion minV,
                          ProtocolVersion maxV,
                          EndPointRole epr,
                          bool b,
                          int sockfd,
                          std::string pkp,
                          std::string epcp,
                          std::string cotcp,
                          std::list<std::string> csl);

    OpenSSLSecureEndPoint (const OpenSSLSecureEndPoint&);

    OpenSSLSecureEndPoint& operator=(const OpenSSLSecureEndPoint&);

    ~OpenSSLSecureEndPoint ();

    int setup();
    int doHandshake();
    int send(const char *, int);
    int receive(char *, int);
  private:
    int setupProtocol();
    int setupVersion();
    void setupPeerVerification();
    int setupCredentials();
    int setupCiphersuiteList();
    int setupRole();
  };

} /* TLSAbstractionLayer */

#endif
