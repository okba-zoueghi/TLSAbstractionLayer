#ifndef OpenSSLSecureEndPoint_H
#define OpenSSLSecureEndPoint_H


#include <TLSAbstractionLayer/SecureEndPoint.hpp>
#include <TLSAbstractionLayer/opensslCipherSuites.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>

#define TLS_DEBUG 1

#define DTLS_COOKIE_SECRET_LENGTH 20

namespace TLSAbstractionLayer {

  class OpenSSLSecureEndPoint : public SecureEndPoint{

  private:
    SSL_CTX *ctx;
	  SSL *ssl;
    BIO *rbio;
    BIO *wbio;

  private:
    static std::uint8_t cookie_lenght;
    static std::uint8_t cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
    static bool cookie_secret_intialized;

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

    int setupTLS();
    int setupIO(IO);
    int doHandshake();
    int send(const char *, int);
    int receive(char *, int);
    int writeToBuffer(const char *,int size, char **);
    int readFromBuffer(const char *,int size,char **);
    int initializeDTLSCookies();
  private:
    int setupProtocol();
    int setupVersion();
    int setupPeerVerification();
    int setupCredentials();
    int setupCiphersuiteList();
    int setupRole();
  };

} /* TLSAbstractionLayer */

#endif
