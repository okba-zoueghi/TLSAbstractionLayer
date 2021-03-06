#ifndef OpenSSLSecureEndPoint_H
#define OpenSSLSecureEndPoint_H

/* TLSAbstractionLayer */
#include <TLSAbstractionLayer/SecureEndPoint.hpp>
#include <TLSAbstractionLayer/opensslCipherSuites.hpp>

/* Utilities */
#include <iostream>
#include <mutex>

/* OpenSSL */
#include <openssl/bio.h>

#define DTLS_COOKIE_SECRET_LENGTH 20

#define EGINE_ID "pkcs11"

namespace TLSAbstractionLayer {

  class OpenSSLSecureEndPoint : public SecureEndPoint{

  private:
    SSL_CTX *ctx;
	  SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    ENGINE *engine;
    EVP_PKEY * privateKey;
    bool DTLSCookieSent;
    bool engineInitialized;

  private:
    static std::uint8_t cookie_lenght;
    static std::uint8_t cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
    static bool cookie_secret_intialized;
    static std::mutex cookieGenerationMutex;

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
  private:
    int loadConfigAndEngine();
    int getPrivateKeyFromHSM();
    int setupProtocol();
    int setupVersion();
    int setupPeerVerification();
    int setupCredentials();
    int initializeDTLSCookies();
    int setupDTLSCookies();
    int setupCiphersuiteList();
    int CreateSSLObject();
    int setupRole();
    static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
    static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
  };

} /* TLSAbstractionLayer */

#endif
