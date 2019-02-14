#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>

namespace TLSAbstractionLayer {

  OpenSSLSecureEndPoint::OpenSSLSecureEndPoint(): ctx(NULL), ssl(NULL) {
  }

  OpenSSLSecureEndPoint::OpenSSLSecureEndPoint (Protocol p,
                          ProtocolVersion minV,
                          ProtocolVersion maxV,
                          EndPointRole epr,
                          bool b,
                          int sockfd,
                          std::string pkp,
                          std::string epcp,
                          std::string cotcp,
                          std::list<std::string> csl) :
                          SecureEndPoint(p, minV, maxV, epr, b, sockfd, pkp, epcp, cotcp, csl),
                          ctx(NULL), ssl(NULL) {
                          }

  OpenSSLSecureEndPoint::OpenSSLSecureEndPoint (const OpenSSLSecureEndPoint& opensslEndpoint):
                          SecureEndPoint(opensslEndpoint.protocol,
                                        opensslEndpoint.minProtocolVersion,
                                        opensslEndpoint.maxProtocolVersion,
                                        opensslEndpoint.endPointRole,
                                        opensslEndpoint.verifyPeerCerificate,
                                        opensslEndpoint.socketFileDescriptor,
                                        opensslEndpoint.privateKeyPath,
                                        opensslEndpoint.endPointCertPath,
                                        opensslEndpoint.chainOfTrustCertPath,
                                        opensslEndpoint.cipherSuiteList), ctx(NULL), ssl(NULL){

                                        }
  OpenSSLSecureEndPoint& OpenSSLSecureEndPoint::operator=(const OpenSSLSecureEndPoint& opensslEndpoint){
      if (this != &opensslEndpoint)
      {
        SSL_CTX_free(ctx);
        SSL_free(ssl);
        protocol = opensslEndpoint.protocol;
        minProtocolVersion = opensslEndpoint.minProtocolVersion;
        maxProtocolVersion = opensslEndpoint.maxProtocolVersion;
        endPointRole = opensslEndpoint.endPointRole;
        verifyPeerCerificate = opensslEndpoint.verifyPeerCerificate;
        socketFileDescriptor = opensslEndpoint.socketFileDescriptor;
        privateKeyPath = opensslEndpoint.privateKeyPath;
        endPointCertPath = opensslEndpoint.endPointCertPath;
        chainOfTrustCertPath = opensslEndpoint.chainOfTrustCertPath;
        cipherSuiteList = opensslEndpoint.cipherSuiteList;
        handshake = HandshakeState::NOTESTABLISHED;
      }
      return *this;
  }

  OpenSSLSecureEndPoint::~OpenSSLSecureEndPoint(){
      SSL_CTX_free(ctx);
      SSL_free(ssl);
  }

  int OpenSSLSecureEndPoint::setupProtocol()
  {
    const SSL_METHOD * method = NULL;
    switch (protocol)
    {
      case TLS:
        method = TLS_method();
        break;
      case DTLS:
        method = DTLS_method();
        break;
    }

    if(!method)
      {
        return -1;
      }

    ctx = SSL_CTX_new(method);

    if(!ctx)
    {
      return -1;
    }

    return 0;
  }

  int OpenSSLSecureEndPoint::setupVersion()
  {
    int maxVersion = -1;
    int minVersion = -1;

    if(protocol == TLS)
    {
      switch (minProtocolVersion)
      {
        case V_1_1:
          minVersion = TLS1_1_VERSION;
          break;
        case V_1_2:
          minVersion = TLS1_2_VERSION;
          break;
        case V_1_3:
          minVersion = TLS1_3_VERSION;
          break;
      }

      if (minVersion == -1)
        return -1;

      if(SSL_CTX_set_min_proto_version(ctx,minVersion) == 0)
        return -1;

      switch (maxProtocolVersion)
      {
        case V_1_1:
          maxVersion = TLS1_1_VERSION;
          break;
        case V_1_2:
          maxVersion = TLS1_2_VERSION;
          break;
        case V_1_3:
          maxVersion = TLS1_3_VERSION;
          break;
      }

      if (maxVersion == -1)
        return -1;

      if(SSL_CTX_set_max_proto_version(ctx,maxVersion) == 0)
        return -1;
    }
    else
    {
      /* DTLS TODO */
      return -1;
    }

    return 0;
  }

  void OpenSSLSecureEndPoint::setupPeerVerification(){

    if (verifyPeerCerificate)
    {
      switch (endPointRole)
      {
        case CLIENT:
          SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
          break;
        case SERVER:
          SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
          break;
      }
    }
    else
    {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
  }

  int OpenSSLSecureEndPoint::setupCredentials()
  {
    char pk[privateKeyPath.size()+1];
    char cert[endPointCertPath.size()+1];
    char cacert[chainOfTrustCertPath.size()+1];

    privateKeyPath.copy(pk,privateKeyPath.size()+1);
    pk[privateKeyPath.size()] = '\0';
    endPointCertPath.copy(cert,endPointCertPath.size()+1);
    cert[endPointCertPath.size()] = '\0';
    chainOfTrustCertPath.copy(cacert,chainOfTrustCertPath.size()+1);
    cacert[chainOfTrustCertPath.size()] = '\0';

    if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1)
      return -1;

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
      return -1;

    if (SSL_CTX_use_PrivateKey_file(ctx, pk, SSL_FILETYPE_PEM) <= 0 )
      return -1;

    return 0;
  }

  int OpenSSLSecureEndPoint::setupCiphersuiteList()
  {
    std::string csl;

    if (!cipherSuiteList.empty())
    {
      for (std::list<std::string>::iterator it=cipherSuiteList.begin(); it != cipherSuiteList.end(); ++it)
      {
        csl += *it + ':';
      }

      char cipherSuitesString[csl.size()+1];
      csl.copy(cipherSuitesString,csl.size());
      cipherSuitesString[csl.size()-1] = '\0';

      if ( SSL_CTX_set_cipher_list(ctx,cipherSuitesString) == 1)
        return 0;

      return -1;
    }

    return 0;
  }

  int OpenSSLSecureEndPoint::setupRole()
  {
    ssl = SSL_new(ctx);

    if (!ssl)
      return -1;

    if (SSL_set_fd(ssl, socketFileDescriptor) == 0)
      return -1;

    switch (endPointRole)
    {
      case CLIENT:
        SSL_set_connect_state(ssl);
        break;
      case SERVER:
        SSL_set_accept_state(ssl);
        break;
    }

    return 0;
  }

  int OpenSSLSecureEndPoint::setup(){
    setupProtocol();
    setupVersion();
    setupPeerVerification();
    setupCredentials();
    setupCiphersuiteList();
    setupRole();
    return 0;
  }

  int OpenSSLSecureEndPoint::doHandshake()
  {
    return SSL_do_handshake(ssl);
  }

  int OpenSSLSecureEndPoint::send(const char * msg, int size)
  {
    return SSL_write(ssl, msg, size);
  }

  int OpenSSLSecureEndPoint::receive(char * msg, int size)
  {
    return SSL_read(ssl, msg, size);
  }

} /* TLSAbstractionLayer */
