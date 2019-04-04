#include <TLSAbstractionLayer/WolfSSLSecureEndPoint.hpp>

#if TLS_DEBUG == 1
#define TLS_LOG_INFO(x) std::cout << "[TLS INFO] : " << x << "\n"
#define TLS_LOG_ERROR(x) std::cout << "[TLS ERROR] : " << x << "\n";
#else
#define TLS_LOG_INFO(x)
#define TLS_LOG_ERROR(x)
#endif

namespace TLSAbstractionLayer {

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint(): ctx(NULL), ssl(NULL), sendCTX(NULL), recvCTX(NULL){
  }

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint (Protocol p,
                          ProtocolVersion minV,
                          ProtocolVersion maxV,
                          EndPointRole epr,
                          bool b,
                          int sockfd,
                          std::string pkp,
                          std::string epcp,
                          std::string cotcp,
                          std::list<std::string> csl):
                          SecureEndPoint(p, minV, maxV, epr, b, sockfd, pkp, epcp, cotcp, csl),
                          ctx(NULL), ssl(NULL), sendCTX(NULL), recvCTX(NULL){
  }

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint (const WolfSSLSecureEndPoint& wolfsslEndpoint):
                          SecureEndPoint(wolfsslEndpoint.protocol,
                                        wolfsslEndpoint.minProtocolVersion,
                                        wolfsslEndpoint.maxProtocolVersion,
                                        wolfsslEndpoint.endPointRole,
                                        wolfsslEndpoint.verifyPeerCerificate,
                                        wolfsslEndpoint.socketFileDescriptor,
                                        wolfsslEndpoint.privateKeyPath,
                                        wolfsslEndpoint.endPointCertPath,
                                        wolfsslEndpoint.chainOfTrustCertPath,
                                        wolfsslEndpoint.cipherSuiteList),
                                        ctx(NULL), ssl(NULL), sendCTX(NULL), recvCTX(NULL){
  }

  WolfSSLSecureEndPoint& WolfSSLSecureEndPoint::operator=(const WolfSSLSecureEndPoint& wolfsslEndpoint){
    if (this != &wolfsslEndpoint)
    {
      if(ctx)
      {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
      }

      if(ssl)
      {
        wolfSSL_free(ssl);
        ssl = NULL;
      }

      wolfSSL_Cleanup();

      protocol = wolfsslEndpoint.protocol;
      minProtocolVersion = wolfsslEndpoint.minProtocolVersion;
      maxProtocolVersion = wolfsslEndpoint.maxProtocolVersion;
      endPointRole = wolfsslEndpoint.endPointRole;
      verifyPeerCerificate = wolfsslEndpoint.verifyPeerCerificate;
      socketFileDescriptor = wolfsslEndpoint.socketFileDescriptor;
      privateKeySource = wolfsslEndpoint.privateKeySource;
      privateKeyId = wolfsslEndpoint.privateKeyId;
      privateKeyPin = wolfsslEndpoint.privateKeyPin;
      privateKeyPath = wolfsslEndpoint.privateKeyPath;
      endPointCertPath = wolfsslEndpoint.endPointCertPath;
      chainOfTrustCertPath = wolfsslEndpoint.chainOfTrustCertPath;
      cipherSuiteList = wolfsslEndpoint.cipherSuiteList;
      handshake = HandshakeState::NOTESTABLISHED;
    }
    return *this;
  }

  WolfSSLSecureEndPoint::~WolfSSLSecureEndPoint(){
    if(ctx)
    {
      wolfSSL_CTX_free(ctx);
      ctx = NULL;
    }

    if(ssl)
    {
      wolfSSL_free(ssl);
      ssl = NULL;
    }
  }

  int WolfSSLSecureEndPoint::setupProtocolAndVersion(){

    WOLFSSL_METHOD* (*wolfSSLMethod)(void);

    if (protocol != TLS) {
      TLS_LOG_ERROR("Protocol version unknown");
      return -1;
    }

    if (endPointRole != CLIENT && endPointRole != SERVER) {
      TLS_LOG_ERROR("Endpoint role unknown");
      return -1;
    }

    if (minProtocolVersion == V_1_3 || maxProtocolVersion == V_1_3) {
      TLS_LOG_ERROR("TLS version not supported");
      return -1;
    }

    if (minProtocolVersion != V_1_1 && minProtocolVersion != V_1_2) {
      TLS_LOG_ERROR("Min TLS version unknown");
      return -1;
    }

    if (maxProtocolVersion != V_1_1 && maxProtocolVersion != V_1_2) {
      TLS_LOG_ERROR("Min TLS version unknown");
      return -1;
    }

    if (minProtocolVersion > maxProtocolVersion) {
      TLS_LOG_ERROR("The min TLS version is higher than the max TLS version");
      return -1;
    }

    if (maxProtocolVersion == minProtocolVersion)
    {

      if (endPointRole == SERVER)
      {

        switch (maxProtocolVersion)
        {
          case V_1_1:
            wolfSSLMethod = wolfTLSv1_1_server_method;
            break;
          case V_1_2:
            wolfSSLMethod = wolfTLSv1_2_server_method;
            break;
          default:
            break;
        }

      }
      else
      {
        switch (maxProtocolVersion)
        {
          case V_1_1:
            wolfSSLMethod = wolfTLSv1_1_client_method;
            break;
          case V_1_2:
            wolfSSLMethod = wolfTLSv1_2_client_method;
            break;
          default:
            break;
        }
      }

      if ((ctx = wolfSSL_CTX_new(wolfSSLMethod())) == NULL)
      {
        TLS_LOG_ERROR("Failed to create WOLFSSL_CTX");
        return -1;
      }
    }
    else
    {
      switch (endPointRole)
      {
        case SERVER:
          wolfSSLMethod = wolfSSLv23_server_method;
        case CLIENT:
          wolfSSLMethod = wolfSSLv23_client_method;
      }

      if ((ctx = wolfSSL_CTX_new(wolfSSLMethod())) == NULL)
      {
        TLS_LOG_ERROR("Failed to create WOLFSSL_CTX");
        return -1;
      }

      if (wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_1) != SSL_SUCCESS)
      {
        TLS_LOG_ERROR("Failed to set min version");
        return -1;
      }
    }

    TLS_LOG_INFO("Setup protcol OK");
    TLS_LOG_INFO("Setup version OK");

    return 0;
  }

  int WolfSSLSecureEndPoint::setupPeerVerification(){

    if (verifyPeerCerificate)
    {
      switch (endPointRole)
      {
        case CLIENT:
          wolfSSL_CTX_set_verify(ctx,SSL_VERIFY_PEER, 0);
          break;
        case SERVER:
          wolfSSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
          break;
        default:
          TLS_LOG_ERROR("Endpoint role unknown");
          return -1;
      }
    }
    else
    {
      wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    }

    TLS_LOG_INFO("Peer verification setup OK");
    return 0;
  }

  int WolfSSLSecureEndPoint::setupCredentials(){

    if (endPointCertPath.empty() || chainOfTrustCertPath.empty()) {
      TLS_LOG_ERROR("Setup credentials string empty");
      return -1;
    }

    char cert[endPointCertPath.size()+1];
    char cacert[chainOfTrustCertPath.size()+1];

    endPointCertPath.copy(cert,endPointCertPath.size()+1);
    cert[endPointCertPath.size()] = '\0';
    chainOfTrustCertPath.copy(cacert,chainOfTrustCertPath.size()+1);
    cacert[chainOfTrustCertPath.size()] = '\0';

    if (wolfSSL_CTX_load_verify_locations(ctx, cacert, NULL) != SSL_SUCCESS)
    {
      TLS_LOG_ERROR("Loading chain of trust certificate failed");
      return -1;
    }

    TLS_LOG_INFO("Loaded chain of trust certificate");

    if (wolfSSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
      TLS_LOG_ERROR("Loading endpoint's certificate failed");
      return -1;
    }

    TLS_LOG_INFO("Loaded endpoint's certificate");

    if (privateKeySource == FROM_FILE)
    {

      if (privateKeyPath.empty()) {
        TLS_LOG_ERROR("Private key path empty");
        return -1;
      }

      char pk[privateKeyPath.size()+1];
      privateKeyPath.copy(pk,privateKeyPath.size()+1);
      pk[privateKeyPath.size()] = '\0';

      if (wolfSSL_CTX_use_PrivateKey_file(ctx, pk, SSL_FILETYPE_PEM) != SSL_SUCCESS)
      {
        TLS_LOG_ERROR("Loading endpoint's private key from file failed");
        return -1;
      }

    }
    else if (privateKeySource == FROM_HSM)
    {
      /* TODO */
      TLS_LOG_ERROR("Private from HSM not supported")
      return -1;
    }
    else
    {
      TLS_LOG_ERROR("Private key source unknown");
      return -1;
    }

    TLS_LOG_INFO("Loaded endpoint's private key");
    return 0;
  }

} /* TLSAbstractionLayer */
