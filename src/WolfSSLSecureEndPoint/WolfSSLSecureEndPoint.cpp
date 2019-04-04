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

} /* TLSAbstractionLayer */
