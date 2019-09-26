#include <TLSAbstractionLayer/SecureEndPoint.hpp>

namespace TLSAbstractionLayer {

  SecureEndPoint::SecureEndPoint(){
  }

  SecureEndPoint::SecureEndPoint (Protocol p, ProtocolVersion minV, ProtocolVersion maxV, EndPointRole epr, bool b,
                  int sockfd, std::string pkp, std::string epcp, std::string cotcp, std::list<std::string> csl) :
                  protocol(p), minProtocolVersion(minV), maxProtocolVersion(maxV),
                  endPointRole(epr), handshake(HandshakeState::NOTESTABLISHED), verifyPeerCerificate(b),
                  socketFileDescriptor(sockfd), privateKeyPath(pkp), endPointCertPath(epcp),
                  chainOfTrustCertPath(cotcp), cipherSuiteList(csl)  {
                  }

  SecureEndPoint::~SecureEndPoint(){
  }

  void SecureEndPoint::setProtocol(Protocol p){
  protocol = p;
  }

  void SecureEndPoint::setEndPointRole(EndPointRole r){
  endPointRole = r;
  }

  void SecureEndPoint::setMinProtocolVersion(ProtocolVersion v){
    minProtocolVersion = v;
  }

  void SecureEndPoint::setMaxProtocolVersion(ProtocolVersion v){
    maxProtocolVersion = v;
  }

  void SecureEndPoint::setPeerVerify(bool b)
  {
    verifyPeerCerificate = b;
  }

  void SecureEndPoint::setSocketFileDescriptor(int fd){
    socketFileDescriptor = fd;
  }

  void SecureEndPoint::setPrivateKeySource(PrivateKeySource pkSource){
    privateKeySource = pkSource;
  }

  void SecureEndPoint::setHSMPrivateKeyId(const std::string& pkId){
    privateKeyId = pkId;
  }

  void SecureEndPoint::setHSMPrivateKeyPin(const std::string& pkPin){
    privateKeyPin = pkPin;
  }

  void SecureEndPoint::setPrivateKeyPath(const std::string& k){
    privateKeyPath = k;
  }

  void SecureEndPoint::setEndPointCertPath(const std::string& cert){
    endPointCertPath = cert;
  }

  void SecureEndPoint::setChainOfTrustCertPath(const std::string& cert){
    chainOfTrustCertPath = cert;
  }

  void SecureEndPoint::setCipherSuiteList(const std::list<std::string>& l){
    cipherSuiteList = l;
  }

} /* TLSAbstractionLayer */
