#ifndef SecureEndPoint_H
#define SecureEndPoint_H

#include <string>
#include <list>
#include <iterator>

namespace TLSAbstractionLayer
{
  enum EndPointRole : std::uint8_t { SERVER = 0, CLIENT };

  enum Protocol : std::uint8_t { TLS = 0, DTLS  };

  enum HandshakeState : std::uint8_t { ESTABLISHED = 4, NOTESTABLISHED, FAILED  };

  enum ProtocolVersion { V_1_1 = 0, V_1_2, V_1_3 };

  enum Error : std::uint8_t { ERROR_WANT_READ = 0, ERROR_WANT_WRITE, ERROR_READ_FAILED, ERROR_WRITE_FAILED};

  enum IO :std::uint8_t { SOCKET =0, BUFFER};

  class SecureEndPoint
  {

  protected:
    Protocol protocol;
    ProtocolVersion minProtocolVersion;
    ProtocolVersion maxProtocolVersion;
    EndPointRole endPointRole;
    HandshakeState handshake;
    bool verifyPeerCerificate;
    int socketFileDescriptor;
    std::string privateKeyPath;
    std::string endPointCertPath;
    std::string chainOfTrustCertPath;
    std::list<std::string> cipherSuiteList;

  public:

    SecureEndPoint ();

    SecureEndPoint (Protocol p,
                    ProtocolVersion minV,
                    ProtocolVersion maxV,
                    EndPointRole epr,
                    bool b,
                    int sockfd,
                    std::string pkp,
                    std::string epcp,
                    std::string cotcp,
                    std::list<std::string> csl);

    virtual ~SecureEndPoint ();

  public:
    void setProtocol(Protocol);
    void setEndPointRole(EndPointRole);
    void setMinProtocolVersion(ProtocolVersion);
    void setMaxProtocolVersion(ProtocolVersion);
    void setPeerVerify(bool);
    void setSocketFileDescriptor(int);
    void setPrivateKeyPath(const std::string&);
    void setEndPointCertPath(const std::string&);
    void setChainOfTrustCertPath(const std::string&);
    void setCipherSuiteList(const std::list<std::string>&);
    virtual int setupTLS() = 0;
    virtual int setupIO(IO) = 0;
    virtual int doHandshake() = 0;
    virtual int send(const char *, int) = 0;
    virtual int receive(char *, int) = 0;
    virtual int writeToBuffer(const char *,int size, char **) = 0;
    virtual int readFromBuffer(const char *,int size,char **) = 0;
  };

} /* TLSAbstractionLayer */

#endif
