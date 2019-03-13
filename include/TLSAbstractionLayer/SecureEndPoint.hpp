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

  enum PrivateKeySource :std::uint8_t {FROM_FILE = 0, FROM_HSM};

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

    /**
     * \brief Set the protocol
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setProtocol(Protocol);

    /**
     * \brief Set the endpoint role
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setEndPointRole(EndPointRole);

    /**
     * \brief Set the minimum protocol version
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setMinProtocolVersion(ProtocolVersion);

    /**
     * \brief Set the maximum protocol version
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setMaxProtocolVersion(ProtocolVersion);

    /**
     * \brief Configures the authentication, if true is passed the handshake
     *  will fail if no certificate is received or if the certificate is not
     *  verified
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setPeerVerify(bool);

    /**
     * \brief Set the socket file descriptor of an existing socket
     *
     * \warning If the transport protocol is TCP, the socket shall be connected
     * \warning The changes will not take place until calling setupIO method
     */
    void setSocketFileDescriptor(int);

    /**
     * \brief Set the private key path
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setPrivateKeyPath(const std::string&);

    /**
     * \brief Set the endpoint certificate path
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setEndPointCertPath(const std::string&);

    /**
     * \brief Set the chain of trust certificate path, while establishing the
     *  handshake, the certificate of the second endpoint will be verified
     *  using against this certificate
     *
     * \warning The changes will not take place until calling setupTLS method
     */
    void setChainOfTrustCertPath(const std::string&);

    /**
     * \brief Configure the cipher suite list, the priority of the cipher suites
     *  is determined based on the order in the given list.
     *  the first cipher suite in the list will have the highest priority.
     *  If multiple TLS (or DTLS) versions may be used for the handshake.
     *  the list shall start by the cipher suites of the min version going up to
     *  to the max version. If the cipher suite list is not configured explicitly using
     *  this method, a default list is set.
     */
    void setCipherSuiteList(const std::list<std::string>&);

    /**
     * \brief apply the configurations with regards to TLS (or DTLS)
     *
     * \warning should be called after configuring all the attributes.
     *  if a parameter is not configured, the setup fails
     */
    virtual int setupTLS() = 0;

    /**
     * \brief apply the IO configuration
     *  this method allows to choose the IO, the IO could be a socket
     *  or a memory (buffer)
     *
     * \warning shall be called after configuring all the attributes.
     *  if a parameter is not configured, the setup fails
     */
    virtual int setupIO(IO) = 0;

    /**
     * \brief Establish TLS (or DTLS) handshake
     *
     */
    virtual int doHandshake() = 0;

    /**
     * \brief Send data securely
     *
     * \warning This method shall not be called if the handshake is not established
     *  or failed
     * \warning This method shall not be used if the IO is configured to memory.
     *  this method is only used to send data over a socket
     */
    virtual int send(const char *, int) = 0;

    /**
     * \brief Receive data securely
     *
     * \warning This method shall not be called if the handshake is not established
     *  or failed
     * \warning This method shall not be used if the IO is configured to memory.
     *  this method is only used to receive data over a socket
     */
    virtual int receive(char *, int) = 0;

    /**
     * \brief Write the protected data to a buffer instead of writing directly to
     * a socket.
     *
     * \warning This method shall not be called if the handshake is not established
     *  or failed
     * \warning This method shall not be used if the IO is configured to socket.
     * \warning This method allocates memory to write the encrypted message,
     *  freeing encMsg should be handled manually
     *
     * \param clearMsg buffer containing the plain text message to be encrypted.
     * \param clearMsgsize size of the plain text message
     * \param encMsg char pointer in which the encrypted message will be written
     *
     * \return size of the encrypted message
     */
    virtual int writeToBuffer(const char *clearMsg, int clearMsgsize, char ** encMsg) = 0;

    /**
     * \brief Read the protected data from a buffer instead of reading directly from
     * a socket.
     *
     * \warning This method shall not be called if the handshake is not established
     *  or failed
     * \warning This method shall not be used if the IO is configured to socket.
     * \warning This method allocates memory to write the decrypted message,
     *  freeing plainTextMsg should be handled manually
     *
     * \param encMsg buffer containing the encrypted message
     * \param encMsgSize size of the encrypted message
     * \param clearMsg buffer in which the decrypted message will be written
     *
     * \return size of the plain text message
     */
    virtual int readFromBuffer(const char * encMsg, int encMsgsize, char **clearMsg) = 0;
  };

} /* TLSAbstractionLayer */

#endif
