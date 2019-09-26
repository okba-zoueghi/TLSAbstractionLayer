/* TLSAbstractionLayer */
#include <TLSAbstractionLayer/WolfSSLSecureEndPoint.hpp>
#include <TLSAbstractionLayer/wolfsslConfig.hpp>

/* WolfSSL */
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Utilities */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>



namespace TLSAbstractionLayer {

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint(): ctx(NULL), ssl(NULL), wbio(NULL), rbio(NULL){
  }

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint (Protocol p,
                          ProtocolVersion minV, ProtocolVersion maxV, EndPointRole epr, bool b,
                          int sockfd, std::string pkp, std::string epcp, std::string cotcp, std::list<std::string> csl):
                          SecureEndPoint(p, minV, maxV, epr, b, sockfd, pkp, epcp, cotcp, csl),
                          ctx(NULL), ssl(NULL), wbio(NULL), rbio(NULL){
  }

  WolfSSLSecureEndPoint::WolfSSLSecureEndPoint (const WolfSSLSecureEndPoint& wolfsslEndpoint):
                          SecureEndPoint(wolfsslEndpoint), ctx(NULL), ssl(NULL), wbio(NULL), rbio(NULL){
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

      SecureEndPoint::operator=(wolfsslEndpoint);
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
          break;
        case CLIENT:
          wolfSSLMethod = wolfSSLv23_client_method;
          break;
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

  int WolfSSLSecureEndPoint::setupCiphersuiteList(){

    if (!cipherSuiteList.empty())
    {
      std::string csl;

      for (std::list<std::string>::iterator it=cipherSuiteList.begin(); it != cipherSuiteList.end(); ++it)
      {
          csl += *it + ':';
      }

      char cipherSuitesString[csl.size()+1];
      csl.copy(cipherSuitesString,csl.size());
      cipherSuitesString[csl.size()-1] = '\0';

      if ( wolfSSL_CTX_set_cipher_list(ctx,cipherSuitesString) != SSL_SUCCESS)
      {
        TLS_LOG_ERROR("Setting TLS v1.1 and v1.2 cipher suites failed");
        return -1;
      }
    }

    TLS_LOG_INFO("Cipher suites configured");
    return 0;
  }

  int WolfSSLSecureEndPoint::CreateSSLObject(){

    if ((ssl = wolfSSL_new(ctx)) == NULL)
    {
      TLS_LOG_ERROR("wolfSSL_new() failed");
      return -1;
    }

    return 0;
  }

  int WolfSSLSecureEndPoint::setupTLS(){

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

    if (setupProtocolAndVersion() != 0)
      return -1;

    if (setupPeerVerification() != 0)
      return -1;

    if (setupCredentials() != 0)
      return -1;

    if (setupCiphersuiteList() != 0)
      return -1;

    if (CreateSSLObject() != 0)
      return -1;

    TLS_LOG_INFO("TLS setup OK");
    return 0;
  }

  int WolfSSLSecureEndPoint::setupIO(IO io)
  {
    if (io == SOCKET) {
      if (socketFileDescriptor <= 0) {
        TLS_LOG_ERROR("Invalid socket file descriptor");
        return -1;
      }
      if (wolfSSL_set_fd(ssl, socketFileDescriptor) == 0)
      {
        TLS_LOG_ERROR("Failed to set socket file descriptor");
        return -1;
      }
      TLS_LOG_INFO("Set socket file descriptor OK");
    }
    else if(io == BUFFER)
    {
      rbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
      wbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());

      if (wbio == NULL || rbio == NULL) {
        TLS_LOG_ERROR("Failed to allocate memory BIOs");
        return -1;
      }

      wolfSSL_set_bio(ssl,rbio,wbio);
    }
    else
    {
      TLS_LOG_ERROR("IO unknown");
      return -1;
    }

    return 0;
  }

  int WolfSSLSecureEndPoint::doHandshake()
  {

    int ret = 0;

    switch (endPointRole) {
      case SERVER:
        ret = wolfSSL_accept(ssl);
        break;
      case CLIENT:
        ret = wolfSSL_connect(ssl);
        break;
      default:
        TLS_LOG_ERROR("EndPointRole unknown");
        return -1;
    }

    if (ret != SSL_SUCCESS)
    {
      switch (wolfSSL_get_error(ssl,ret))
      {
        case SSL_ERROR_WANT_READ :
          return Error::ERROR_WANT_READ;
          break;
        case SSL_ERROR_WANT_WRITE :
          return Error::ERROR_WANT_WRITE;
          break;

        default:
          TLS_LOG_ERROR("Handshake FAILED");
          return HandshakeState::FAILED;
      };
    }

    TLS_LOG_INFO("Handshake ESTABLISHED");
    return HandshakeState::ESTABLISHED;
  }

  int WolfSSLSecureEndPoint::send(const char * msg, int size)
  {
    int ret = wolfSSL_write(ssl, msg, size);

    if (ret <= 0)
    {
      switch (wolfSSL_get_error(ssl,ret))
      {
        case SSL_ERROR_WANT_READ :
          return Error::ERROR_WANT_READ;
          break;
        case SSL_ERROR_WANT_WRITE :
          return Error::ERROR_WANT_WRITE;
          break;

        default:
          TLS_LOG_ERROR("SSL_write FAILED");
          return Error::ERROR_WRITE_FAILED;
      };

    }

    TLS_LOG_INFO("Message sent");
    return ret;
  }

  int WolfSSLSecureEndPoint::receive(char * msg, int size)
  {
    int ret = wolfSSL_read(ssl, msg, size);

    if (ret <= 0)
    {
      switch (wolfSSL_get_error(ssl,ret))
      {
        case SSL_ERROR_WANT_READ :
          return Error::ERROR_WANT_READ;
          break;
        case SSL_ERROR_WANT_WRITE :
          return Error::ERROR_WANT_WRITE;
          break;

        default:
          TLS_LOG_ERROR("SSL_read FAILED");
          return Error::ERROR_READ_FAILED;
      };
    }

    TLS_LOG_INFO("Message received");
    return ret;
  }

  int WolfSSLSecureEndPoint::writeToBuffer(const char *clearMsg, int clearMsgsize, char ** encMsg)
  {
    int ret = wolfSSL_write(ssl,clearMsg,clearMsgsize);
    if (ret < 0) {
      TLS_LOG_ERROR("SSL_write FAILED");
      return -1;
    }

    char * buff;
    int encMsgSize = 0;
    encMsgSize = wolfSSL_BIO_get_mem_data(wbio,&buff);
    if (encMsgSize <= 0) {
      TLS_LOG_ERROR("BIO_get_mem_data FAILED");
      return -1;
    }

    (*encMsg) = NULL;
    (*encMsg) = new char[encMsgSize];
    if ((*encMsg) == NULL) {
      TLS_LOG_ERROR("Allocating memory to store encrypted message FAILED");
      return -1;
    }

    ret = wolfSSL_BIO_read(wbio,(*encMsg),encMsgSize);
    if (ret <= 0) {
      TLS_LOG_ERROR("BIO_read FAILED");
      return -1;
    }

    TLS_LOG_INFO("Message encypted");
    return ret;
  }

  int WolfSSLSecureEndPoint::readFromBuffer(const char * encMsg, int encMsgsize, char **clearMsg)
  {

    int ret = wolfSSL_BIO_write(rbio,encMsg,encMsgsize);
    if (ret <= 0) {
      TLS_LOG_ERROR("BIO_write FAILED");
      return -1;
    }

    (*clearMsg) = NULL;
    (*clearMsg) = new char[encMsgsize];
    if ((*clearMsg) == NULL) {
      TLS_LOG_ERROR("Allocating memory to store plain text message FAILED");
      return -1;
    }

    ret = wolfSSL_read(ssl,(*clearMsg),encMsgsize);
    if (ret <= 0) {
      TLS_LOG_ERROR("SSL_read FAILED");
      return -1;
    }

    TLS_LOG_INFO("Message decrypted");
    return ret;
  }

} /* TLSAbstractionLayer */
