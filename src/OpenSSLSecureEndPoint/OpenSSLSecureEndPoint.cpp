#include <TLSAbstractionLayer/OpenSSLSecureEndPoint.hpp>

#if TLS_DEBUG == 1
#define TLS_LOG_INFO(x) std::cout << "[TLS INFO] : " << x << "\n"
#define TLS_LOG_ERROR(x) std::cout << "[TLS ERROR] : " << x << "\n";ERR_print_errors_fp(stderr)
#else
#define TLS_LOG_INFO(x)
#define TLS_LOG_ERROR(x)
#endif

namespace TLSAbstractionLayer {

  bool OpenSSLSecureEndPoint::cookie_secret_intialized = false;
  std::uint8_t OpenSSLSecureEndPoint::cookie_lenght = DTLS_COOKIE_SECRET_LENGTH;
  std::uint8_t OpenSSLSecureEndPoint::cookie_secret[DTLS_COOKIE_SECRET_LENGTH] = {0};
  std::mutex OpenSSLSecureEndPoint::cookieGenerationMutex;

  int OpenSSLSecureEndPoint::initializeDTLSCookies()
  {
    if(cookie_secret_intialized)
      return 0;

    cookieGenerationMutex.lock();
    if (!cookie_secret_intialized && !RAND_bytes(OpenSSLSecureEndPoint::cookie_secret,OpenSSLSecureEndPoint::cookie_lenght))
    {
      TLS_LOG_ERROR("Failed to generate secret DTLS cookie");
      cookieGenerationMutex.unlock();
      return -1;
    }

    cookie_secret_intialized = true;
    cookieGenerationMutex.unlock();
    TLS_LOG_INFO("DTLS secret cookie generated");
    return 0;
  }

  OpenSSLSecureEndPoint::OpenSSLSecureEndPoint(): ctx(NULL), ssl(NULL), rbio(NULL),
  wbio(NULL), DTLSCookieSent(false) {
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
                          ctx(NULL), ssl(NULL), rbio(NULL), wbio(NULL), DTLSCookieSent(false) {
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
                                        opensslEndpoint.cipherSuiteList),
                                        ctx(NULL), ssl(NULL), rbio(NULL),
                                        wbio(NULL), DTLSCookieSent(false){

                                        }
  OpenSSLSecureEndPoint& OpenSSLSecureEndPoint::operator=(const OpenSSLSecureEndPoint& opensslEndpoint){
      if (this != &opensslEndpoint)
      {
        SSL_CTX_free(ctx);
        ctx = NULL;
        SSL_free(ssl);
        ssl = NULL;
        DTLSCookieSent = false;
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

      if (engineInitialized) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
      }
  }

  int OpenSSLSecureEndPoint::loadCofigAndEngine(){

    engine = NULL;
    engineInitialized = false;

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
      TLS_LOG_ERROR("Failed to load configuration from config file");
      return -1;
    }

    engine = ENGINE_by_id(EGINE_ID);

    if (!engine) {
      TLS_LOG_ERROR("Failed to load engine");
      return -1;
    }

    if (!ENGINE_init(engine)) {
     TLS_LOG_ERROR("Failed to initialize engine");
     ENGINE_free(engine);
     return -1;
    }

    TLS_LOG_INFO("Engine loaded and initialized");
    engineInitialized = true;
    return 0;
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

      default:
        TLS_LOG_ERROR("Protocol doesn't match");
        return -1;
    }

    if(!method)
      {
        TLS_LOG_ERROR("TLS_method() failed");
        return -1;
      }

    ctx = SSL_CTX_new(method);

    if(!ctx)
    {
      TLS_LOG_ERROR("SSL_CTX_new() failed");
      return -1;
    }

    TLS_LOG_INFO("Setup protocol OK");
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

        default:
          TLS_LOG_ERROR("minimum protocol version doesn't match");
          return -1;
      }

      if(SSL_CTX_set_min_proto_version(ctx,minVersion) == 0)
      {
        TLS_LOG_ERROR("setting minimum protocol version failed");
        return -1;
      }


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

        default:
          TLS_LOG_ERROR("Maximum protocol version doesn't match");
          return -1;
      }

      if(SSL_CTX_set_max_proto_version(ctx,maxVersion) == 0)
      {
        TLS_LOG_ERROR("setting maximum protocol version failed");
        return -1;
      }

    }
    else
    {
      switch (minProtocolVersion)
      {
        case V_1_1:
          minVersion = DTLS1_VERSION;
          break;
        case V_1_2:
          minVersion = DTLS1_2_VERSION;
          break;

        default:
          TLS_LOG_ERROR("minimum protocol version doesn't match");
          return -1;
      }

      if(SSL_CTX_set_min_proto_version(ctx,minVersion) == 0)
      {
        TLS_LOG_ERROR("setting minimum protocol version failed");
        return -1;
      }

      switch (maxProtocolVersion)
      {
        case V_1_1:
          maxVersion = DTLS1_VERSION;
          break;
        case V_1_2:
          maxVersion = DTLS1_2_VERSION;
          break;

        default:
          TLS_LOG_ERROR("maximum protocol version doesn't match");
          return -1;
      }

      if(SSL_CTX_set_max_proto_version(ctx,maxVersion) == 0)
      {
        TLS_LOG_ERROR("setting maximum protocol version failed");
        return -1;
      }
    }

    TLS_LOG_INFO("Setup version OK");
    return 0;
  }

  int OpenSSLSecureEndPoint::setupPeerVerification(){

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

        default:
          TLS_LOG_ERROR("Endpoint role unknown");
          return -1;
      }
    }
    else
    {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    TLS_LOG_INFO("Peer verification setup OK");
    return 0;
  }

  int OpenSSLSecureEndPoint::setupCredentials()
  {
    if (privateKeyPath.empty() || endPointCertPath.empty() || chainOfTrustCertPath.empty()) {
      TLS_LOG_ERROR("Setup credentials string empty");
      return -1;
    }

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
    {
      TLS_LOG_ERROR("Loading chain of trust certificate failed");
      return -1;
    }

    TLS_LOG_INFO("Loaded chain of trust certificate");

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    {
      TLS_LOG_ERROR("Loading endpoint's certificate failed");
      return -1;
    }

    TLS_LOG_INFO("Loaded endpoint's certificate");

    if (SSL_CTX_use_PrivateKey_file(ctx, pk, SSL_FILETYPE_PEM) <= 0 )
    {
      TLS_LOG_ERROR("Loading endpoint's private key failed");
      return -1;
    }

    TLS_LOG_INFO("Loaded endpoint's private key");

    return 0;
  }

  int OpenSSLSecureEndPoint::setupCiphersuiteList()
  {
    int ret = 0;

    if (!cipherSuiteList.empty())
    {
      std::string csl;
      std::string cslv1_3;

      for (std::list<std::string>::iterator it=cipherSuiteList.begin(); it != cipherSuiteList.end(); ++it)
      {
        if (*it == TLS_AES_128_GCM_SHA256) {
          cslv1_3 += *it + ':';
        }
        else if (*it == TLS_AES_256_GCM_SHA384) {
          cslv1_3 += *it + ':';
        }
        else if (*it == TLS_CHACHA20_POLY1305_SHA256) {
          cslv1_3 += *it + ':';
        }
        else if (*it == TLS_AES_128_CCM_SHA256) {
          cslv1_3 += *it + ':';
        }
        else if (*it == TLS_AES_128_CCM_8_SHA256) {
          cslv1_3 += *it + ':';
        }
        else{
          csl += *it + ':';
        }
      }

      if (!csl.empty())
      {
        char cipherSuitesString[csl.size()+1];
        csl.copy(cipherSuitesString,csl.size());
        cipherSuitesString[csl.size()-1] = '\0';

        if ( SSL_CTX_set_cipher_list(ctx,cipherSuitesString) != 1)
        {
          TLS_LOG_ERROR("Setting TLS v1.1 and v1.2 cipher suites failed");
          ret = -1;
        }

      }

      if (!cslv1_3.empty())
      {
        char cipherSuitesString[cslv1_3.size()+1];
        cslv1_3.copy(cipherSuitesString,cslv1_3.size());
        cipherSuitesString[cslv1_3.size()-1] = '\0';

        if ( SSL_CTX_set_ciphersuites(ctx,cipherSuitesString) != 1)
        {
          TLS_LOG_ERROR("Setting TLS v1.3 cipher suites failed");
          ret = -1;
        }
      }

      TLS_LOG_INFO("Cipher suites configured");
    }

    return ret;
  }

  int OpenSSLSecureEndPoint::setupDTLSCookies()
  {
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);

    if(initializeDTLSCookies() != 0)
      return -1;

    TLS_LOG_INFO("Setup DTLS cookies OK");
    return 0;
  }

  int OpenSSLSecureEndPoint::setupRole()
  {
    ssl = SSL_new(ctx);

    if (!ssl)
    {
      TLS_LOG_ERROR("SSL_new() failed");
      return -1;
    }


    switch (endPointRole)
    {
      case CLIENT:
        SSL_set_connect_state(ssl);
        break;
      case SERVER:
        SSL_set_accept_state(ssl);
        break;

      default:
       TLS_LOG_ERROR("Endpoint role unknown");
       return -1;
    }

    return 0;
  }

  int OpenSSLSecureEndPoint::setupTLS(){

    SSL_CTX_free(ctx);
    ctx = NULL;
    SSL_free(ssl);
    ssl = NULL;

    if (setupProtocol() != 0)
      return -1;

    if (setupVersion() != 0)
      return -1;

    if (setupPeerVerification() != 0)
      return -1;

    if (setupCredentials()!= 0)
      return -1;

    if ( (protocol == DTLS) && (setupDTLSCookies() != 0) )
      return -1;

    if (setupCiphersuiteList()!= 0)
      return -1;

    if (setupRole()!= 0)
      return -1;

    TLS_LOG_INFO("TLS setup OK");
    return 0;
  }

  int OpenSSLSecureEndPoint::setupIO(IO io)
  {
    if (io == SOCKET) {
      if (socketFileDescriptor <= 0) {
        TLS_LOG_ERROR("Invalid socket file descriptor");
        return -1;
      }
      if (SSL_set_fd(ssl, socketFileDescriptor) == 0)
      {
        TLS_LOG_ERROR("Failed to set socket file descriptor");
        return -1;
      }
      TLS_LOG_INFO("Set socket file descriptor OK");
    }
    else if(io == BUFFER)
    {
      rbio = BIO_new(BIO_s_mem());
      wbio = BIO_new(BIO_s_mem());

      if (wbio == NULL || rbio == NULL) {
        TLS_LOG_ERROR("Failed to allocate memory BIOs");
        return -1;
      }

      SSL_set_bio(ssl,rbio,wbio);
    }
    else
    {
      TLS_LOG_ERROR("IO unknown");
      return -1;
    }

    return 0;
  }

  int OpenSSLSecureEndPoint::doHandshake()
  {
    if ( (protocol == DTLS) && (endPointRole == SERVER) && !DTLSCookieSent )
    {
      int ret = 0;
      BIO_ADDR * clientAddr = BIO_ADDR_new();

      if (clientAddr == 0)
      {
        TLS_LOG_ERROR("Failed to allocate memory for client address (DTLSv1_listen)");
        return HandshakeState::FAILED;
      }

      do
      {
        ret = DTLSv1_listen(ssl, clientAddr);
      }
      while (ret == 0);
      BIO_ADDR_free(clientAddr);

      if (ret < 0)
        return HandshakeState::FAILED;

      TLS_LOG_INFO("Client Hello received and cookie sent");
      DTLSCookieSent = true;
    }

    int ret = SSL_do_handshake(ssl);

    if (ret != 1)
    {
      switch (SSL_get_error(ssl,ret))
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

  int OpenSSLSecureEndPoint::send(const char * msg, int size)
  {
    int ret = SSL_write(ssl, msg, size);

    if (ret <= 0)
    {
      switch (SSL_get_error(ssl,ret))
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

  int OpenSSLSecureEndPoint::receive(char * msg, int size)
  {
    int ret = SSL_read(ssl, msg, size);

    if (ret <= 0)
    {
      switch (SSL_get_error(ssl,ret))
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

  int OpenSSLSecureEndPoint::writeToBuffer(const char *clearMsg,int clearMsgsize,char ** encMsg)
  {
    int ret = SSL_write(ssl,clearMsg,clearMsgsize);
    if (ret < 0) {
      TLS_LOG_ERROR("SSL_write FAILED");
      return -1;
    }

    char * buff;
    size_t encMsgSize = 0;
    encMsgSize = BIO_get_mem_data(wbio,&buff);
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

    ret = BIO_read(wbio,(*encMsg),encMsgSize);
    if (ret <= 0) {
      TLS_LOG_ERROR("BIO_read FAILED");
      return -1;
    }

    TLS_LOG_INFO("Message encypted");
    return ret;
  }

  int OpenSSLSecureEndPoint::readFromBuffer(const char * encMsg, int encMsgsize, char **clearMsg)
  {

    int ret = BIO_write(rbio,encMsg,encMsgsize);
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

    ret = SSL_read(ssl,(*clearMsg),encMsgsize);
    if (ret <= 0) {
      TLS_LOG_ERROR("SSL_read FAILED");
      return -1;
    }

    TLS_LOG_INFO("Message decrypted");
    return ret;
  }

  int OpenSSLSecureEndPoint::generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
  	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  	unsigned int length = 0, resultlength;
  	union {
  		struct sockaddr_storage ss;
  		struct sockaddr_in6 s6;
  		struct sockaddr_in s4;
  	} peer;

  	/* Read peer information */
    socklen_t n = sizeof( peer );
    int socket = SSL_get_fd(ssl);
    getpeername(socket, (struct sockaddr *) &peer, &n);

  	/* Create buffer with peer's address and port */
  	length = 0;
  	switch (peer.ss.ss_family) {
  		case AF_INET:
  			length += sizeof(struct in_addr);
  			break;
  		case AF_INET6:
  			length += sizeof(struct in6_addr);
  			break;
  		default:
  			OPENSSL_assert(0);
  			break;
  	}
  	length += sizeof(in_port_t);
  	buffer = (unsigned char*) OPENSSL_malloc(length);

  	if (buffer == NULL)
  		{
  		printf("out of memory\n");
  		return 0;
  		}

  	switch (peer.ss.ss_family) {
  		case AF_INET:
  			memcpy(buffer,
  			       &peer.s4.sin_port,
  			       sizeof(in_port_t));
  			memcpy(buffer + sizeof(peer.s4.sin_port),
  			       &peer.s4.sin_addr,
  			       sizeof(struct in_addr));
  			break;
  		case AF_INET6:
  			memcpy(buffer,
  			       &peer.s6.sin6_port,
  			       sizeof(in_port_t));
  			memcpy(buffer + sizeof(in_port_t),
  			       &peer.s6.sin6_addr,
  			       sizeof(struct in6_addr));
  			break;
  		default:
  			OPENSSL_assert(0);
  			break;
  	}

  	/* Calculate HMAC of buffer using the secret */
  	HMAC(EVP_sha1(), (const void*) cookie_secret, cookie_lenght,
  	     (const unsigned char*) buffer, length, result, &resultlength);
  	OPENSSL_free(buffer);

  	memcpy(cookie, result, resultlength);
  	*cookie_len = resultlength;

  	return 1;
  }

  int OpenSSLSecureEndPoint::verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Read peer information */
  socklen_t n = sizeof( peer );
  int socket = SSL_get_fd(ssl);
  getpeername(socket, (struct sockaddr *) &peer, &n);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, cookie_lenght,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

} /* TLSAbstractionLayer */
