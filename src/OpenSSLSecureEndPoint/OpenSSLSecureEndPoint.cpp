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

  OpenSSLSecureEndPoint::~OpenSSLSecureEndPoint(){
      SSL_CTX_free(ctx);
      SSL_free(ssl);
  }

  int OpenSSLSecureEndPoint::setup(){

    const SSL_METHOD * method = NULL;
    int maxVersion = -1;
    int minVersion = -1;
    char pk[privateKeyPath.size()+1];
    char cert[endPointCertPath.size()+1];
    char cacert[chainOfTrustCertPath.size()+1];

    privateKeyPath.copy(pk,privateKeyPath.size()+1);
    pk[privateKeyPath.size()] = '\0';
    endPointCertPath.copy(cert,endPointCertPath.size()+1);
    cert[endPointCertPath.size()] = '\0';
    chainOfTrustCertPath.copy(cacert,chainOfTrustCertPath.size()+1);
    cacert[chainOfTrustCertPath.size()] = '\0';

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

      if(minVersion != -1)
      {
        if(SSL_CTX_set_min_proto_version(ctx,minVersion) == 0)
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
      }

      if(maxVersion != -1)
      {
        if(SSL_CTX_set_max_proto_version(ctx,maxVersion) == 0)
          return -1;
      }

    }
    else
    {
      /* DTLS TODO */
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) == 1)
  	{
  		printf("loaded chain of trust\n");
  	}
  	else
  	{
  		printf("failed to load chain of trust\n");
  		exit(EXIT_FAILURE);
  	}

	/* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, pk, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    //Link the SSL variable to its context
	ssl = SSL_new(ctx);

	//Link the SSL variable to the socket
    SSL_set_fd(ssl, socketFileDescriptor);

	//Set SSL varibale to client mode
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
