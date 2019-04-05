
#if TLS_DEBUG == 1

  #if PRINT_TLS_LIBRARY == 1
    #define TLS_LIBRARY "OPENSSL "
  #else
    #define TLS_LIBRARY
  #endif

  #define TLS_LOG_INFO(x) std::cout <<  "[" TLS_LIBRARY "TLS INFO] : " << x << "\n"
  #define TLS_LOG_ERROR(x) std::cout << "[" TLS_LIBRARY "TLS ERROR] : " << x << "\n";ERR_print_errors_fp(stderr)
  #else
  #define TLS_LOG_INFO(x)
  #define TLS_LOG_ERROR(x)

#endif
