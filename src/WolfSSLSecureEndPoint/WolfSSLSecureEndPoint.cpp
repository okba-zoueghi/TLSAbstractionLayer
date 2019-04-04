#include <TLSAbstractionLayer/WolfSSLSecureEndPoint.hpp>

#if TLS_DEBUG == 1
#define TLS_LOG_INFO(x) std::cout << "[TLS INFO] : " << x << "\n"
#define TLS_LOG_ERROR(x) std::cout << "[TLS ERROR] : " << x << "\n";
#else
#define TLS_LOG_INFO(x)
#define TLS_LOG_ERROR(x)
#endif

namespace TLSAbstractionLayer {

} /* TLSAbstractionLayer */
