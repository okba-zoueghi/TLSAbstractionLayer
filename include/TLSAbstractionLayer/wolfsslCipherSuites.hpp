#ifndef wolfsslCipherSuites_H
#define wolfsslCipherSuites_H

namespace TLSAbstractionLayer
{

/* TLS V 1.1 Cipher Suites */

const char * const  TLS_RSA_WITH_AES_128_CBC_SHA = "AES128-SHA";
const char * const  TLS_RSA_WITH_AES_256_CBC_SHA = "AES256-SHA";
const char * const  TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "DHE-RSA-AES128-SHA";
const char * const  TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "DHE-RSA-AES256-SHA";

/* TLS V 1.2 Cipher Suites */

const char * const  TLS_RSA_WITH_NULL_SHA256 = "NULL-SHA256";

const char * const  TLS_RSA_WITH_AES_128_CBC_SHA256 = "AES128-SHA256";
const char * const  TLS_RSA_WITH_AES_256_CBC_SHA256 = "AES256-SHA256";
const char * const  TLS_RSA_WITH_AES_128_GCM_SHA256 = "AES128-GCM-SHA256";
const char * const  TLS_RSA_WITH_AES_256_GCM_SHA384 = "AES256-GCM-SHA384";

const char * const  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = "DHE-RSA-AES128-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = "DHE-RSA-AES256-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = "DHE-RSA-AES128-GCM-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = "DHE-RSA-AES256-GCM-SHA384";

const char * const  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = "ECDHE-RSA-AES128-SHA256";
const char * const  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = "ECDHE-RSA-AES256-SHA384";
const char * const  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "ECDHE-RSA-AES128-GCM-SHA256";
const char * const  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "ECDHE-RSA-AES256-GCM-SHA384";

}

#endif
