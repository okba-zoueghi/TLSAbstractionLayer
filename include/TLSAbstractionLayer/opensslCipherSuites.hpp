#ifndef CipherSuites_H
#define CipherSuites_H

namespace TLSAbstractionLayer
{

/* TLS V 1.1 Cipher Suites */

const char * const  TLS_RSA_WITH_AES_128_CBC_SHA = "AES128-SHA";
const char * const  TLS_RSA_WITH_AES_256_CBC_SHA = "AES256-SHA";

const char * const  TLS_DH_DSS_WITH_AES_128_CBC_SHA = "DH-DSS-AES128-SHA";
const char * const  TLS_DH_DSS_WITH_AES_256_CBC_SHA = "DH-DSS-AES256-SHA";
const char * const  TLS_DH_RSA_WITH_AES_128_CBC_SHA = "DH-RSA-AES128-SHA";
const char * const  TLS_DH_RSA_WITH_AES_256_CBC_SHA = "DH-RSA-AES256-SHA";

const char * const  TLS_DHE_DSS_WITH_AES_128_CBC_SHA = "DHE-DSS-AES128-SHA";
const char * const  TLS_DHE_DSS_WITH_AES_256_CBC_SHA = "DHE-DSS-AES256-SHA";
const char * const  TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "DHE-RSA-AES128-SHA";
const char * const  TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "DHE-RSA-AES256-SHA";

const char * const  TLS_DH_anon_WITH_AES_128_CBC_SHA = "ADH-AES128-SHA";
const char * const  TLS_DH_anon_WITH_AES_256_CBC_SHA = "ADH-AES256-SHA";

/* TLS V 1.2 Cipher Suites */

const char * const  TLS_RSA_WITH_NULL_SHA256 = "NULL-SHA256";

const char * const  TLS_RSA_WITH_AES_128_CBC_SHA256 = "AES128-SHA256";
const char * const  TLS_RSA_WITH_AES_256_CBC_SHA256 = "AES256-SHA256";
const char * const  TLS_RSA_WITH_AES_128_GCM_SHA256 = "AES128-GCM-SHA256";
const char * const  TLS_RSA_WITH_AES_256_GCM_SHA384 = "AES256-GCM-SHA384";

const char * const  TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = "DH-RSA-AES128-SHA256";
const char * const  TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = "DH-RSA-AES256-SHA256";
const char * const  TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = "DH-RSA-AES128-GCM-SHA256";
const char * const  TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = "DH-RSA-AES256-GCM-SHA384";

const char * const  TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = "DH-DSS-AES128-SHA256";
const char * const  TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = "DH-DSS-AES256-SHA256";
const char * const  TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = "DH-DSS-AES128-GCM-SHA256";
const char * const  TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = "DH-DSS-AES256-GCM-SHA384";

const char * const  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = "DHE-RSA-AES128-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = "DHE-RSA-AES256-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = "DHE-RSA-AES128-GCM-SHA256";
const char * const  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = "DHE-RSA-AES256-GCM-SHA384";

const char * const  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = "DHE-DSS-AES128-SHA256";
const char * const  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = "DHE-DSS-AES256-SHA256";
const char * const  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = "DHE-DSS-AES128-GCM-SHA256";
const char * const  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = "DHE-DSS-AES256-GCM-SHA384";

const char * const  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = "ECDHE-RSA-AES128-SHA256";
const char * const  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = "ECDHE-RSA-AES256-SHA384";
const char * const  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "ECDHE-RSA-AES128-GCM-SHA256";
const char * const  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "ECDHE-RSA-AES256-GCM-SHA384";

const char * const  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = "ECDHE-ECDSA-AES128-SHA256";
const char * const  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = "ECDHE-ECDSA-AES256-SHA384";
const char * const  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = "ECDHE-ECDSA-AES128-GCM-SHA256";
const char * const  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = "ECDHE-ECDSA-AES256-GCM-SHA384";

const char * const  TLS_DH_anon_WITH_AES_128_CBC_SHA256 = "ADH-AES128-SHA256";
const char * const  TLS_DH_anon_WITH_AES_256_CBC_SHA256 = "ADH-AES256-SHA256";
const char * const  TLS_DH_anon_WITH_AES_128_GCM_SHA256 = "ADH-AES128-GCM-SHA256";
const char * const  TLS_DH_anon_WITH_AES_256_GCM_SHA384 = "ADH-AES256-GCM-SHA384";

const char * const  RSA_WITH_AES_128_CCM = "AES128-CCM";
const char * const  RSA_WITH_AES_256_CCM = "AES256-CCM";
const char * const  DHE_RSA_WITH_AES_128_CCM = "DHE-RSA-AES128-CCM";
const char * const  DHE_RSA_WITH_AES_256_CCM = "DHE-RSA-AES256-CCM";
const char * const  RSA_WITH_AES_128_CCM_8 = "AES128-CCM8";
const char * const  RSA_WITH_AES_256_CCM_8 = "AES256-CCM8";
const char * const  DHE_RSA_WITH_AES_128_CCM_8 = "DHE-RSA-AES128-CCM8";
const char * const  DHE_RSA_WITH_AES_256_CCM_8 = "DHE-RSA-AES256-CCM8";
const char * const  ECDHE_ECDSA_WITH_AES_128_CCM = "ECDHE-ECDSA-AES128-CCM";
const char * const  ECDHE_ECDSA_WITH_AES_256_CCM = "ECDHE-ECDSA-AES256-CCM";
const char * const  ECDHE_ECDSA_WITH_AES_128_CCM_8 = "ECDHE-ECDSA-AES128-CCM8";
const char * const  ECDHE_ECDSA_WITH_AES_256_CCM_8 = "ECDHE-ECDSA-AES256-CCM8";

/* TLS V 1.3 Cipher Suites */

const char * const  TLS_AES_128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256";
const char * const  TLS_AES_256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384";
const char * const  TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256";
const char * const  TLS_AES_128_CCM_SHA256 = "TLS_AES_128_CCM_SHA256";
const char * const  TLS_AES_128_CCM_8_SHA256 = "TLS_AES_128_CCM_8_SHA256";

}

#endif
