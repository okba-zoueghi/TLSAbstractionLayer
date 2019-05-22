project(TLSAbstractionLayer)

if( "FALSE" STREQUAL "${USE_OPENSSL}")
  set(OPENSSL_SRC_FILES "")
else()
  set(OPENSSL_SRC_FILES "${PROJECT_SOURCE_DIR}/src/OpenSSLSecureEndPoint/*.cpp")
endif()

if( "FALSE" STREQUAL "${USE_WOLFSSL}")
  set(WOLFSSL_SRC_FILES "")
else()
  set(WOLFSSL_SRC_FILES "${PROJECT_SOURCE_DIR}/src/WolfSSLSecureEndPoint/*.cpp")
endif()

file(GLOB SOURCES
  "${PROJECT_SOURCE_DIR}/src/SecureEndPoint/*.cpp"
  "${OPENSSL_SRC_FILES}"
  "${WOLFSSL_SRC_FILES}"
)

include_directories(
	${PROJECT_SOURCE_DIR}/include/
)

add_library(sharedlib SHARED ${SOURCES})
add_library(staticlib STATIC ${SOURCES})

set_target_properties(sharedlib PROPERTIES OUTPUT_NAME tlsabstractionlayer)
set_target_properties(staticlib PROPERTIES OUTPUT_NAME tlsabstractionlayer)
