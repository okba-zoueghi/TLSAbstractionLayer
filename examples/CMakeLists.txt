set(INC_DIR "../include/")

# use the default library in libs if no environment variable is defined

if(NOT DEFINED OPENSSL_LIB_DIR)
  set(OPENSSL_LIB_DIR "../../libs/openssl/")
endif()

# use the default library in libs if no environment variable is defined

if(NOT DEFINED WOLFSSL_LIB_DIR)
  set(WOLFSSL_LIB_DIR "../../libs/wolfssl/")
endif()

set(TLSAbstractionLayer_LIB_DIR "../../build/")

file(GLOB SOURCES
  "*.cpp"
)

include_directories(
	${INC_DIR}
)

link_directories(
  ${OPENSSL_LIB_DIR}
  ${WOLFSSL_LIB_DIR}
  ${TLSAbstractionLayer_LIB_DIR}
)

foreach(srcfile ${SOURCES})
  string(REGEX REPLACE ".*/" "" src_name ${srcfile})
  string(REPLACE ".cpp" "" executable_name ${src_name})
  add_executable(${executable_name} ${srcfile})
  target_link_libraries(${executable_name} tlsabstractionlayer ssl crypto wolfssl)
endforeach()
