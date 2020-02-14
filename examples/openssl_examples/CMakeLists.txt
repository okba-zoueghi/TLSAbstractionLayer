set(INC_DIR "../../include/")

if(NOT DEFINED OPENSSL_LIB_DIR)
  message( FATAL_ERROR "OPENSSL_LIB_DIR is undefined. Define it and retry!" )
endif()

if(NOT DEFINED TLSAbstractionLayer_LIB_DIR)
  message( FATAL_ERROR "TLSAbstractionLayer_LIB_DIR is undefined. Define it and retry!" )
endif()

file(GLOB SOURCES
  "*.cpp"
)

include_directories(
	${INC_DIR}
)

link_directories(
  ${OPENSSL_LIB_DIR}
  ${TLSAbstractionLayer_LIB_DIR}
)

foreach(srcfile ${SOURCES})
  string(REGEX REPLACE ".*/" "" src_name ${srcfile})
  string(REPLACE ".cpp" "" executable_name ${src_name})
  add_executable(${executable_name} ${srcfile})
  target_link_libraries(${executable_name} tlsabstractionlayer crypto ssl)
endforeach()
