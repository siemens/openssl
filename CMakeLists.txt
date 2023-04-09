cmake_minimum_required(VERSION 3.7)

project(cmp)

if(NOT DEFINED CMPOSSL_VERSION)
  set(MAJOR 2)
  set(CMPOSSL_VERSION ${MAJOR}.0.0)
endif()

message(STATUS "CMPforOpenSSL version " ${CMPOSSL_VERSION})

set(CMAKE_VERBOSE_MAKEFILE ON)

if(DEFINED ENV{OPENSSL_DIR})
  set(OpenSSL_INCLUDE_DIRS $ENV{OPENSSL_DIR}/include)
  set(OPENSSL_LIBRARIES $ENV{OPENSSL_DIR}/libssl.so $ENV{OPENSSL_DIR}/libcrypto.so)
  add_definitions(-isystem ${OpenSSL_INCLUDE_DIRS})
else()
  find_package(OpenSSL REQUIRED)
endif()

set(INC_OPENSSL 	${PROJECT_SOURCE_DIR}/include/openssl)
set(INC_INTERNAL	${PROJECT_SOURCE_DIR}/include/internal)
set(LIBCMP_INC 		${PROJECT_SOURCE_DIR}/include/cmp)
set(LIBCMP_INC_OPENSSL  ${LIBCMP_INC}/openssl)
set(LIBCMP_INC_INTERNAL ${LIBCMP_INC}/internal)

set(CMPOSSL_SRC_CMP_DIR  ${PROJECT_SOURCE_DIR}/crypto/cmp)
set(CMPOSSL_SRC_CRMF_DIR ${PROJECT_SOURCE_DIR}/crypto/crmf)
set(CMPOSSL_SRC_HTTP_DIR ${PROJECT_SOURCE_DIR}/crypto/http)

# TODO remove 
file(GLOB INC_OPENSSL_HDRS  "${INC_OPENSSL}/*.h") 
file(MAKE_DIRECTORY ${LIBCMP_INC_OPENSSL}) 
file(COPY ${INC_OPENSSL_HDRS} DESTINATION ${LIBCMP_INC_OPENSSL}) 

file(GLOB INC_INTERNAL_HDRS "${INC_INTERNAL}/*.h")
file(MAKE_DIRECTORY ${LIBCMP_INC_INTERNAL})
file(COPY ${INC_INTERNAL_HDRS} DESTINATION ${LIBCMP_INC_INTERNAL})

set(INC_PUBLIC_HDRS
  ${INC_OPENSSL}/cmp.h
  ${INC_OPENSSL}/cmperr.h
  ${INC_OPENSSL}/cmp_util.h
  ${INC_OPENSSL}/crmf.h
  ${INC_OPENSSL}/crmferr.h
  ${INC_OPENSSL}/cryptoerr_legacy.h
  ${INC_OPENSSL}/safestack_backport.h
  ${INC_OPENSSL}/openssl_backport.h
  ${INC_OPENSSL}/http.h
)

set(CMPOSSL_SRC
  ${CMPOSSL_SRC_CRMF_DIR}/crmf_asn.c
  ${CMPOSSL_SRC_CRMF_DIR}/crmf_err.c
  ${CMPOSSL_SRC_CRMF_DIR}/crmf_lib.c
  ${CMPOSSL_SRC_CRMF_DIR}/crmf_pbm.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_asn.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_ctx.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_err.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_http.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_hdr.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_msg.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_protect.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_client.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_server.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_status.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_vfy.c
  ${CMPOSSL_SRC_CMP_DIR}/cmp_util.c
  ${CMPOSSL_SRC_CMP_DIR}/openssl_backport.c
  ${CMPOSSL_SRC_HTTP_DIR}/http_client.c
  ${CMPOSSL_SRC_HTTP_DIR}/http_err.c
  ${CMPOSSL_SRC_HTTP_DIR}/http_lib.c
)

add_library(${PROJECT_NAME} SHARED ${CMPOSSL_SRC})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
target_include_directories(${PROJECT_NAME} PRIVATE ${LIBCMP_INC})

if(DEFINED ENV{NDEBUG})
  add_definitions(-DNDEBUG=1 -O2)
else()
  add_definitions(-g -O0)
  set(DEBUG_FLAGS -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all)
  add_definitions(${DEBUG_FLAGS})
  link_libraries(${DEBUG_FLAGS})
endif()

target_compile_options(${PROJECT_NAME} PRIVATE
  -include ${LIBCMP_INC}/openssl/openssl_backport.h -DCMP_STANDALONE
  -DDEBUG_UNUSED -DPEDANTIC -pedantic -Wall -Wextra
  -Wswitch -Wsign-compare -Wmissing-prototypes -Wstrict-prototypes
  -Wshadow -Wformat -Wtype-limits -Wundef)

set_target_properties(${PROJECT_NAME} PROPERTIES
  VERSION ${CMPOSSL_VERSION} SOVERSION ${MAJOR}
  PUBLIC_HEADER "${INC_PUBLIC_HDRS}"
)

set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 90)

install(TARGETS ${PROJECT_NAME}
  LIBRARY
    DESTINATION lib
    COMPONENT Library
  PUBLIC_HEADER
    DESTINATION include/openssl
    COMPONENT Development
)
