# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT openssl_server_t.h openssl_server_t.c openssl_server_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/openssl_server.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/openssl_server.edl)

add_executable(enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/openssl_server_t.c)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file openssl_server_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OEOpenSSL_INCLUDEDIR})

# Link to openenclave::oeenclave with openssl library
target_link_libraries(enclave PRIVATE ${oeenclave-openssl} openenclave::oelibc openenclave::oehostsock openenclave::oehostfs openenclave::oehostresolver ${OEOpenSSL_LDFLAGS})
