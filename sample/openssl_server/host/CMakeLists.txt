# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT openssl_server_u.h openssl_server_u.c openssl_server_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/openssl_server.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/openssl_server.edl)

add_executable(openssl_server_host host.c ${CMAKE_CURRENT_BINARY_DIR}/openssl_server_u.c)

target_include_directories(openssl_server_host PRIVATE
  # Needed for the generated file openssl_server_u.h
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(openssl_server_host openenclave::oehostapp)
