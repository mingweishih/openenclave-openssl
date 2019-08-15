# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)
set(CMAKE_CXX_STANDARD 11)
project("Attested TLS sample" LANGUAGES C CXX)

# Find packages
find_package(OpenEnclave CONFIG REQUIRED)
find_package(OECrypto CONFIG REQUIRED)
find_package(PkgConfig)
pkg_check_modules(OEOpenSSL openssl_oe_enclave)

# Link OpenEnclave enclave target with oecrypto library
set(oeenclave-openssl openenclave::oeenclave oecrypto::oecrypto)

# Add subdirectories
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(non_enc_client)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(run
    DEPENDS tls_server tls_client tls_non_enc_client tls_client_enc tls_server_enc
    COMMENT "Launch processes to establish an Attested TLS between two enclaves"
    COMMAND ${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12341 &
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/client/host/tls_client_host ${CMAKE_BINARY_DIR}/client/enc/tls_client_enc.signed -server:localhost -port:12341
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMENT "Launch processes to establish an Attested TLS between an non-encalve TLS client and an TLS server running inside an enclave "
    COMMAND ${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12341 &
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/non_enc_client/tls_non_enc_client -server:localhost -port:12341)
endif ()
