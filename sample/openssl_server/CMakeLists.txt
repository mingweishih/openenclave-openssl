# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)
set(CMAKE_CXX_STANDARD 11)
project("OECrypto Sample" LANGUAGES C CXX)

# Find packages
find_package(OpenEnclave CONFIG REQUIRED)
find_package(OECrypto CONFIG REQUIRED)
find_package(PkgConfig)
pkg_check_modules(OEOpenSSL openssl_oe_enclave)

# Link OpenEnclave enclave target with oecrypto library
set(oeenclave-openssl openenclave::oeenclave oecrypto::oecrypto)

# Add subdirectories
add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

add_custom_command(OUTPUT key.pem cert.pem
  COMMAND openssl genrsa -out key.pem
  COMMAND openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/C=US/ST=Ohio/L=Columbus/O=Acme Company/OU=Acme/CN=Root")

# Sign enclave
add_custom_command(OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/openssl_server.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c ${CMAKE_SOURCE_DIR}/enclave/openssl_server.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed cert.pem)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(run
    DEPENDS openssl_server_host sign
    COMMAND openssl_server_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(simulate
  DEPENDS openssl_server_host sign
  COMMAND openssl_server_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
