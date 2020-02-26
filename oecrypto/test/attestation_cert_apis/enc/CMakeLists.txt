# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../tls.edl enclave gen)

add_executable(tls_enc enc.cpp ${gen})

target_include_directories(tls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OEOpenSSL_INCLUDEDIR} ${OE_INTERNAL_INCLUDEDIR})
target_link_libraries(tls_enc PUBLIC openenclave::oeenclave oecrypto ${OEOpenSSL_LDFLAGS})
