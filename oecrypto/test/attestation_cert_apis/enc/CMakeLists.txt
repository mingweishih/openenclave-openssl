# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../tls.edl enclave gen)

add_executable(tls_enc enc.cpp ${gen})

target_include_directories(tls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OEOpenSSL_INCLUDE_DIR})
target_link_libraries(tls_enc PUBLIC openenclave::oeenclave oecrypto openenclave::oelibc -L${OEOpenSSL_LIB_DIR} -lssl -lcrypto)
