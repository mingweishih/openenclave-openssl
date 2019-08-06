# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../tls.edl host gen)

add_executable(tls_host host.cpp ${gen})

target_include_directories(tls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tls_host oecrypto_includes openenclave::oehostapp)
