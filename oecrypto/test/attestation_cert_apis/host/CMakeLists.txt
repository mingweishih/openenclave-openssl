# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../tls.edl host gen)

add_executable(tls_host host.cpp ${gen})

target_include_directories(tls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INTERNAL_INCLUDEDIR})
target_link_libraries(tls_host openenclave::oehostapp)
