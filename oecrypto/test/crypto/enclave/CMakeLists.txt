# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

add_subdirectory(host)
add_enclave_test(test/crypto/enclave cryptohost cryptoenc)
