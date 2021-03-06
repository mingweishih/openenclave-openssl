# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# OS-specific source files
if (UNIX)
  set(PLATFORM_SRC
    ${OE_SRC_DIR}/common/sgx/rand.S
    ../asn1_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../read_file.c
    ../rsa_tests.c
)
elseif (WIN32)
  set(PLATFORM_SRC
    ${OE_SRC_DIR}/common/sgx/rand.asm)
else()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

add_executable(hostcrypto
    ${PLATFORM_SRC}
    main.c
    ../hash.c
    ../hmac_tests.c
    ../kdf_tests.c
    ../random_tests.c
    ../rdrand_test.c
    ../sha_tests.c
    ../tests.c
    ../utils.c)

add_dependencies(hostcrypto crypto_test_data)
target_include_directories(hostcrypto PRIVATE ${OE_INTERNAL_INCLUDEDIR})
target_link_libraries(hostcrypto openenclave::oehost)
add_test(tests/crypto/host hostcrypto)
