# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
   add_subdirectory(enc)
endif()

add_enclave_test(tests/attestation_cert_api tls_host tls_enc)
