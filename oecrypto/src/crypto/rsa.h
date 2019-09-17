// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_OPENSSL_RSA_H
#define _OE_ENCLAVE_CRYPTO_OPENSSL_RSA_H

#include <openssl/evp.h>

#include <openenclave/internal/rsa.h>

/* Caller is responsible for validating parameters */
void oe_rsa_public_key_init(oe_rsa_public_key_t* public_key, EVP_PKEY* pkey);

#endif /* _OE_ENCLAVE_CRYPTO_OPENSSL_RSA_H */
