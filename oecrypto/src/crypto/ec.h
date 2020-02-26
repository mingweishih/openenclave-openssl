// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_EC_H
#define _OE_ENCLAVE_CRYPTO_EC_H

#include <openssl/evp.h>

#include <openenclave/internal/crypto/ec.h>

/* Caller is responsible for validating parameters */
// needed in oe_cert_get_ec_public_key in cert.c
void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey);

void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey);

#endif /* _OE_ENCLAVE_CRYPTO_EC_H */
