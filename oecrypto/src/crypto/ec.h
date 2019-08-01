// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_EC_H
#define _OE_HOST_CRYPTO_EC_H

#include <openssl/evp.h>

#include <oecrypto/internal/ec.h>

/* Caller is responsible for validating parameters */
void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey);

void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey);

#endif /* _OE_HOST_CRYPTO_EC_H */