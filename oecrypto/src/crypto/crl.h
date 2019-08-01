// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_CRL_H
#define _OE_HOST_CRYPTO_CRL_H

#include <openssl/x509.h>

#include <oecrypto/internal/crypto/crl.h>

typedef struct _crl
{
    uint64_t magic;
    X509_CRL* crl;
} crl_t;

bool crl_is_valid(const crl_t* impl);

#endif /* _OE_HOST_CRYPTO_CRL_H */
