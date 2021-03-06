// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/rand.h>

#include <openenclave/internal/random.h>

oe_result_t oe_random_internal(void* data, size_t size)
{
    if (size > OE_INT_MAX)
        return OE_INVALID_PARAMETER;

    if (!RAND_bytes(data, (int)size))
        return OE_CRYPTO_ERROR;

    return OE_OK;
}
