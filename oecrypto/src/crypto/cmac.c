// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/evp.h>
#include <openssl/cmac.h>

#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

oe_result_t oe_aes_cmac_sign(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* message,
    size_t message_length,
    oe_aes_cmac_t* aes_cmac)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t key_size_bits = key_size * 8;
    size_t final_size = sizeof(oe_aes_cmac_t);

    if (aes_cmac == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key_size_bits != 128)
        OE_RAISE(OE_UNSUPPORTED);

    oe_secure_zero_fill(aes_cmac->impl, sizeof(*aes_cmac));

    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, key_size, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, message, message_length);
    CMAC_Final(ctx, (unsigned char*)aes_cmac->impl, &final_size);

    result = OE_OK;

done:
    return result;
}
