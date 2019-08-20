// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <openenclave/bits/result.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#include <ctype.h>
#include <string.h>
#include "../magic.h"
#include "crl.h"
#include "ec.h"
#include "init.h"
#include "rsa.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

typedef struct _cert
{
    uint64_t magic;
    X509* x509;
} cert_t;

OE_STATIC_ASSERT(sizeof(cert_t) <= sizeof(oe_cert_t));

static void _cert_init(cert_t* impl, X509* x509)
{
    impl->magic = OE_CERT_MAGIC;
    impl->x509 = x509;
}

static bool _cert_is_valid(const cert_t* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->x509;
}

static void _cert_clear(cert_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->x509 = NULL;
    }
}

typedef struct _cert_chain
{
    uint64_t magic;
    STACK_OF(X509) * sk;
} cert_chain_t;

OE_STATIC_ASSERT(sizeof(cert_chain_t) <= sizeof(oe_cert_chain_t));

static void _cert_chain_init(cert_chain_t* impl, STACK_OF(X509) * sk)
{
    impl->magic = OE_CERT_CHAIN_MAGIC;
    impl->sk = sk;
}

static bool _cert_chain_is_valid(const cert_chain_t* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->sk;
}

static void _cert_chain_clear(cert_chain_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->sk = NULL;
    }
}

static STACK_OF(X509) * _read_cert_chain(const char* pem)
{
    STACK_OF(X509)* result = NULL;
    STACK_OF(X509)* sk = NULL;
    BIO* bio = NULL;
    X509* x509 = NULL;

    // Check parameters:
    if (!pem)
        goto done;

    // Create empty X509 stack:
    if (!(sk = sk_X509_new_null()))
        goto done;

    while (*pem)
    {
        const char* end;

        /* The PEM certificate must start with this */
        if (strncmp(
                pem, OE_PEM_BEGIN_CERTIFICATE, OE_PEM_BEGIN_CERTIFICATE_LEN) !=
            0)
            goto done;

        /* Find the end of this PEM certificate */
        {
            if (!(end = strstr(pem, OE_PEM_END_CERTIFICATE)))
                goto done;

            end += OE_PEM_END_CERTIFICATE_LEN;
        }

        /* Skip trailing spaces */
        while (isspace(*end))
            end++;

        /* Create a BIO for this certificate */
        if (!(bio = BIO_new_mem_buf(pem, (int)(end - pem))))
            goto done;

        /* Read BIO into X509 object */
        if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
            goto done;

        // Push certificate onto stack:
        {
            if (!sk_X509_push(sk, x509))
                goto done;

            x509 = NULL;
        }

        // Release the bio:
        BIO_free(bio);
        bio = NULL;

        pem = end;
    }

    result = sk;
    sk = NULL;

done:

    if (bio)
        BIO_free(bio);

    if (sk)
        sk_X509_pop_free(sk, X509_free);

    return result;
}

/* Clone the certificate to clear any verification state */
static X509* _clone_x509(X509* x509)
{
    X509* ret = NULL;
    BIO* out = NULL;
    BIO* in = NULL;
    BUF_MEM* mem;

    if (!x509)
        goto done;

    if (!(out = BIO_new(BIO_s_mem())))
        goto done;

    if (!PEM_write_bio_X509(out, x509))
        goto done;

    if (!BIO_get_mem_ptr(out, &mem))
        goto done;

    if (mem->length > OE_INT_MAX)
        goto done;

    if (!(in = BIO_new_mem_buf(mem->data, (int)mem->length)))
        goto done;

    ret = PEM_read_bio_X509(in, NULL, 0, NULL);

done:

    if (out)
        BIO_free(out);

    if (in)
        BIO_free(in);

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed because some versions of OpenSSL do not support X509_up_ref() */
static int X509_up_ref(X509* x509)
{
    if (!x509)
        return 0;

    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

static const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509* x)
{
    if (!x->cert_info)
    {
        return NULL;
    }
    return x->cert_info->extensions;
}

#endif

static oe_result_t _cert_chain_get_length(const cert_chain_t* impl, int* length)
{
    oe_result_t result = OE_UNEXPECTED;
    int num;

    *length = 0;

    if ((num = sk_X509_num(impl->sk)) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    *length = num;

    result = OE_OK;

done:
    return result;
}

static STACK_OF(X509) * _clone_chain(STACK_OF(X509) * chain)
{
    STACK_OF(X509)* sk = NULL;
    int n = sk_X509_num(chain);

    if (!(sk = sk_X509_new(NULL)))
        return NULL;

    for (int i = 0; i < n; i++)
    {
        X509* x509;

        if (!(x509 = sk_X509_value(chain, (int)i)))
            return NULL;

        if (!(x509 = _clone_x509(x509)))
            return NULL;

        if (!sk_X509_push(sk, x509))
            return NULL;
    }

    return sk;
}

static oe_result_t _verify_cert(
    X509* cert,
    STACK_OF(X509) * chain_,
    const oe_crl_t* const* crls,
    size_t num_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* store = NULL;
    X509* x509 = NULL;
    STACK_OF(X509)* chain = NULL;

    /* Clone the certificate to clear any cached verification state */
    if (!(x509 = _clone_x509(cert)))
        OE_RAISE_MSG(OE_FAILURE, "Failed to clone X509 cert", NULL);

    /* Clone the chain to clear any cached verification state */
    if (chain_ && !(chain = _clone_chain(chain_)))
        OE_RAISE_MSG(OE_FAILURE, "Failed to clone X509 cert chain", NULL);

    /* Create a store for the verification */
    if (!(store = X509_STORE_new()))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "Failed to allocate X509 store", NULL);

    /* Create a context for verification */
    if (!(ctx = X509_STORE_CTX_new()))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "Failed to create new X509 context", NULL);

    /* Initialize the context that will be used to verify the certificate */
    if (!X509_STORE_CTX_init(ctx, store, NULL, NULL))
    {
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "Failed to initialize X509 context", NULL);
    }

    /* Create a store with CRLs if needed */
    if (crls && num_crls)
    {
        X509_VERIFY_PARAM* verify_param = NULL;

        for (size_t i = 0; i < num_crls; i++)
        {
            crl_t* crl_impl = (crl_t*)crls[i];

            /* X509_STORE_add_crl manages its own addition refcount */
            if (!X509_STORE_add_crl(store, crl_impl->crl))
                OE_RAISE_MSG(
                    OE_CRYPTO_ERROR, "Failed to add CRL to X509 store", NULL);
        }

        /* Get the verify parameter (must not be null) */
        if (!(verify_param = X509_STORE_CTX_get0_param(ctx)))
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR, "Failed to get X509 verify parameter", NULL);

        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK);
        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK_ALL);
    }

    /* Inject the certificate into the verification context */
    X509_STORE_CTX_set_cert(ctx, x509);

    /* Set the CA chain into the verification context */
    if (chain)
        X509_STORE_CTX_trusted_stack(ctx, chain);
    else
        X509_STORE_add_cert(store, x509);

    /* Finally verify the certificate */
    if (!X509_verify_cert(ctx))
    {
        oe_result_t verify_result = OE_VERIFY_FAILED;
        int errorno = X509_STORE_CTX_get_error(ctx);
        switch (errorno)
        {
            case X509_V_ERR_CRL_HAS_EXPIRED:
                verify_result = OE_VERIFY_CRL_EXPIRED;
                break;
            case X509_V_ERR_UNABLE_TO_GET_CRL:
                verify_result = OE_VERIFY_CRL_MISSING;
                break;
            case X509_V_ERR_CERT_REVOKED:
                verify_result = OE_VERIFY_REVOKED;
                break;
        }
        OE_RAISE_MSG(
            verify_result,
            "X509_verify_cert failed!\n"
            " error: (%d) %s\n",
            errorno,
            X509_verify_cert_error_string(errorno));
    }

    result = OE_OK;

done:

    if (x509)
        X509_free(x509);

    if (chain)
        sk_X509_pop_free(chain, X509_free);

    if (store)
        X509_STORE_free(store);

    if (ctx)
        X509_STORE_CTX_free(ctx);

    return result;
}

// Find the last certificate in the chain and then verify that it's a
// self-signed certificate (a root certificate).
static X509* _find_root_cert(STACK_OF(X509) * chain)
{
    int n = sk_X509_num(chain);
    X509* x509;

    /* Get the last certificate in the list */
    if (!(x509 = sk_X509_value(chain, n - 1)))
        return NULL;

    /* If the last certificate is not self-signed, then fail */
    {
        const X509_NAME* subject = X509_get_subject_name(x509);
        const X509_NAME* issuer = X509_get_issuer_name(x509);

        if (!subject || !issuer || X509_NAME_cmp(subject, issuer) != 0)
            return NULL;
    }

    /* Return the root certificate */
    return x509;
}

/* Verify each certificate in the chain against its predecessor. */
static oe_result_t _verify_whole_chain(STACK_OF(X509) * chain)
{
    oe_result_t result = OE_UNEXPECTED;
    X509* root;
    STACK_OF(X509)* subchain = NULL;
    int n;

    if (!chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the root certificate */
    if (!(root = _find_root_cert(chain)))
        OE_RAISE(OE_VERIFY_FAILED);

    /* Get number of certificates in the chain */
    n = sk_X509_num(chain);

    /* If chain is empty */
    if (n < 1)
        OE_RAISE(OE_FAILURE);

    /* Create a subchain that grows to include the whole chain */
    if (!(subchain = sk_X509_new_null()))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Add the root certificate to the subchain */
    {
        X509_up_ref(root);

        if (!sk_X509_push(subchain, root))
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Verify each certificate in the chain against the subchain */
    for (int i = sk_X509_num(chain) - 1; i >= 0; i--)
    {
        X509* cert = sk_X509_value(chain, i);

        if (!cert)
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Verify cert chain without CRL checks */
        OE_CHECK(_verify_cert(cert, subchain, NULL, 0));

        /* Add this certificate to the subchain */
        {
            X509_up_ref(cert);

            if (!sk_X509_push(subchain, cert))
                OE_RAISE(OE_CRYPTO_ERROR);
        }
    }

    result = OE_OK;

done:

    if (subchain)
        sk_X509_pop_free(subchain, X509_free);

    return result;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    BIO* bio = NULL;
    X509* x509 = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pem_data, (int)pem_size)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Convert the PEM BIO into a certificate object */
    if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    _cert_init(impl, x509);
    x509 = NULL;

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    if (x509)
        X509_free(x509);

    return result;
}

oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    X509* x509 = NULL;
    unsigned char* p = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!der_data || !der_size || der_size > OE_INT_MAX || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    p = (unsigned char*)der_data;

    /* Convert the PEM BIO into a certificate object */
    if (!(x509 = d2i_X509(NULL, (const unsigned char**)&p, (int)der_size)))
        OE_RAISE(OE_FAILURE);

    _cert_init(impl, x509);
    x509 = NULL;

    result = OE_OK;

done:

    X509_free(x509);

    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;

    /* Check parameters */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    X509_free(impl->x509);
    _cert_clear(impl);

    result = OE_OK;

done:
    return result;
}

/**
 * Compare issue dates (not before dates) of two certs.
 * Returns
 *      0 if c1 and c2 were issued at the same time
 *      1 if c1 was issued before c2
 *     -1 if c1 was issued after c2
 */
static int _cert_issue_date_compare(
    const X509* const* c1,
    const X509* const* c2)
{
    ASN1_TIME* issue_date_c1 = X509_get_notBefore(*c1);
    ASN1_TIME* issue_date_c2 = X509_get_notBefore(*c2);

    int pday = 0;
    int psec = 0;
    // Get days and seconds elapsed after issue of c1 till issue of c2.
    ASN1_TIME_diff(&pday, &psec, issue_date_c1, issue_date_c2);

    // Use days elapsed first.
    if (pday != 0)
        return pday;
    return psec;
}

/**
 * Reorder the cert chain to be leaf->intermeditate->root.
 * This order simplifies cert validation.
 * The preferred order is also the reverse chronological order of issue dates.
 */
static void _sort_certs_by_issue_date(STACK_OF(X509) * chain)
{
    sk_X509_set_cmp_func(chain, _cert_issue_date_compare);
    sk_X509_sort(chain);
}

oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;
    STACK_OF(X509)* sk = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        memset(impl, 0, sizeof(cert_chain_t));

    /* Check parameters */
    if (!pem_data || !pem_size || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Read the certificate chain into memory */
    if (!(sk = _read_cert_chain((const char*)pem_data)))
        OE_RAISE(OE_FAILURE);

    /* Reorder certs in the chain to preferred order */
    _sort_certs_by_issue_date(sk);

    /* Verify the whole certificate chain */
    OE_CHECK(_verify_whole_chain(sk));

    _cert_chain_init(impl, sk);

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;

    /* Check the parameter */
    if (!_cert_chain_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the stack of certificates */
    sk_X509_pop_free(impl->sk, X509_free);

    /* Clear the implementation */
    _cert_chain_clear(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* cert_impl = (cert_t*)cert;
    cert_chain_t* chain_impl = (cert_chain_t*)chain;

    /* Check for invalid cert parameter */
    if (!_cert_is_valid(cert_impl))
    {
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid cert parameter", NULL);
    }

    /* Check for invalid chain parameter */
    if (chain && !_cert_chain_is_valid(chain_impl))
    {
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid chain parameter", NULL);
    }

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Verify the certificate */
    OE_CHECK(_verify_cert(
        cert_impl->x509,
        (chain_impl != NULL ? chain_impl->sk : NULL),
        crls,
        num_crls));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key (increments reference count) */
    if (!(pkey = X509_get_pubkey(impl->x509)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Get RSA public key (increments reference count) */
    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* Initialize the RSA public key */
    oe_rsa_public_key_init(public_key, pkey);
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
    {
        /* Decrement reference count (incremented above) */
        EVP_PKEY_free(pkey);
    }

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    EVP_PKEY* pkey = NULL;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key (increments reference count) */
    if (!(pkey = X509_get_pubkey(impl->x509)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* If this is not an EC key */
    {
        EC_KEY* ec;

        if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
            OE_RAISE_NO_TRACE(OE_CRYPTO_ERROR);

        EC_KEY_free(ec);
    }

    /* Initialize the EC public key */
    oe_ec_public_key_init(public_key, pkey);
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
    {
        /* Decrement reference count (incremented above) */
        EVP_PKEY_free(pkey);
    }

    return result;
}

oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the number of certificates in the chain */
    {
        int n;
        OE_CHECK(_cert_chain_get_length(impl, &n));
        *length = (size_t)n;
    }

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;
    size_t length;
    X509* x509 = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        memset(cert, 0, sizeof(oe_cert_t));

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the length of the certificate chain */
    {
        int n;
        OE_CHECK(_cert_chain_get_length(impl, &n));
        length = (size_t)n;
    }

    /* Check for out of bounds */
    if (index >= length)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Check for overflow when converting to int */
    if (index >= OE_INT_MAX)
        OE_RAISE(OE_INTEGER_OVERFLOW);

    /* Get the certificate with the given index */
    if (!(x509 = sk_X509_value(impl->sk, (int)index)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Increment the reference count and initialize the output certificate */
    if (!X509_up_ref(x509))
        OE_RAISE(OE_CRYPTO_ERROR);
    _cert_init((cert_t*)cert, x509);

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    const STACK_OF(X509_EXTENSION) * extensions;
    int num_extensions;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set a pointer to the stack of extensions (possibly NULL) */
    if (!(extensions = X509_get0_extensions(impl->x509)))
        OE_RAISE(OE_NOT_FOUND);

    /* Get the number of extensions (possibly zero) */
    num_extensions = sk_X509_EXTENSION_num(extensions);

    /* Find the certificate with this OID */
    for (int i = 0; i < num_extensions; i++)
    {
        X509_EXTENSION* ext;
        ASN1_OBJECT* obj;
        oe_oid_string_t ext_oid;

        /* Get the i-th extension from the stack */
        if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Get the OID */
        if (!(obj = X509_EXTENSION_get_object(ext)))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Get the string name of the OID */
        if (!OBJ_obj2txt(ext_oid.buf, sizeof(ext_oid.buf), obj, 1))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* If found then get the data */
        if (strcmp(ext_oid.buf, oid) == 0)
        {
            ASN1_OCTET_STRING* str;

            /* Get the data from the extension */
            if (!(str = X509_EXTENSION_get_data(ext)))
                OE_RAISE(OE_CRYPTO_ERROR);

            /* If the caller's buffer is too small, raise error */
            if ((size_t)str->length > *size)
            {
                *size = (size_t)str->length;
                OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
            }

            if (data)
            {
                OE_CHECK(
                    oe_memcpy_s(data, *size, str->data, (size_t)str->length));
                *size = (size_t)str->length;
                result = OE_OK;
                goto done;
            }
        }
    }

    result = OE_NOT_FOUND;

done:
    return result;
}

/* Parse the name string into X509_NAME struct. E.g. name_s = "C=UK,O=ARM,CN=mbed TLS Server 1", split and add each entry into name. */
int _X509_parse_name(X509_NAME* name, const char* name_s) {
    char* key = NULL;
    char* val = NULL;
    char* name_s_cpy = strdup(name_s);

    if (!name_s_cpy) 
        return 0;

    key = strsep(&name_s_cpy, "=");
    while (key != NULL) {
        val = strsep(&name_s_cpy, ",");

        if (!val)
            return 0;

        X509_NAME_add_entry_by_txt(name, key,  MBSTRING_ASC, (unsigned char *) val, -1, -1, 0);

        key = strsep(&name_s_cpy, "=");
    }

    return 1;
}

/* mbedTLS takes hex (encoded) form of oid for extension creation, but OpenSSL takes strings.
 * The function decodes the oid in hex format into its string format.*/
char* _decode_oid_to_str(char* oid, int oid_size) {
    char byt;
    char* oid_str;
    char oid_str_buf[101];
    char num_str_buf[21];
    int hi = 0, i = 0;
    int num = 0;

    // First part
    byt = oid[hi++];
    oid_str_buf[i++] = '0' + byt / 40;
    oid_str_buf[i++] = '.';
    oid_str_buf[i++] = '0' + byt % 40;

    // Other parts - variable length decoding
    while (hi < oid_size) {
        num = 0;
        byt = oid[hi++] & 0xff;
        while ((byt & (1 << 8)) >> 8) {     // if highest bit is one, there are following bytes
            byt = byt & 0b1111111;          // remove highest bit
            num = (num + byt) << 7;         // add up
            byt = oid[hi++];
            if (hi >= oid_size)             // byte encoding incorrect
                return NULL;
        }
        num += byt;

        oid_str_buf[i++] = '.';
        snprintf(num_str_buf, sizeof(num_str_buf), "%d", num);
        if (i + strlen(num_str_buf) > 100) // string too long
            return NULL;

        strcpy(oid_str_buf + i, num_str_buf); 
        i += strlen(num_str_buf);
    }
    oid_str_buf[i] = 0;

    // Copy from buffer
    oid_str = (char*) malloc((i + 1) * sizeof(char));
    if (oid_str == NULL) // malloc failed
        return NULL;
    strcpy(oid_str, oid_str_buf);

    return oid_str;
}

oe_result_t oe_gen_custom_x509_cert(
    oe_cert_config_t* config,
    unsigned char* cert_buf,
    size_t cert_buf_size,
    size_t* bytes_written)
{
    oe_result_t result = OE_CRYPTO_ERROR;
    int ret = 0;

    unsigned char* buff = NULL;
    unsigned char* p = NULL;
    X509* x509cert = NULL;
    BIO* bio = NULL;
    X509_NAME* name = NULL;
    EVP_PKEY* subject_issuer_key_pair = NULL;
    X509_EXTENSION* ex = NULL;
    ASN1_OBJECT* obj = NULL;
    ASN1_OCTET_STRING* data = NULL;
    BASIC_CONSTRAINTS* bc = NULL;
    unsigned char* str = NULL;
    char* txt = NULL;
    char date_str[16];
    int len = 0;

    x509cert = X509_new();
    subject_issuer_key_pair = EVP_PKEY_new();

    // Allocate buffer for certificate
    if ((buff = malloc(cert_buf_size)) == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Set certificate info */

    // Parse public key
    bio = BIO_new_mem_buf((const void*) config->public_key_buf, config->public_key_buf_size);
    if (bio == NULL)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bio = NULL");

    if (!PEM_read_bio_PUBKEY(bio, &subject_issuer_key_pair, NULL, NULL))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "subject_key read failed");

    OE_TRACE_VERBOSE(
        "custom_x509_cert: key type:%d", EVP_PKEY_base_id(subject_issuer_key_pair));

    BIO_free(bio);
    bio = NULL;

    // Parse private key
    bio = BIO_new_mem_buf((const void*) config->private_key_buf, config->private_key_buf_size);
    if (bio == NULL)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bio = NULL");

    if (!PEM_read_bio_PrivateKey(bio, &subject_issuer_key_pair, NULL, NULL))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "issuer_key read failed");
 
    BIO_free(bio);
    bio = NULL;

    // Set version
    ret = X509_set_version(x509cert, 2); // version 3
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set version failed");

    // Set key
    ret = X509_set_pubkey(x509cert, subject_issuer_key_pair);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set pubkey failed");

    // Set subject name
    name = X509_get_subject_name(x509cert);
    ret = _X509_parse_name(name, (const char*) config->subject_name);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set subject name failed");

    // Set issuer name
    name = X509_get_issuer_name(x509cert);
    ret = _X509_parse_name(name, (const char*) config->issuer_name);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set issuer name failed");

    // Set serial number
    ret = ASN1_INTEGER_set(X509_get_serialNumber(x509cert), 1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set serial number failed");

    // Set vadility date
    strcpy(date_str, config->date_not_valid_before);
    strcat(date_str, "Z");
    ret = ASN1_TIME_set_string(X509_getm_notBefore(x509cert), date_str);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set validity date not before failed");

    strcpy(date_str, config->date_not_valid_after);
    strcat(date_str, "Z");
    ret = ASN1_TIME_set_string(X509_getm_notAfter(x509cert), date_str);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set validity date not after failed");

    /* Set extensions */
    data = ASN1_OCTET_STRING_new();

    // Set basic constraints
    bc = BASIC_CONSTRAINTS_new();
    bc->ca = false;
    bc->pathlen = 0;

    len = i2d_BASIC_CONSTRAINTS(bc, &str);
    if (len < 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "i2d basic constraint failed");

    ret = ASN1_OCTET_STRING_set(data, str, len);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set octet string (%s) failed", str);

    if (!X509_EXTENSION_create_by_NID(&ex, NID_basic_constraints, 0, data))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "create basic constraint extension failed");

    ret = X509_add_ext(x509cert, ex, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add basic constraint extension failed");

    // SKI & AKI are not needed when CA = false

    // Set custom extension
    ret = ASN1_OCTET_STRING_set(data, (char*) config->ext_data_buf, config->ext_data_buf_size);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set octet string failed");

    txt = _decode_oid_to_str((char*) config->ext_oid, config->ext_oid_size);
    if (!txt) {
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "decode oid failed");
    }

    obj = OBJ_txt2obj(txt, 1);
    if (!obj)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "create custom extension obj failed");

    if (!X509_EXTENSION_create_by_OBJ(&ex, obj, 0, data))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "create custom extension failed");

    ret = X509_add_ext(x509cert, ex, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add custom extension failed");

    /* Write certificate data */

    // Sign the certificate
    if (!X509_sign(x509cert, subject_issuer_key_pair, EVP_sha256()))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "sign cert failed");

    // Write to DER
    // The use of temporary variable is mandatory.
    // If p is not NULL is writes the DER encoded data to the buffer at *p, and increments it to point after the data just written.
    p = buff;
    *bytes_written = (size_t) i2d_X509(x509cert, &p);
    if (*bytes_written <= 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bytes_written = 0x%x ", (unsigned int) *bytes_written);

    // Copy DER data to buffer
    OE_CHECK(oe_memcpy_s(
        (void*) cert_buf,
        cert_buf_size,
        (const void*) buff,
        *bytes_written));
    OE_TRACE_VERBOSE("bytes_written = 0x%x", (unsigned int) *bytes_written);

    result = OE_OK;
done:
    X509_free(x509cert);
    X509_EXTENSION_free(ex);
    if (bio != NULL)
        BIO_free(bio);
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(data);
    BASIC_CONSTRAINTS_free(bc);
    EVP_PKEY_free(subject_issuer_key_pair);
    free(buff);
    if (!txt)
        free(txt);
    if (!ret)
        result = OE_CRYPTO_ERROR;

    return result;
}
