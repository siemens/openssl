/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "cmp_local.h"
#include "crypto/asn1.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/cmp_util.h>

#define RSAKEM_KEYLENGTH 32

/* using X963KDF without info */
static int kdf2(OSSL_CMP_CTX *ctx,
                unsigned char *secret, size_t secret_len,
                unsigned char *out, int out_len)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[4], *p = params;

    if (out == NULL)
        return 0;

    kdf = EVP_KDF_fetch(ctx->libctx, "X963KDF", ctx->propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                             secret, (size_t)secret_len);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        return 0;
    }
    EVP_KDF_CTX_free(kctx);
    return 1;
}

X509_ALGOR *ossl_cmp_rsakem_algor(OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *kemrsa_algo = NULL;
    OSSL_CMP_RSAKEMPARAMETERS *param = NULL;
    ASN1_STRING *stmp = NULL;

    if ((param = OSSL_CMP_RSAKEMPARAMETERS_new()) == NULL
        || (param->KeyDerivationFunction
            = ossl_cmp_kem_kdf_algor(ctx, NID_id_kdf_kdf2)) == NULL
        || !ASN1_INTEGER_set(param->KeyLength, RSAKEM_KEYLENGTH))
        goto err;

    if (ASN1_item_pack(param, ASN1_ITEM_rptr(OSSL_CMP_RSAKEMPARAMETERS),
                       &stmp) == NULL)
        goto err;
    kemrsa_algo = ossl_X509_ALGOR_from_nid(NID_id_kem_rsa,
                                           V_ASN1_SEQUENCE, stmp);
    if (kemrsa_algo == NULL)
        goto err;
    stmp = NULL;
 err:
    OSSL_CMP_RSAKEMPARAMETERS_free(param);
    ASN1_STRING_free(stmp);
    return kemrsa_algo;
}

int ossl_cmp_kemrsa_decapsulation(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey,
                                  const unsigned char *ct, size_t ct_len,
                                  unsigned char **secret, size_t *secret_len)
{
    int ret = 0;
    size_t sec_len;
    unsigned char *sec;
    EVP_PKEY_CTX *kem_decaps_ctx;

    if (ctx == NULL || pkey == NULL
        || ct == NULL
        || secret == NULL || secret_len == NULL)
        return 0;

    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA)
        return 0;

    kem_decaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                pkey,
                                                ctx->propq);

    if (kem_decaps_ctx == NULL
        || EVP_PKEY_decapsulate_init(kem_decaps_ctx, NULL) <= 0
        || EVP_PKEY_CTX_set_kem_op(kem_decaps_ctx, "RSASVE") <= 0
        || EVP_PKEY_decapsulate(kem_decaps_ctx, NULL, &sec_len,
                                ct, ct_len) <= 0) {
        goto err;
    }

    sec = OPENSSL_malloc(sec_len);
    if (sec == NULL)
        goto err;

    if (EVP_PKEY_decapsulate(kem_decaps_ctx,
                             sec, &sec_len,
                             ct, ct_len) <= 0) {
        OPENSSL_free(sec);
        goto err;
    }

    *secret_len = RSAKEM_KEYLENGTH;
    *secret = OPENSSL_malloc(*secret_len);
    if (*secret == NULL) {
        OPENSSL_clear_free(sec, sec_len);
        goto err;
    }

    if (!kdf2(ctx, sec, sec_len, *secret, *secret_len)) {
        OPENSSL_clear_free(sec, sec_len);
        OPENSSL_clear_free(*secret, *secret_len);
        goto err;
    }
    OPENSSL_clear_free(sec, sec_len);
    ret = 1;
 err:
    EVP_PKEY_CTX_free(kem_decaps_ctx);
    return ret;
}

int ossl_cmp_kemrsa_encapsulation(OSSL_CMP_CTX *ctx,
                                  const EVP_PKEY *pubkey,
                                  size_t *secret_len, unsigned char **secret,
                                  size_t *ct_len, unsigned char **ct)
{
    int ret = 0;
    size_t sec_len;
    unsigned char *sec;
    EVP_PKEY_CTX *kem_encaps_ctx;

    if (ctx == NULL || pubkey == NULL
        || ct == NULL
        || secret == NULL || secret_len == NULL)
        return 0;

    if (EVP_PKEY_get_base_id(pubkey) != EVP_PKEY_RSA)
        return 0;

    kem_encaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                (EVP_PKEY *)pubkey,
                                                ctx->propq);

    if (kem_encaps_ctx == NULL
        || EVP_PKEY_encapsulate_init(kem_encaps_ctx, NULL) <= 0
        || EVP_PKEY_CTX_set_kem_op(kem_encaps_ctx, "RSASVE") <= 0
        || EVP_PKEY_encapsulate(kem_encaps_ctx, NULL, ct_len,
                                NULL, &sec_len) <= 0) {
        goto err;
    }

    *ct = OPENSSL_malloc(*ct_len);
    if (*ct == NULL)
        goto err;

    sec = OPENSSL_malloc(sec_len);
    if (sec == NULL) {
        OPENSSL_free(*ct);
        goto err;
    }

    if (EVP_PKEY_encapsulate(kem_encaps_ctx, *ct, ct_len,
                             sec, &sec_len) <= 0) {
        OPENSSL_free(*ct);
        OPENSSL_free(sec);
        goto err;
    }

    *secret_len = RSAKEM_KEYLENGTH;
    *secret = OPENSSL_malloc(*secret_len);
    if (*secret == NULL) {
        OPENSSL_clear_free(sec, sec_len);
        goto err;
    }

    if (!kdf2(ctx, sec, sec_len, *secret, *secret_len)) {
        OPENSSL_clear_free(sec, sec_len);
        OPENSSL_clear_free(*secret, *secret_len);
        OPENSSL_clear_free(*ct, *ct_len);
        goto err;
    }
    OPENSSL_clear_free(sec, sec_len);
    ret = 1;
 err:
    EVP_PKEY_CTX_free(kem_encaps_ctx);
    return ret;
}
