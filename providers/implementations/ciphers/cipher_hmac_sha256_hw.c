/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* hmac_sha256 cipher implementation */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cipher_hmac_sha256.h"

static int hmac_sha256_initkey(PROV_CIPHER_CTX *bctx, const uint8_t *key,
                               size_t keylen)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;

    if (key != NULL && keylen <= HMAC_SHA256_KEYLEN) {
        memcpy(ctx->key, key, keylen);
        ctx->keylen = keylen;
    }

    return 1;
}

static int hmac_sha256_initiv(PROV_CIPHER_CTX *bctx,
                              const unsigned char *iv, size_t ivlen)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;

    if (iv == NULL || ivlen != HMAC_SHA256_IVLEN)
        return 0;
    if (!HMAC_Init_ex(ctx->hmac, ctx->key, ctx->keylen, ctx->evp_md, NULL))
        return 0;
    if (!HMAC_Update(ctx->hmac, iv, ivlen))
        return 0;

    return 1;
}

static int hmac_sha256_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
                              const unsigned char *in, size_t inl)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;
    unsigned char ltag[HMAC_SHA256_TAGLEN];
    unsigned int ltag_len;

    if (in != NULL) {
        if (!HMAC_Update(ctx->hmac, in, inl))
            return 0;
    } else {
        if (!HMAC_Final(ctx->hmac,
                        bctx->enc ? ctx->tag : ltag,
                        bctx->enc ? &ctx->tag_len : &ltag_len))
            return 0;

        if (!bctx->enc) {
            if (CRYPTO_memcmp(ltag, ctx->tag, ctx->tag_len))
                return 0;
        }
    }
    return 1;
}

static const PROV_CIPHER_HW_HMAC_SHA256 hmac_sha256_hw = {
    { hmac_sha256_initkey, hmac_sha256_cipher },
    hmac_sha256_initiv
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_hmac_sha256(size_t keybits)
{
    return (PROV_CIPHER_HW *)&hmac_sha256_hw;
}
