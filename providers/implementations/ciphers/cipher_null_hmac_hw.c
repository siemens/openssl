/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* null_hmac cipher implementation */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cipher_null_hmac.h"

static int null_hmac_initkey(PROV_CIPHER_CTX *bctx, const uint8_t *key,
                             size_t keylen)
{
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)bctx;

    if (key == NULL || keylen > sizeof(ctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(ctx->key, key, keylen);
    return 1;
}

static int null_hmac_initiv(PROV_CIPHER_CTX *bctx,
                            const unsigned char *iv, size_t ivlen)
{
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)bctx;

    if (iv == NULL || ivlen > NULL_HMAC_MAX_IVLEN) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!HMAC_Init_ex(ctx->hmac, ctx->key, ctx->base.keylen,
                      ossl_prov_digest_md(&ctx->md), NULL))
        return 0;

    return HMAC_Update(ctx->hmac, iv, ivlen);
}

static int null_hmac_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
                            const unsigned char *in, size_t inl)
{
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)bctx;
    unsigned char ltag[NULL_HMAC_MAX_TAGLEN];
    unsigned int ltag_len = 0;

    if (in != NULL) {
        if (!HMAC_Update(ctx->hmac, in, inl))
            return 0;
    } else {
        if (!HMAC_Final(ctx->hmac,
                        bctx->enc ? ctx->tag : ltag,
                        bctx->enc ? &ctx->tag_len : &ltag_len))
            return 0;

        if (!bctx->enc) {
            if (ltag_len != ctx->tag_len
                || CRYPTO_memcmp(ltag, ctx->tag, ctx->tag_len) != 0)
                return 0;
        }
    }

    /* Just copying because we don't encrypt or decrypt */
    if (in != NULL && out != NULL && in != out)
        memcpy(out, in, inl);

    return 1;
}

static const PROV_CIPHER_HW_NULL_HMAC null_hmac_hw = {
    { null_hmac_initkey, null_hmac_cipher },
    null_hmac_initiv
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_null_hmac(size_t keybits)
{
    return (PROV_CIPHER_HW *)&null_hmac_hw;
}
