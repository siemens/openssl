/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* enull_hmac cipher implementation */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cipher_enull_hmac.h"

static int enull_hmac_initkey(PROV_CIPHER_CTX *bctx, const uint8_t *key,
                              size_t keylen)
{
    PROV_ENULL_HMAC_CTX *ctx = (PROV_ENULL_HMAC_CTX *)bctx;

    if (key == NULL || keylen > sizeof(ctx->key))
        return 0;

    memcpy(ctx->key, key, keylen);
    ctx->keylen = keylen;
    return 1;
}

static int enull_hmac_initiv(PROV_CIPHER_CTX *bctx,
                             const unsigned char *iv, size_t ivlen)
{
    PROV_ENULL_HMAC_CTX *ctx = (PROV_ENULL_HMAC_CTX *)bctx;

    if (iv == NULL || ivlen > ENULL_HMAC_MAX_IVLEN)
        return 0;
    if (!HMAC_Init_ex(ctx->hmac, ctx->key, ctx->keylen, ctx->evp_md, NULL))
        return 0;

    return HMAC_Update(ctx->hmac, iv, ivlen);
}

static int enull_hmac_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
                             const unsigned char *in, size_t inl)
{
    PROV_ENULL_HMAC_CTX *ctx = (PROV_ENULL_HMAC_CTX *)bctx;
    unsigned char ltag[ENULL_HMAC_MAX_TAGLEN];
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
            if (CRYPTO_memcmp(ltag, ctx->tag, ctx->tag_len) != 0)
                return 0;
        }
    }

    if (in != NULL && out != NULL && in != out)
        memcpy(out, in, inl);

    return 1;
}

static const PROV_CIPHER_HW_ENULL_HMAC enull_hmac_hw = {
    { enull_hmac_initkey, enull_hmac_cipher },
    enull_hmac_initiv
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_enull_hmac(size_t keybits)
{
    return (PROV_CIPHER_HW *)&enull_hmac_hw;
}
