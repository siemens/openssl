/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* hmac_sha256 cipher implementation */

#include "cipher_hmac_sha256.h"

static int hmac_sha256_initkey(PROV_CIPHER_CTX *bctx, const uint8_t *key,
                            size_t keylen)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;
    unsigned int i;
    return 1;
}

static int hmac_sha256_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;
    unsigned int i;

    return 1;
}

static int hmac_sha256_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    PROV_HMAC_SHA256_CTX *ctx = (PROV_HMAC_SHA256_CTX *)bctx;
    //unsigned int n, rem, ctr32;
    if( out != NULL)
        memcpy(out, in, inl);

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

