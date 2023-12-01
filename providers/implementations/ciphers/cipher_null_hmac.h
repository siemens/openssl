/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/ciphercommon.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"

#define NULL_HMAC_SHA256_KEYLEN 32
#define NULL_HMAC_SHA256_BLKLEN 1
#define NULL_HMAC_SHA256_TAGLEN 32
#define NULL_HMAC_SHA256_IVLEN  32
#define NULL_HMAC_SHA256_MODE   0
#define NULL_HMAC_SHA256_FLAGS  (PROV_CIPHER_FLAG_AEAD            \
                                 | PROV_CIPHER_FLAG_CUSTOM_IV)

#define NULL_HMAC_SHA384_KEYLEN 48
#define NULL_HMAC_SHA384_BLKLEN 1
#define NULL_HMAC_SHA384_TAGLEN 48
#define NULL_HMAC_SHA384_IVLEN  48
#define NULL_HMAC_SHA384_MODE   0
#define NULL_HMAC_SHA384_FLAGS  (PROV_CIPHER_FLAG_AEAD             \
                                 | PROV_CIPHER_FLAG_CUSTOM_IV)

#define NULL_HMAC_MAX_KEYLEN  48 /* NULL_HMAC_SHA384_KEYLEN */
#define NULL_HMAC_MAX_TAGLEN  48 /* NULL_HMAC_SHA384_TAGLEN */
#define NULL_HMAC_MAX_IVLEN   48 /* NULL_HMAC_SHA384_IVLEN */

typedef struct {
    PROV_CIPHER_CTX base;     /* must be first */
    HMAC_CTX *hmac;
    PROV_DIGEST md;
    unsigned char key[NULL_HMAC_MAX_KEYLEN]; /* len is in base.keylen */
    unsigned char tag[NULL_HMAC_MAX_TAGLEN];
    unsigned int tag_len;
} PROV_NULL_HMAC_CTX;

typedef struct prov_cipher_hw_null_hmac_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*initiv)(PROV_CIPHER_CTX *ctx, const unsigned char *iv, size_t ivlen);
} PROV_CIPHER_HW_NULL_HMAC;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_null_hmac(size_t keybits);

OSSL_FUNC_cipher_encrypt_init_fn ossl_hmac_sha256_einit;
OSSL_FUNC_cipher_decrypt_init_fn ossl_hmac_sha256_dinit;
void ossl_hmac_sha256_initctx(PROV_NULL_HMAC_CTX *ctx);
