/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/ciphercommon.h"

#define HMAC_SHA256_KEYLEN 32
#define HMAC_SHA256_BLKLEN 1
#define HMAC_SHA256_TAGLEN 32
#define HMAC_SHA256_IVLEN 32
#define HMAC_SHA256_MODE 0
#define HMAC_SHA256_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

typedef struct {
    PROV_CIPHER_CTX base;     /* must be first */
    HMAC_CTX *hmac;
    EVP_MD *evp_md;
    unsigned char key[HMAC_SHA256_KEYLEN];
    unsigned int keylen;
    unsigned char tag[HMAC_SHA256_TAGLEN];
    unsigned int tag_len;

} PROV_HMAC_SHA256_CTX;

typedef struct prov_cipher_hw_hmac_sha256_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*initiv)(PROV_CIPHER_CTX *ctx, const unsigned char *iv, size_t ivlen);
} PROV_CIPHER_HW_HMAC_SHA256;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_hmac_sha256(size_t keybits);

OSSL_FUNC_cipher_encrypt_init_fn ossl_hmac_sha256_einit;
OSSL_FUNC_cipher_decrypt_init_fn ossl_hmac_sha256_dinit;
void ossl_hmac_sha256_initctx(PROV_HMAC_SHA256_CTX *ctx);
