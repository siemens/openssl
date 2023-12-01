/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#ifndef OPENSSL_NO_INTEGRITY_ONLY_CIPHER

# include <openssl/evp.h>
# include <openssl/objects.h>
# include "crypto/evp.h"
# include "evp_local.h"

static EVP_CIPHER enull_hmac_sha256_cipher = {
    NID_enull_hmac_sha256, 0, 0, 0, 0, EVP_ORIG_GLOBAL,
    NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL
};

static EVP_CIPHER enull_hmac_sha384_cipher = {
    NID_enull_hmac_sha384, 0, 0, 0, 0, EVP_ORIG_GLOBAL,
    NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL
};

/*
 * dummy cipher just to populate the NID value.
 * TODO: look for better way of doing it.
 */
const EVP_CIPHER *EVP_enc_null_hmac_sha256(void)
{
    return (&enull_hmac_sha256_cipher);
}

const EVP_CIPHER *EVP_enc_null_hmac_sha384(void)
{
    return (&enull_hmac_sha384_cipher);
}

#endif
