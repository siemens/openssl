/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DEPRECATION_HELPERS_H
# define OPENSSL_DEPRECATION_HELPERS_H
# pragma once

#include <openssl/opensslv.h>

/* Helpers for deprecation and version backward compatibility  */

# if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  ifdef OPENSSL_NO_DEPRECATED_3_0

#   define HMAC(evp_md, key, keylen, data, datalen, out, outlen) \
    EVP_mac(NULL, "HMAC", NULL, EVP_MD_name(evp_md), NULL, \
            key, keylen, data, datalen, out, EVP_MD_size(evp_md), outlen)
#  endif
# endif

#endif /* OPENSSL_DEPRECATION_HELPERS_H */
