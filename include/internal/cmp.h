/*
 * Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#ifndef OSSL_INTERNAL_CMP_H
# define OSSL_INTERNAL_CMP_H
# pragma once

# include <openssl/cmp.h>

int ossl_cmp_kem_performKemEncapsulation(const EVP_PKEY *pubkey,
                                         size_t *secret_len,
                                         unsigned char **secret,
                                         size_t *ct_len, unsigned char **ct,
                                         OSSL_LIB_CTX *libctx, char *propq);
int ossl_cmp_kem_performKemDecapsulation(EVP_PKEY *pkey,
                                         const unsigned char *ct, size_t ct_len,
                                         unsigned char **secret, size_t *secret_len,
                                         OSSL_LIB_CTX *libctx, char *propq);

int ossl_cmp_asn1_octet_string_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, int len);
X509_ALGOR *ossl_cmp_kem_algor(const EVP_PKEY *pubkey,
                               OSSL_LIB_CTX *libctx,
                               char *propq);
int ossl_cmp_x509_algor_set0(X509_ALGOR **tgt, X509_ALGOR *src);
int ossl_cmp_set0_ASN1_INTEGER(ASN1_INTEGER **tgt, ASN1_INTEGER *src);
int ossl_cmp_asn1_octet_string_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src);
X509_ALGOR *ossl_cmp_kem_kdf_algor(int nid_kdf,
                                   OSSL_LIB_CTX *libctx, char *propq);
int ossl_cmp_kem_derive_ssk_HKDF(unsigned char *key, int keylen,
                                 unsigned char *salt, int saltlen,
                                 unsigned char *info, int infolen,
                                 unsigned char **ssk, int ssklen,
                                 OSSL_LIB_CTX *libctx, char *propq);

#endif
