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
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/cmp_util.h>
#include "crypto/asn1.h"

#define RSAKEM_KEYLENGTH 32

/* TODO: look for existing OpenSSL solution */
static int x509_algor_from_nid_with_md(int nid, X509_ALGOR **palg,
                                       const EVP_MD *md)
{
    X509_ALGOR *algtmp = NULL;
    ASN1_STRING *stmp = NULL;

    *palg = NULL;
    if (md == NULL)
        return 0;
    /* need to embed algorithm ID inside another */
    if (!ossl_x509_algor_new_from_md(&algtmp, md))
        goto err;
    if (ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp) == NULL)
        goto err;
    *palg = ossl_X509_ALGOR_from_nid(nid, V_ASN1_SEQUENCE, stmp);
    if (*palg == NULL)
        goto err;
    stmp = NULL;
 err:
    ASN1_STRING_free(stmp);
    X509_ALGOR_free(algtmp);
    return *palg != NULL;
}

X509_ALGOR *ossl_cmp_kem_kdf_algor(const OSSL_CMP_CTX *ctx, int nid_kdf)
{
    X509_ALGOR *alg = NULL;

    if (nid_kdf == NID_hkdfWithSHA256) {
        alg = ossl_X509_ALGOR_from_nid(NID_hkdfWithSHA256,
                                       V_ASN1_UNDEF, NULL);
    } else if (nid_kdf == NID_id_kdf_kdf2) {
        EVP_MD *md = NULL;

        if ((md = EVP_MD_fetch(ctx->libctx, "SHA256",
                               ctx->propq)) == NULL)
            return NULL;
        (void)x509_algor_from_nid_with_md(NID_id_kdf_kdf2, &alg, md);
        EVP_MD_free(md);
    }

    return alg;
}

static X509_ALGOR *mac_algor(const OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *alg = NULL;

    if (ctx->kem_mac == NID_hmacWithSHA256)
        alg = ossl_X509_ALGOR_from_nid(NID_hmacWithSHA256, V_ASN1_UNDEF, NULL);

    return alg;
}

static int get_pknid(const EVP_PKEY *pkey)
{
    int pknid;

    if (pkey == NULL)
        return NID_undef;
    pknid = EVP_PKEY_get_base_id(pkey);
    if (pknid <= 0) { /* check whether a provider registered a NID */
        const char *typename = EVP_PKEY_get0_type_name(pkey);

        if (typename != NULL)
            pknid = OBJ_txt2nid(typename);
    }
    return pknid;
}

static X509_ALGOR *kem_algor(OSSL_CMP_CTX *ctx,
                             const EVP_PKEY *pubkey)
{
    X509_ALGOR *kem = NULL;
    int pknid = get_pknid(pubkey);

    if (pknid <= 0)
        return NULL;

    switch (pknid) {
    case EVP_PKEY_RSA:
        /* kem rsa */
        kem = ossl_cmp_rsakem_algor(ctx);
        break;
    case EVP_PKEY_EC:
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
        /* TODO: fall through */
    default:
        /* TODO: Check if any other algorithm need parameter */
        kem = ossl_X509_ALGOR_from_nid(pknid, V_ASN1_UNDEF, NULL);
        break;
    }
    return kem;
}

X509_ALGOR *ossl_cmp_kem_BasedMac_algor(const OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *alg = NULL;
    OSSL_CMP_KEMBMPARAMETER *param = NULL;
    unsigned char *param_der = NULL;
    int param_der_len;
    ASN1_STRING *param_str = NULL;

    if ((param = OSSL_CMP_KEMBMPARAMETER_new()) == NULL
        || !ossl_cmp_x509_algor_set0(&param->kdf,
                                     ossl_cmp_kem_kdf_algor(ctx, ctx->kem_kdf))
        || !ossl_cmp_x509_algor_set0(&param->mac, mac_algor(ctx))
        || !ASN1_INTEGER_set(param->len, ctx->kem_ssklen))
        goto err;

    if ((param_str = ASN1_STRING_new()) == NULL)
        goto err;
    if ((param_der_len = i2d_OSSL_CMP_KEMBMPARAMETER(param, &param_der)) < 0)
        goto err;
    if (!ASN1_STRING_set(param_str, param_der, param_der_len))
        goto err;

    alg = ossl_X509_ALGOR_from_nid(NID_id_KemBasedMac,
                                   V_ASN1_SEQUENCE, param_str);

 err:
    if (alg == NULL)
        ASN1_STRING_free(param_str);
    OPENSSL_free(param_der);
    OSSL_CMP_KEMBMPARAMETER_free(param);
    return alg;
}

/* return -1 in case of error */
int ossl_cmp_kem_BasedMac_required(OSSL_CMP_CTX *ctx)
{
    uint32_t ex_kusage = 0;

    /* Secret is provided for PBM or unprotected msg is allowed */
    if (ctx == NULL)
        return -1;
    if (ctx->unprotectedSend
        || ctx->secretValue != NULL)
        return 0;

    /* Client have certificate for KEM or DS */
    if (ctx->cert != NULL && ctx->pkey != NULL) {
        if (!X509_check_private_key(ctx->cert, ctx->pkey)) {
            ERR_raise(ERR_LIB_CMP, CMP_R_CERT_AND_KEY_DO_NOT_MATCH);
            return -1;
        }
        ex_kusage = X509_get_key_usage(ctx->cert);
        if (ex_kusage == UINT32_MAX) {
            ossl_cmp_debug(ctx,
                           "key usage absent in CMP signer cert");
        } else if (ex_kusage & X509v3_KU_DIGITAL_SIGNATURE) {
            return 0;
        } else if (ex_kusage & X509v3_KU_KEY_ENCIPHERMENT) {
            OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                                    KBM_SSK_USING_CLIENT_KEM_KEY);
            return 1;
        }
    }
    /* Server certificate with KEM is known to client */
    if (ctx->srvCert != NULL) {
        ex_kusage = X509_get_key_usage(ctx->srvCert);

        if (ex_kusage == UINT32_MAX) {
            ossl_cmp_debug(ctx,
                           "key usage absent in server cert");
        } else if (ex_kusage & X509v3_KU_KEY_ENCIPHERMENT) {
            OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                                    KBM_SSK_USING_SERVER_KEM_KEY);
            return 1;
        }
    }
    return 0;
}

static int kem_decapsulation(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey, int is_EC,
                             const unsigned char *ct, size_t ct_len,
                             unsigned char **secret, size_t *secret_len)
{
    int ret = 0;
    EVP_PKEY_CTX *kem_decaps_ctx;

    if (ctx == NULL || pkey == NULL
        || ct == NULL
        || secret == NULL || secret_len == NULL)
        return 0;

    kem_decaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                pkey,
                                                ctx->propq);

    if (kem_decaps_ctx == NULL
        || EVP_PKEY_decapsulate_init(kem_decaps_ctx, NULL) <= 0
        || (is_EC && EVP_PKEY_CTX_set_kem_op(kem_decaps_ctx, "DHKEM") <= 0)
        || EVP_PKEY_decapsulate(kem_decaps_ctx, NULL, secret_len,
                                ct, ct_len) <= 0) {
        goto err;
    }

    *secret = OPENSSL_malloc(*secret_len);
    if (*secret == NULL)
        goto err;

    if (EVP_PKEY_decapsulate(kem_decaps_ctx,
                             *secret, secret_len,
                             ct, ct_len) <= 0) {
        OPENSSL_free(*secret);
        goto err;
    }
    ret = 1;
 err:
    EVP_PKEY_CTX_free(kem_decaps_ctx);
    return ret;
}

static int performKemDecapsulation(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey,
                                   const unsigned char *ct, size_t ct_len,
                                   unsigned char **secret, size_t *secret_len)
{
    int pknid = get_pknid(pkey);

    if (pknid <= 0)
        return 0;

    if (pknid == EVP_PKEY_EC
        || pknid == EVP_PKEY_X25519
        || pknid == EVP_PKEY_X448) {
        return kem_decapsulation(ctx, pkey, 1, ct, ct_len, secret, secret_len);
    } else if (pknid == EVP_PKEY_RSA) {
        return ossl_cmp_kemrsa_decapsulation(ctx, pkey,
                                             ct, ct_len, secret, secret_len);
    } else {
        return kem_decapsulation(ctx, pkey, 0, ct, ct_len, secret, secret_len);
    }
    return 0;
}

static int derive_ssk_HKDF(OSSL_CMP_CTX *ctx,
                           unsigned char *key, int keylen,
                           unsigned char *salt, int saltlen,
                           unsigned char *info, int infolen,
                           unsigned char **ssk, int *ssklen)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kdfctx;
    OSSL_PARAM params[5], *p = params;
    int rv;

    if (ctx == NULL || ssk == NULL || ssklen == NULL
        || key == NULL || info == NULL)
        return 0;

    *ssklen = ctx->kem_ssklen;
    *ssk = OPENSSL_zalloc(*ssklen);
    if (*ssk == NULL
        || (kdf = EVP_KDF_fetch(ctx->libctx, "HKDF", ctx->propq)) == NULL)
        return 0;

    kdfctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key,
                                             keylen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info,
                                             infolen);

    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt,
                                                 saltlen);

    *p = OSSL_PARAM_construct_end();
    rv = EVP_KDF_derive(kdfctx, *ssk, *ssklen, params);
    EVP_KDF_CTX_free(kdfctx);
    return rv;
}

int ossl_cmp_kem_derivessk(OSSL_CMP_CTX *ctx,
                           unsigned char *secret, int secret_len,
                           unsigned char **out, int *len)
{
    int info_len = 0;
    unsigned char *salt = NULL, *info = NULL;

    if (!ossl_cmp_kem_KemOtherInfo_new(ctx, &info, &info_len)) {
        return 0;
    }

    derive_ssk_HKDF(ctx, secret, secret_len,
                    salt, sizeof(salt), info, info_len,
                    out, len);

    OPENSSL_clear_free(info, info_len);
    OPENSSL_free(salt);
    return 1;
}

int ossl_cmp_kem_derivessk_using_kemctinfo(OSSL_CMP_CTX *ctx,
                                           OSSL_CMP_ITAV *KemCiphertextInfo,
                                           EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *ct;
    size_t secret_len = 0;
    unsigned char *secret = NULL, *ssk = NULL;
    int ssk_len = 0, ret = 0;

    if (ctx == NULL || KemCiphertextInfo == NULL || pkey == NULL)
        return 0;

    if (NID_id_it_KemCiphertextInfo !=
        OBJ_obj2nid(OSSL_CMP_ITAV_get0_type(KemCiphertextInfo)))
        return 0;

    ct = KemCiphertextInfo->infoValue.KemCiphertextInfoValue->ct;
    if (!ossl_cmp_ctx_set1_kem_ct(ctx, ct))
        return 0;

    if (!performKemDecapsulation(ctx, pkey,
                                 ASN1_STRING_get0_data(ct),
                                 ASN1_STRING_length(ct),
                                 &secret, &secret_len))
        goto err;

    if (!ossl_cmp_kem_derivessk(ctx, secret, secret_len, &ssk, &ssk_len))
        goto err;

    ossl_cmp_ctx_set1_kem_ssk(ctx, ssk, ssk_len);
    ret = 1;
 err:
    OPENSSL_clear_free(secret, secret_len);
    OPENSSL_clear_free(ssk, ssk_len);
    return ret;
}

int OSSL_CMP_get_ssk(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_ITAV *req, *itav;
    int ret = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((req = OSSL_CMP_ITAV_create(OBJ_nid2obj(NID_id_it_KemCiphertextInfo),
                                    NULL)) == NULL)
        return 0;
    if ((itav = ossl_cmp_genm_get_itav(ctx, req, NID_id_it_KemCiphertextInfo,
                                       "KemCiphertextInfo")) == NULL)
        return 0;

    if (!ossl_cmp_kem_derivessk_using_kemctinfo(ctx, itav, ctx->pkey))
        goto err;

    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                            KBM_SSK_ESTABLISHED_USING_CLIENT);
    ret = 1;
 err:
    OSSL_CMP_ITAV_free(itav);
    return ret;
}

static int kem_encapsulation(OSSL_CMP_CTX *ctx,
                             const EVP_PKEY *pubkey,
                             int is_EC,
                             size_t *secret_len, unsigned char **secret,
                             size_t *ct_len, unsigned char **ct)
{
    int ret = 0;
    EVP_PKEY_CTX *kem_encaps_ctx = NULL;

    if (ctx == NULL || pubkey == NULL
        || ct == NULL
        || secret == NULL || secret_len == NULL)
        return 0;

    kem_encaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                (EVP_PKEY *)pubkey,
                                                ctx->propq);

    if (kem_encaps_ctx == NULL
        || EVP_PKEY_encapsulate_init(kem_encaps_ctx, NULL) <= 0
        || (is_EC && EVP_PKEY_CTX_set_kem_op(kem_encaps_ctx, "DHKEM") <= 0)
        || EVP_PKEY_encapsulate(kem_encaps_ctx, NULL, ct_len,
                                NULL, secret_len) <= 0) {
        goto err;
    }

    *ct = OPENSSL_malloc(*ct_len);
    if (*ct == NULL)
        goto err;

    *secret = OPENSSL_malloc(*secret_len);
    if (*secret == NULL) {
        OPENSSL_free(*ct);
        goto err;
    }

    if (EVP_PKEY_encapsulate(kem_encaps_ctx, *ct, ct_len,
                             *secret, secret_len) <= 0) {
        OPENSSL_free(*ct);
        OPENSSL_free(*secret);
        goto err;
    }

    ret = 1;
 err:
    EVP_PKEY_CTX_free(kem_encaps_ctx);
    return ret;
}

static int performKemEncapsulation(OSSL_CMP_CTX *ctx,
                                   const EVP_PKEY *pubkey,
                                   size_t *secret_len, unsigned char **secret,
                                   size_t *ct_len, unsigned char **ct)
{
    int pknid;

    if (secret_len == NULL || secret == NULL
        || ct_len == NULL || ct == NULL
        || pubkey == NULL)
        return 0;

    pknid = get_pknid(pubkey);
    if (pknid <= 0)
        return 0;

    if (pknid == EVP_PKEY_EC
        || pknid == EVP_PKEY_X25519
        || pknid == EVP_PKEY_X448) {
        return kem_encapsulation(ctx, pubkey, 1, secret_len,
                                 secret, ct_len, ct);
    } else if (pknid == EVP_PKEY_RSA) {
        return ossl_cmp_kemrsa_encapsulation(ctx, pubkey, secret_len,
                                             secret, ct_len, ct);
    } else {
        return kem_encapsulation(ctx, pubkey, 0, secret_len,
                                 secret, ct_len, ct);
    }
}

OSSL_CMP_ITAV *ossl_cmp_kem_get_KemCiphertext(OSSL_CMP_CTX *ctx,
                                              const EVP_PKEY *pubkey)
{
    size_t secret_len, ct_len;
    unsigned char *secret = NULL, *ct = NULL;
    OSSL_CMP_ITAV *kem_itav = NULL;
    ASN1_OCTET_STRING *asn1ct = NULL;
    X509_ALGOR *kem_algo;

    if (ctx == NULL || pubkey == NULL)
        return NULL;

    if (!performKemEncapsulation(ctx, pubkey, &secret_len, &secret,
                                 &ct_len, &ct))
        return NULL;

    if (!ossl_cmp_ctx_set1_kem_secret(ctx, secret, secret_len))
        goto err;
    if (!ossl_cmp_asn1_octet_string_set1_bytes(&asn1ct, ct, ct_len))
        goto err;
    if (!ossl_cmp_ctx_set1_kem_ct(ctx, asn1ct))
        goto err;

    kem_algo = kem_algor(ctx, pubkey);
    kem_itav = ossl_cmp_itav_new_KemCiphertext(kem_algo,
                                               ct, ct_len);
    if (kem_itav == NULL)
        goto err;

 err:
    if (secret != NULL)
        OPENSSL_clear_free(secret, secret_len);
    if (ct != NULL)
        OPENSSL_clear_free(ct, ct_len);
    ASN1_OCTET_STRING_free(asn1ct);
    return kem_itav;
}

int ossl_cmp_kem_get_ss_using_srvcert(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    OSSL_CMP_ITAV *kem_itav = NULL;
    int ret = 0;
    EVP_PKEY *pubkey = X509_get0_pubkey(ctx->srvCert);

    if ((kem_itav = ossl_cmp_kem_get_KemCiphertext(ctx, pubkey))
        == NULL)
        goto err;

    if (msg->header == NULL
        || !ossl_cmp_hdr_generalInfo_push0_item(msg->header, kem_itav)) {
        OSSL_CMP_ITAV_free(kem_itav);
        goto err;
    }

    ossl_cmp_ctx_set1_kem_senderNonce(ctx,
                                      msg->header->senderNonce);
    ossl_cmp_ctx_set1_kem_recipNonce(ctx,
                                     msg->header->recipNonce);

    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                            KBM_SSK_USING_SERVER_KEM_KEY_1);
    ret = 1;
 err:
    return ret;
}

static OSSL_CMP_KEMBMPARAMETER *decode_KEMBMPARAMETER(X509_ALGOR *protectionAlg)
{
    const ASN1_OBJECT *algorOID = NULL;
    const void *ppval = NULL;
    int pptype = 0;
    ASN1_STRING *param_str = NULL;
    const unsigned char *param_str_uc = NULL;

    X509_ALGOR_get0(&algorOID, &pptype, &ppval, protectionAlg);
    if (NID_id_KemBasedMac != OBJ_obj2nid(algorOID)
        || ppval == NULL)
        return NULL;

    param_str = (ASN1_STRING *)ppval;
    param_str_uc = param_str->data;
    return d2i_OSSL_CMP_KEMBMPARAMETER(NULL, &param_str_uc,
                                       param_str->length);
}

int ossl_cmp_kem_derive_ssk_using_srvcert(OSSL_CMP_CTX *ctx,
                                          const OSSL_CMP_MSG *msg)
{
    unsigned char *ssk;
    int len;
    OSSL_CMP_KEMBMPARAMETER *param = NULL;

    if (ctx == NULL || msg == NULL)
        return 0;

    param = decode_KEMBMPARAMETER(msg->header->protectionAlg);
    if (param == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_WRONG_ALGORITHM_OID);
        return 0;
    }
    ctx->kem_kdf = OBJ_obj2nid(param->kdf->algorithm);
    ctx->kem_mac = OBJ_obj2nid(param->mac->algorithm);
    ctx->kem_ssklen = ASN1_INTEGER_get(param->len);

    if (ctx->kem_status != KBM_SSK_USING_SERVER_KEM_KEY_1
        || ctx->kem_secret == NULL
        || !ossl_cmp_kem_derivessk(ctx,
                                   (unsigned char *)
                                   ASN1_STRING_get0_data(ctx->kem_secret),
                                   ASN1_STRING_length(ctx->kem_secret),
                                   &ssk, &len))
        return 0;
    ossl_cmp_ctx_set1_kem_ssk(ctx, ssk, len);
    OSSL_CMP_CTX_set_option(ctx,
                            OSSL_CMP_OPT_KEM_STATUS,
                            KBM_SSK_ESTABLISHED_USING_SERVER);
    OPENSSL_free(ssk);
    OSSL_CMP_KEMBMPARAMETER_free(param);
    return 1;
}
