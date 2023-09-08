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

#define RSAKEM_KEYLENGTH 32

/* using X963KDF without info */
static int kdf2(OSSL_CMP_CTX *ctx, unsigned char *secret, size_t secret_len,
                unsigned char *out, int out_len)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[4], *p = params;

    if (out == NULL)
        return 0;

    kdf = EVP_KDF_fetch(ctx->libctx, "X963KDF", ctx->propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                             secret, (size_t)secret_len);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        return 0;
    }
    EVP_KDF_CTX_free(kctx);
    return 1;
}

static int x509_algor_from_nid_with_md(int nid, X509_ALGOR **palg,
                                       const EVP_MD *md)
{
    X509_ALGOR *algtmp = NULL;
    ASN1_STRING *stmp = NULL;

    *palg = NULL;
    if (md == NULL)
        return 1;
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

static X509_ALGOR *kdf_algor(const OSSL_CMP_CTX *ctx, int nid_kdf)
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

static X509_ALGOR *kem_rsa_algor(OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *kemrsa_algo = NULL;
    OSSL_CMP_RSAKEMPARAMETERS *param = NULL;
    ASN1_STRING *stmp = NULL;

    if ((param = OSSL_CMP_RSAKEMPARAMETERS_new()) == NULL
        || (param->KeyDerivationFunction = kdf_algor(ctx,
                                                     NID_id_kdf_kdf2)) == NULL
        || !ASN1_INTEGER_set(param->KeyLength, RSAKEM_KEYLENGTH))
        goto err;

    if (ASN1_item_pack(param, ASN1_ITEM_rptr(OSSL_CMP_RSAKEMPARAMETERS),
                       &stmp) == NULL)
        goto err;
    kemrsa_algo = ossl_X509_ALGOR_from_nid(NID_id_kem_rsa,
                                           V_ASN1_SEQUENCE, stmp);
    if (kemrsa_algo == NULL)
        goto err;
    stmp = NULL;
 err:
    OSSL_CMP_RSAKEMPARAMETERS_free(param);
    ASN1_STRING_free(stmp);
    return kemrsa_algo;
}

static X509_ALGOR *kem_algor(OSSL_CMP_CTX *ctx,
                             const EVP_PKEY *pubkey)
{
    X509_ALGOR *kem = NULL;

    switch (EVP_PKEY_get_base_id(pubkey)) {
    case EVP_PKEY_RSA:
        /* kem rsa */
        kem = kem_rsa_algor(ctx);
        break;
    case EVP_PKEY_EC:
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
        break;
    default:
        break;
    }

    if (kem == NULL)
        ERR_raise(ERR_LIB_CMP, CMP_R_UNSUPPORTED_ALGORITHM);

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
        || (param->kdf = kdf_algor(ctx, ctx->kem_kdf)) == NULL
        || (param->mac = mac_algor(ctx)) == NULL
        || !ASN1_INTEGER_set(param->len, ctx->ssklen))
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
    if (ctx == NULL
        || ctx->unprotectedSend
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
                                    KBM_SSK_USING_CLINET_KEM_KEY);
            return 1;
        }
    }
    /* Server certificate with KEM is known to client */
    if (ctx->srvCert != NULL) {
        ex_kusage = X509_get_key_usage(ctx->srvCert);

        if (ex_kusage == UINT32_MAX) {
            ossl_cmp_debug(ctx,
                           "key usage absent in serever cert");
        } else if (ex_kusage & X509v3_KU_KEY_ENCIPHERMENT) {
            OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                                    KBM_SSK_USING_SERVER_KEM_KEY);
            return 1;
        }
    }
    return 0;
}

static int performKemDecapsulation(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey,
                                   const unsigned char *ct, size_t ct_len,
                                   unsigned char **secret, size_t *secret_len)
{
    int ret = 0;
    size_t sec_len;
    unsigned char *sec;
    int pktype = EVP_PKEY_get_base_id(pkey);
    EVP_PKEY_CTX *kem_decaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                              pkey,
                                                              ctx->propq);

    if (kem_decaps_ctx == NULL
        || EVP_PKEY_decapsulate_init(kem_decaps_ctx, NULL) <= 0
        || (pktype == EVP_PKEY_RSA
            && EVP_PKEY_CTX_set_kem_op(kem_decaps_ctx, "RSASVE") <= 0)
        || ((pktype == EVP_PKEY_EC
             || pktype == EVP_PKEY_X25519
             || pktype == EVP_PKEY_X448)
            && EVP_PKEY_CTX_set_kem_op(kem_decaps_ctx, "DHKEM") <= 0)
        || EVP_PKEY_decapsulate(kem_decaps_ctx, NULL, &sec_len,
                                ct, ct_len) <= 0) {
        goto err;
    }

    sec = OPENSSL_malloc(sec_len);
    if (sec == NULL)
        goto err;

    if (EVP_PKEY_decapsulate(kem_decaps_ctx,
                             sec, &sec_len,
                             ct, ct_len) <= 0) {
        OPENSSL_free(sec);
        goto err;
    }
    if (pktype == EVP_PKEY_RSA) {
        *secret_len = RSAKEM_KEYLENGTH;
        *secret = OPENSSL_malloc(*secret_len);
        if (*secret == NULL) {
            OPENSSL_clear_free(sec, sec_len);
            goto err;
        }

        if (!kdf2(ctx, sec, sec_len, *secret, *secret_len)) {
            OPENSSL_clear_free(sec, sec_len);
            OPENSSL_clear_free(*secret, *secret_len);
            goto err;
        }
        OPENSSL_clear_free(sec, sec_len);

    } else {
        *secret_len = sec_len;
        *secret = sec;
    }
    ret = 1;
 err:
    EVP_PKEY_CTX_free(kem_decaps_ctx);
    return ret;
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

    *ssklen = ctx->ssklen;
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
    return 1;
}

int ossl_cmp_kem_derivessk_using_kemctinfo(OSSL_CMP_CTX *ctx,
                                           OSSL_CMP_ITAV *KemCiphertextInfo,
                                           EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *ct;
    size_t secret_len = 0;
    unsigned char *secret = NULL, *ssk = NULL;
    int ssk_len;

    if (ctx == NULL || KemCiphertextInfo == NULL || pkey == NULL)
        return 0;

    if (NID_id_it_KemCiphertextInfo !=
        OBJ_obj2nid(OSSL_CMP_ITAV_get0_type(KemCiphertextInfo)))
        return 0;

    ct = KemCiphertextInfo->infoValue.KemCiphertextInfoValue->ct;
    if (!ossl_cmp_ctx_set1_ct(ctx, ct))
        return 0;

    if (!performKemDecapsulation(ctx, pkey,
                                 ASN1_STRING_get0_data(ct),
                                 ASN1_STRING_length(ct),
                                 &secret, &secret_len))
        return 0;

    if (!ossl_cmp_kem_derivessk(ctx, secret, secret_len, &ssk, &ssk_len))
        return 0;

    ossl_cmp_ctx_set1_ssk(ctx, ssk, ssk_len);
    return 1;
}

int OSSL_CMP_get_ssk(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_ITAV *req, *itav;

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
        return 0;

    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEM_STATUS,
                            KBM_SSK_ESTABLISHED_USING_CLIENT);
    return 1;
}

static int performKemEncapsulation(OSSL_CMP_CTX *ctx,
                                   const EVP_PKEY *pubkey,
                                   size_t *secret_len, unsigned char **secret,
                                   size_t *ct_len, unsigned char **ct)
{
    int pktype, ret = 0;
    EVP_PKEY_CTX *kem_encaps_ctx = NULL;
    size_t sec_len;
    unsigned char *sec;

    if (secret_len == NULL || secret == NULL
        || ct_len == NULL || ct == NULL)
        return 0;

    pktype = EVP_PKEY_get_base_id(pubkey);
    if (!(pktype == EVP_PKEY_RSA
          || pktype == EVP_PKEY_EC
          || pktype == EVP_PKEY_X25519
          || pktype == EVP_PKEY_X448))
        goto err;

    kem_encaps_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                (EVP_PKEY *)pubkey,
                                                ctx->propq);

    if (kem_encaps_ctx == NULL
        || EVP_PKEY_encapsulate_init(kem_encaps_ctx, NULL) <= 0
        || (pktype == EVP_PKEY_RSA
            && EVP_PKEY_CTX_set_kem_op(kem_encaps_ctx, "RSASVE") <= 0)
        || ((pktype == EVP_PKEY_EC
             || pktype == EVP_PKEY_X25519
             || pktype == EVP_PKEY_X448)
            && EVP_PKEY_CTX_set_kem_op(kem_encaps_ctx, "DHKEM") <= 0)
        || EVP_PKEY_encapsulate(kem_encaps_ctx, NULL, ct_len,
                                NULL, &sec_len) <= 0) {
        goto err;
    }

    *ct = OPENSSL_malloc(*ct_len);
    if (*ct == NULL)
        goto err;

    sec = OPENSSL_malloc(sec_len);
    if (sec == NULL) {
        OPENSSL_free(*ct);
        goto err;
    }

    if (EVP_PKEY_encapsulate(kem_encaps_ctx, *ct, ct_len,
                             sec, &sec_len) <= 0) {
        OPENSSL_free(*ct);
        OPENSSL_free(sec);
        goto err;
    }

    if (pktype == EVP_PKEY_RSA) {
        *secret_len = 32; /* TODO- remove hardcoded */
        *secret = OPENSSL_malloc(*secret_len);
        if (*secret == NULL) {
            OPENSSL_clear_free(sec, sec_len);
            goto err;
        }

        if (!kdf2(ctx, sec, sec_len, *secret, *secret_len)) {
            OPENSSL_clear_free(sec, sec_len);
            OPENSSL_clear_free(*secret, *secret_len);
            OPENSSL_clear_free(*ct, *ct_len);
            goto err;
        }
        OPENSSL_clear_free(sec, sec_len);

    } else {
        *secret_len = sec_len;
        *secret = sec;
    }
    ret = 1;

 err:
    EVP_PKEY_CTX_free(kem_encaps_ctx);
    return ret;
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
    if (!ossl_cmp_ctx_set1_ct(ctx, asn1ct))
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

    if (!ossl_cmp_hdr_generalInfo_push0_item(msg->header, kem_itav)) {
        OSSL_CMP_ITAV_free(kem_itav);
        goto err;
    }

    ossl_cmp_ctx_set1_kemSenderNonce(ctx,
                                     ossl_cmp_hdr_get0_senderNonce(msg->header));
    ossl_cmp_ctx_set1_kemRecipNonce(ctx,
                                    OSSL_CMP_HDR_get0_recipNonce(msg->header));

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
    ctx->ssklen = ASN1_INTEGER_get(param->len);

    if (ctx->kem != KBM_SSK_USING_SERVER_KEM_KEY_1
        || ctx->kem_secret == NULL
        || !ossl_cmp_kem_derivessk(ctx,
                                   (unsigned char *)
                                   ASN1_STRING_get0_data(ctx->kem_secret),
                                   ASN1_STRING_length(ctx->kem_secret),
                                   &ssk, &len))
        return 0;
    ossl_cmp_ctx_set1_ssk(ctx, ssk, len);
    OSSL_CMP_CTX_set_option(ctx,
                            OSSL_CMP_OPT_KEM_STATUS,
                            KBM_SSK_ESTABLISHED_USING_SERVER);
    OPENSSL_free(ssk);
    return 1;
}
