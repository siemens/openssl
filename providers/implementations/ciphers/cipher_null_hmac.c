/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for null_hmac cipher */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"

#include <openssl/proverr.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cipher_null_hmac.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static OSSL_FUNC_cipher_freectx_fn null_hmac_freectx;
static OSSL_FUNC_cipher_dupctx_fn null_hmac_dupctx;
static OSSL_FUNC_cipher_encrypt_init_fn null_hmac_einit;
static OSSL_FUNC_cipher_decrypt_init_fn null_hmac_dinit;
static OSSL_FUNC_cipher_get_ctx_params_fn null_hmac_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn null_hmac_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn null_hmac_cipher;
static OSSL_FUNC_cipher_final_fn null_hmac_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn null_hmac_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn null_hmac_settable_ctx_params;
#define null_hmac_update null_hmac_cipher
#define null_hmac_gettable_params ossl_cipher_generic_gettable_params

static void null_hmac_freectx(void *vctx)
{
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)vctx;

    if (ctx != NULL) {
        ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
        HMAC_CTX_free(ctx->hmac);
        ossl_prov_digest_reset(&ctx->md);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void *null_hmac_dupctx(void *vctx)
{
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)vctx, *dupctx;

    if (ctx == NULL)
        return NULL;

    dupctx = OPENSSL_memdup(ctx, sizeof(*dupctx));
    if (dupctx == NULL)
        return NULL;

    if (!ossl_assert(dupctx->base.tlsmac == NULL))
        goto err;

    if (!ossl_prov_digest_copy(&dupctx->md, &ctx->md))
        goto err;

    if ((dupctx->hmac = HMAC_CTX_new()) == NULL)
        goto err;

    if (!HMAC_CTX_copy(dupctx->hmac, ctx->hmac))
        goto err;

    return dupctx;
 err:
    null_hmac_freectx(dupctx);
    return NULL;
}

static int null_hmac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)vctx;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->base.enc || p->data_size != ctx->tag_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
    }

    return 1;
}

static const OSSL_PARAM null_hmac_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *null_hmac_gettable_ctx_params(ossl_unused void *cctx,
                                                ossl_unused void *provctx)
{
    return null_hmac_known_gettable_ctx_params;
}

static int null_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_NULL_HMAC_CTX *ctx = (PROV_NULL_HMAC_CTX *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The key length can not be modified */
        if (len != ctx->base.keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The iv length can not be modified */
        if (len != ctx->base.ivlen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size != ctx->tag_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->base.enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
    }
    return 1;
}

static const OSSL_PARAM null_hmac_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *null_hmac_settable_ctx_params(ossl_unused void *cctx,
                                                ossl_unused void *provctx)
{
    return null_hmac_known_settable_ctx_params;
}

static int null_hmac_einit(void *vctx,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_NULL_HMAC *hw = (PROV_CIPHER_HW_NULL_HMAC *)ctx->hw;

        ret = hw->initiv(ctx, iv, ivlen);
    }
    if (ret && !null_hmac_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int null_hmac_dinit(void *vctx,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_NULL_HMAC *hw = (PROV_CIPHER_HW_NULL_HMAC *)ctx->hw;

        hw->initiv(ctx, iv, ivlen);
    }
    if (ret && !null_hmac_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int null_hmac_cipher(void *vctx, unsigned char *out,
                            size_t *outl, size_t outsize,
                            const unsigned char *in, size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_NULL_HMAC *hw = (PROV_CIPHER_HW_NULL_HMAC *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!hw->base.cipher(ctx, out, in, inl))
        return 0;
    *outl = inl;
    return 1;
}

static int null_hmac_final(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsize)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_NULL_HMAC *hw = (PROV_CIPHER_HW_NULL_HMAC *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (!hw->base.cipher(ctx, out, NULL, 0))
        return 0;

    *outl = 0;
    return 1;
}

#define OSSL_DISPATCHALG(num, name) {OSSL_FUNC_CIPHER_##num,                   \
                                        (void (*)(void))name}
#define IMPLEMENT_cipher(cmd, CMD, flags, kbits, blkbits, ivbits)              \
static OSSL_FUNC_cipher_get_params_fn null_hmac_##cmd##_get_params;            \
static int null_hmac_##cmd##_get_params(OSSL_PARAM params[])                   \
{                                                                              \
    return ossl_cipher_generic_get_params(params, 0, flags,                    \
                                          kbits, blkbits, ivbits);             \
}                                                                              \
                                                                               \
static OSSL_FUNC_cipher_newctx_fn null_hmac_##cmd##_newctx;                    \
static void *null_hmac_##cmd##_newctx(void *provctx)                           \
{                                                                              \
    PROV_NULL_HMAC_CTX *ctx;                                                   \
                                                                               \
    if (!ossl_prov_is_running())                                               \
        return NULL;                                                           \
                                                                               \
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)                          \
        return NULL;                                                           \
                                                                               \
    if ((ctx->hmac = HMAC_CTX_new()) == NULL) {                                \
        OPENSSL_free(ctx);                                                     \
        return NULL;                                                           \
    }                                                                          \
    if (ossl_prov_digest_fetch(&ctx->md, PROV_LIBCTX_OF(provctx),              \
                               #CMD, NULL) == NULL) {                          \
        null_hmac_freectx(ctx);                                                \
        return NULL;                                                           \
    }                                                                          \
    ctx->tag_len = NULL_HMAC_##CMD##_TAGLEN;                                   \
    ossl_cipher_generic_initkey(ctx, kbits, blkbits, ivbits, 0, flags,         \
                                ossl_prov_cipher_hw_null_hmac(kbits),          \
                                provctx);                                      \
    return ctx;                                                                \
}                                                                              \
                                                                               \
const OSSL_DISPATCH ossl_null_hmac_##cmd##_functions[] = {                     \
    OSSL_DISPATCHALG(NEWCTX, null_hmac_##cmd##_newctx),                        \
    OSSL_DISPATCHALG(FREECTX, null_hmac_freectx),                              \
    OSSL_DISPATCHALG(DUPCTX, null_hmac_dupctx),                                \
    OSSL_DISPATCHALG(ENCRYPT_INIT, null_hmac_einit),                           \
    OSSL_DISPATCHALG(DECRYPT_INIT, null_hmac_dinit),                           \
    OSSL_DISPATCHALG(UPDATE, null_hmac_update),                                \
    OSSL_DISPATCHALG(FINAL, null_hmac_final),                                  \
    OSSL_DISPATCHALG(CIPHER, null_hmac_cipher),                                \
    OSSL_DISPATCHALG(GET_PARAMS, null_hmac_##cmd##_get_params),                \
    OSSL_DISPATCHALG(GETTABLE_PARAMS, null_hmac_gettable_params),              \
    OSSL_DISPATCHALG(GET_CTX_PARAMS,  null_hmac_get_ctx_params),               \
    OSSL_DISPATCHALG(GETTABLE_CTX_PARAMS, null_hmac_gettable_ctx_params),      \
    OSSL_DISPATCHALG(SET_CTX_PARAMS, null_hmac_set_ctx_params),                \
    OSSL_DISPATCHALG(SETTABLE_CTX_PARAMS, null_hmac_settable_ctx_params),      \
    OSSL_DISPATCH_END                                                          \
}

IMPLEMENT_cipher(sha256, SHA256, NULL_HMAC_SHA256_FLAGS,
                 NULL_HMAC_SHA256_KEYLEN * 8, NULL_HMAC_SHA256_BLKLEN * 8,
                 NULL_HMAC_SHA256_IVLEN * 8);
IMPLEMENT_cipher(sha384, SHA384, NULL_HMAC_SHA384_FLAGS,
                 NULL_HMAC_SHA384_KEYLEN * 8, NULL_HMAC_SHA384_BLKLEN * 8,
                 NULL_HMAC_SHA384_IVLEN * 8);
