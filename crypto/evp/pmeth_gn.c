/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include "internal/bn_int.h"
#include "internal/asn1_int.h"
#include "internal/evp_int.h"

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_PARAMGEN;
    if (!ctx->pmeth->paramgen_init)
        return 1;
    ret = ctx->pmeth->paramgen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ctx->operation != EVP_PKEY_OP_PARAMGEN) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();

    if (*ppkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ret = ctx->pmeth->paramgen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_KEYGEN;
    if (!ctx->pmeth->keygen_init)
        return 1;
    ret = ctx->pmeth->keygen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;

    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_KEYGEN) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();
    if (*ppkey == NULL)
        return -1;

    ret = ctx->pmeth->keygen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb)
{
    ctx->pkey_gencb = cb;
}

EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx)
{
    return ctx->pkey_gencb;
}

/*
 * "translation callback" to call EVP_PKEY_CTX callbacks using BN_GENCB style
 * callbacks.
 */

static int trans_cb(int a, int b, BN_GENCB *gcb)
{
    EVP_PKEY_CTX *ctx = BN_GENCB_get_arg(gcb);
    ctx->keygen_info[0] = a;
    ctx->keygen_info[1] = b;
    return ctx->pkey_gencb(ctx);
}

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx)
{
    BN_GENCB_set(cb, trans_cb, ctx);
}

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx)
{
    if (idx == -1)
        return ctx->keygen_info_count;
    if (idx < 0 || idx > ctx->keygen_info_count)
        return 0;
    return ctx->keygen_info[idx];
}

static EVP_PKEY *evp_pkey_new_key(int priv, int type, ENGINE *e,
                                  const unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Note for compatibility reasons we allow keylen to be < 0 in some cases */

    ctx = EVP_PKEY_CTX_new_id(type, e);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    if (priv) {
        if (EVP_PKEY_CTX_set_priv_key(ctx, key, (int)keylen) <= 0)
            goto err;
    } else {
        if (EVP_PKEY_CTX_set_pub_key(ctx, key, (int)keylen) <= 0)
            goto err;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto err;
 err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen)
{
    return evp_pkey_new_key(1, type, e, key, keylen);
}

EVP_PKEY *EVP_PKEY_new_priv_key(int type, ENGINE *e,
                                const unsigned char *key, size_t keylen)
{
    if (keylen > INT_MAX)
        return NULL;
    return evp_pkey_new_key(1, type, e, key, keylen);
}

EVP_PKEY *EVP_PKEY_new_pub_key(int type, ENGINE *e,
                               const unsigned char *key, size_t keylen)
{
    if (keylen > INT_MAX)
        return NULL;
    return evp_pkey_new_key(0, type, e, key, keylen);
}

int EVP_PKEY_check(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY *pkey = ctx->pkey;

    if (pkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CHECK, EVP_R_NO_KEY_SET);
        return 0;
    }

    /* call customized check function first */
    if (ctx->pmeth->check != NULL)
        return ctx->pmeth->check(pkey);

    /* use default check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_check == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CHECK,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_check(pkey);
}
