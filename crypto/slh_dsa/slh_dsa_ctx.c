/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>
#include <openssl/crypto.h>
#include "slh_dsa_local.h"

/**
 * @brief Create a SLH_DSA_CTX that contains parameters, functions, and
 * pre-fetched HASH related objects for a SLH_DSA algorithm.This context is passed
 * to most SLH-DSA functions.
 *
 * @param alg An SLH-DSA algorithm name such as "SLH-DSA-SHA2-128s"
 * @param lib_ctx A library context used for fetching. Can be NULL
 * @param propq A propqery query to use for algorithm fetching. Can be NULL.
 *
 * @returns The created SLH_DSA_CTX object or NULL on failure.
 */
SLH_DSA_CTX *ossl_slh_dsa_ctx_new(const char *alg,
                                  OSSL_LIB_CTX *lib_ctx, const char *propq)
{
    SLH_DSA_CTX *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret != NULL) {
        const SLH_DSA_PARAMS *params = ossl_slh_dsa_params_get(alg);

        if (params == NULL)
            goto err;
        ret->params = params;
        ret->hash_func = ossl_slh_get_hash_fn(params->is_shake);
        ret->adrs_func = ossl_slh_get_adrs_fn(params->is_shake == 0);

        if (!ossl_slh_hash_ctx_init(&ret->hash_ctx, lib_ctx, propq,
                                    params->is_shake,
                                    params->security_category,
                                    params->n, params->m))
            goto err;
    }
    return ret;
 err:
    OPENSSL_free(ret);
    return NULL;
}

/**
 * @brief Destroy a SLH_DSA_CTX
 *
 * @param ctx The SLH_DSA_CTX object to destroy.
 */
void ossl_slh_dsa_ctx_free(SLH_DSA_CTX *ctx)
{
    ossl_slh_hash_ctx_cleanup(&ctx->hash_ctx);
    OPENSSL_free(ctx);
}
