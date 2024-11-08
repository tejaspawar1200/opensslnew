/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/proverr.h>
#include "testutil.h"
#include "fake_cipherprov.h"

#define MAX_KEYNAME 32

typedef struct prov_cipher_fake_ctx_st {
    int enc;
    char key_name[MAX_KEYNAME];
    unsigned char key;
} PROV_CIPHER_FAKE_CTX;
/*
static int ctx_from_key_params(PROV_CIPHER_FAKE_CTX *pctx, const OSSL_PARAM *params)
{
    const OSSL_PARAM *p;
    char key_name[MAX_KEYNAME];
    char *pval = key_name;
    size_t i;

    memset(key_name, 0, MAX_KEYNAME);

    p = OSSL_PARAM_locate_const(params, FAKE_CIPHER_PARAM_KEY_NAME);
    if (p != NULL && !OSSL_PARAM_get_utf8_string(p, &pval, MAX_KEYNAME)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    memcpy(pctx->key_name, key_name, MAX_KEYNAME);
    pctx->key = 0;

    for (i = 0; i < MAX_KEYNAME; i++)
         pctx->key ^= pctx->key_name[i];

    return 0;
}
*/

static OSSL_FUNC_cipher_newctx_fn fake_newctx;
static void *fake_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(PROV_CIPHER_FAKE_CTX));
}

static OSSL_FUNC_cipher_freectx_fn fake_freectx;
static void fake_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static OSSL_FUNC_cipher_encrypt_init_fn fake_einit;
static int fake_einit(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[])
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;

    /*FIXME*/

    ctx->enc = 1;
    return 1;
}

static OSSL_FUNC_cipher_decrypt_init_fn fake_dinit;
static int fake_dinit(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[])
{
    /*FIXME*/

    return 1;
}


static int fake_opaque_init(PROV_CIPHER_FAKE_CTX *ctx, void *pkeyparam,
                            const unsigned char *iv, size_t ivlen,
                            const OSSL_PARAM params[])
{
    if (pkeyparam != NULL) {
        memcpy(ctx, pkeyparam, sizeof(PROV_CIPHER_FAKE_CTX));
    }
    return 1;
}

static OSSL_FUNC_cipher_encrypt_opaque_init_fn fake_opaque_einit;
static int fake_opaque_einit(void *vctx, void *pkeyparam,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[])
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;
    if (fake_opaque_init(ctx, pkeyparam, iv, ivlen, params) != 1)
        return 0;

    ctx->enc = 1;
    return 1;
}

static OSSL_FUNC_cipher_decrypt_opaque_init_fn fake_opaque_dinit;
static int fake_opaque_dinit(void *vctx, void *pkeyparam,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[])
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;
    if (fake_opaque_init(ctx, pkeyparam, iv, ivlen, params) != 1)
        return 0;

    return 1;
}

static OSSL_FUNC_cipher_cipher_fn fake_cipher;
static int fake_cipher(void *vctx, unsigned char *out, size_t *outl,
                       size_t outsize, const unsigned char *in, size_t inl)
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;
    size_t i;

    if (outsize < inl)
        return 0;
    if (out != NULL && in != out)
        memcpy(out, in, inl);
    for (i=0; i < inl; i++)
        out[i] ^= ctx->key;
    *outl = inl;
    return 1;
}

static OSSL_FUNC_cipher_final_fn fake_final;
static int fake_final(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    *outl = 0;
    return 1;
}

#if 0
static OSSL_FUNC_cipher_get_params_fn fake_get_params;
static int fake_get_params(OSSL_PARAM params[])
{
    /* FIXME return ossl_cipher_generic_get_params(params, 0, 0, 0, 8, 0); */
    return 1;
}

static const OSSL_PARAM fake_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint64(FAKE_CIPHER_PARAM_HANDLE, NULL),
    OSSL_PARAM_uint64(FAKE_CIPHER_PARAM_RAW_KEY, NULL),
    OSSL_PARAM_END
};

static OSSL_FUNC_cipher_gettable_ctx_params_fn fake_gettable_ctx_params;
static const OSSL_PARAM *fake_gettable_ctx_params(ossl_unused void *cctx,
                                                  ossl_unused void *provctx)
{
    return fake_known_gettable_ctx_params;
}

static OSSL_FUNC_cipher_get_ctx_params_fn fake_get_ctx_params;
static int fake_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, FAKE_CIPHER_PARAM_HANDLE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0)) { /*FIXME*/
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}
#endif

static const OSSL_PARAM fake_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(FAKE_CIPHER_PARAM_KEY_NAME, NULL, 0),
    OSSL_PARAM_uint64(FAKE_CIPHER_PARAM_RAW_KEY, NULL),
    OSSL_PARAM_END
};

static OSSL_FUNC_cipher_settable_ctx_params_fn fake_settable_ctx_params;
static const OSSL_PARAM *fake_settable_ctx_params(ossl_unused void *cctx,
                                                  ossl_unused void *provctx)
{
    return fake_known_settable_ctx_params;
}

#if 0
static OSSL_FUNC_cipher_set_ctx_params_fn fake_set_ctx_params;
static int fake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_CIPHER_FAKE_CTX *ctx = (PROV_CIPHER_FAKE_CTX *)vctx;
    const OSSL_PARAM *p;

    /*FIXME*/

    return 1;
}
#endif

static const OSSL_DISPATCH ossl_fake_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void)) fake_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) fake_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) fake_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))fake_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))fake_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))fake_cipher },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))fake_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))fake_cipher },
/* FIXME   { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) fake_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))fake_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))fake_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))fake_set_ctx_params }, */
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))fake_settable_ctx_params },
    { OSSL_FUNC_CIPHER_ENCRYPT_OPAQUE_INIT, (void (*)(void))fake_opaque_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_OPAQUE_INIT, (void (*)(void))fake_opaque_dinit },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM fake_cipher_algs[] = {
    { "fake_cipher", "provider=fake-cipher", ossl_fake_functions},
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fake_cipher_query(void *provctx,
                                            int operation_id,
                                            int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return fake_cipher_algs;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fake_cipher_method[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fake_cipher_query },
    OSSL_DISPATCH_END
};

static int fake_cipher_provider_init(const OSSL_CORE_HANDLE *handle,
                                  const OSSL_DISPATCH *in,
                                  const OSSL_DISPATCH **out, void **provctx)
{
    if (!TEST_ptr(*provctx = OSSL_LIB_CTX_new()))
        return 0;
    *out = fake_cipher_method;
    return 1;
}

OSSL_PROVIDER *fake_cipher_start(OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER *p;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "fake-cipher",
                                             fake_cipher_provider_init))
            || !TEST_ptr(p = OSSL_PROVIDER_try_load(libctx, "fake-cipher", 1)))
        return NULL;

    return p;
}

void fake_cipher_finish(OSSL_PROVIDER *p)
{
    OSSL_PROVIDER_unload(p);
}
