/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "testutil.h"
#include "fake_cipherprov.h"

static OSSL_LIB_CTX *libctx = NULL;

static int test_skey_cipher(void)
{
    int ret = 0;
#if 0
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    int i, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        return 0;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    /* Do a direct fetch to see it works */
    if (!TEST_true(fetch_sig(libctx, "RSA", "provider=fake-rsa", fake_rsa))
        || !TEST_true(fetch_sig(libctx, "RSA", "?provider=fake-rsa", fake_rsa)))
        goto end;

    /* Construct a pkey using precise propq to use our provider */
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA",
                                                   "provider=fake-rsa"))
        || !TEST_true(EVP_PKEY_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, NULL))
        || !TEST_ptr(pkey))
        goto end;

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* try exercising signature_init ops a few times */
    for (i = 0; i < 3; i++) {
        size_t siglen;

        /*
         * Create a signing context for our pkey with optional propq.
         * The sign init should pick both keymgmt and signature from
         * fake-rsa as the key is not exportable.
         */
        if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey,
                                                       "?provider=default")))
            goto end;

        /*
         * If this picks the wrong signature without realizing it
         * we can get a segfault or some internal error. At least watch
         * whether fake-rsa sign_init is exercised by calling sign.
         */
        if (!TEST_int_eq(EVP_PKEY_sign_init(ctx), 1))
            goto end;

        if (!TEST_int_eq(EVP_PKEY_sign(ctx, NULL, &siglen, NULL, 0), 1)
            || !TEST_size_t_eq(siglen, 256))
            goto end;

        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

    ret = 1;

end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
#endif
    return ret;
}

int setup_tests(void)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        return 0;

    ADD_TEST(test_skey_cipher);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
