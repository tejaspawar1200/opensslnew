/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "testutil.h"

#if defined(OPENSSL_NO_DH) && defined(OPENSSL_NO_DSA) && defined(OPENSSL_NO_EC)
# define OPENSSL_NO_KEYPARAMS
#endif

#ifndef OPENSSL_NO_KEYPARAMS
# ifndef OPENSSL_NO_DH
static const unsigned char dhparam_bin[] = {
0x30,0x82,0x01,0x08,0x02,0x82,0x01,0x01,0x00,0xc0,0xd1,0x2e,0x14,0x18,0xbd,0x03,
0xfd,0x39,0xe1,0x99,0xf4,0x93,0x06,0x2d,0x49,0xc6,0xb5,0xb9,0xf0,0x91,0xcb,0x2f,
0x48,0x54,0x79,0x7d,0xc4,0x65,0x11,0x55,0xf7,0x99,0xde,0x42,0x83,0x84,0xc0,0xf8,
0x88,0x89,0xa0,0xff,0xff,0x7d,0xe8,0xef,0x9e,0xbc,0xf7,0x1d,0x70,0x6d,0x3a,0x33,
0x49,0x28,0xa1,0xa3,0xe1,0x41,0xc4,0x8b,0x91,0xf9,0xf2,0xb6,0xe2,0x77,0x79,0x38,
0x7d,0x21,0xb3,0xdf,0x79,0x9c,0x5e,0x65,0x16,0x00,0x16,0x82,0xb2,0x36,0x46,0x21,
0xac,0xaf,0x86,0xc7,0xe3,0x10,0x44,0x48,0xfb,0xbd,0xad,0x4e,0x11,0x73,0x4c,0x25,
0xb0,0x8c,0x1c,0x1e,0x8e,0x58,0x50,0x5e,0x43,0x89,0xe4,0xd9,0x34,0xf8,0x3b,0xcc,
0x36,0x2c,0x1b,0xb3,0xb2,0x77,0x0c,0xa5,0x96,0xc1,0x8a,0x38,0xd4,0xe3,0x9c,0x2a,
0xde,0x49,0x46,0xc7,0xd4,0xa2,0x47,0xc9,0x0a,0xbd,0x84,0xd4,0x1c,0xbc,0xb6,0x19,
0x04,0x94,0x64,0xfa,0x8a,0x11,0x9c,0x5f,0x4a,0x4c,0x0f,0x58,0x81,0x02,0xbf,0xcf,
0x87,0x27,0x2b,0xae,0x8e,0xe2,0x61,0x7a,0xdb,0xba,0x23,0x39,0x25,0x44,0xdc,0x22,
0x75,0xc3,0x28,0xd9,0x12,0x33,0x84,0x32,0xd4,0x5d,0xd9,0x77,0xf8,0x04,0x90,0x38,
0x0a,0xec,0x84,0x93,0x43,0xce,0xe7,0x07,0x42,0x7d,0x2d,0xe0,0x21,0x3b,0x19,0x22,
0xa7,0x8f,0x50,0x31,0xda,0xd0,0x0d,0xd3,0x0b,0xdb,0xad,0xed,0x94,0x92,0xff,0x83,
0x06,0x7f,0x7f,0xd7,0x7b,0x42,0x5b,0xba,0x93,0x7a,0xeb,0x43,0x5f,0xce,0x59,0x26,
0xe8,0x76,0xdc,0xee,0xe2,0xbe,0x36,0x7a,0x83,0x02,0x01,0x02
};
# endif

# ifndef OPENSSL_NO_DSA
static const unsigned char dsaparam_bin[] = {
0x30,0x82,0x02,0x28,0x02,0x82,0x01,0x01,0x00,0xf2,0x85,0x01,0xa5,0xb9,0x56,0x65,
0x19,0xff,0x9a,0x7d,0xf9,0x90,0xd6,0xaa,0x73,0xac,0xf7,0x94,0xfa,0x8a,0x64,0x6d,
0xa0,0x01,0x42,0xe5,0x45,0xfc,0x53,0x72,0xb0,0x7c,0xe6,0x3b,0xfb,0x09,0x33,0x41,
0x27,0xbd,0x00,0xb5,0x18,0x87,0x62,0xa8,0x2b,0xfc,0xd0,0x52,0x4a,0x14,0x2d,0xaa,
0x36,0xc6,0xf3,0xa9,0xe3,0x90,0x1b,0x74,0xdf,0x0a,0x6d,0x33,0xba,0xf4,0x32,0x6d,
0xba,0x36,0x68,0x1d,0x83,0x36,0x50,0xc6,0x62,0xc0,0x40,0x67,0x0e,0xf6,0x22,0x00,
0x62,0x1b,0x76,0x72,0x62,0x5f,0xa0,0xdf,0x38,0xb1,0x1d,0x26,0x70,0x9b,0x84,0x64,
0xbb,0x16,0x15,0xc2,0x66,0xb9,0x97,0xd0,0x07,0xf1,0x4b,0x70,0x02,0x03,0xf1,0xd2,
0x03,0xdb,0x78,0x8b,0xb4,0xda,0x6f,0x3c,0xe2,0x31,0xa8,0x1c,0x99,0xea,0x9c,0x75,
0x28,0x96,0x82,0x16,0x77,0xac,0x79,0x32,0x61,0x87,0xec,0xb7,0xb4,0xc3,0xea,0x12,
0x62,0x1f,0x08,0xb8,0x16,0xab,0xcc,0xef,0x28,0xdf,0x06,0x07,0xbe,0xb0,0xdc,0x78,
0x83,0x8a,0x70,0x80,0x34,0xe6,0x91,0xe3,0xd3,0x92,0xd9,0xf4,0x56,0x53,0x52,0xb7,
0x35,0xf6,0x2a,0xec,0x4b,0xcb,0xa2,0x3c,0xc3,0x0c,0x94,0xa7,0x4e,0x1c,0x42,0x9c,
0x72,0x99,0x60,0x8c,0xfe,0xfb,0x60,0x57,0x75,0xf5,0x23,0x11,0x12,0xba,0x97,0xcd,
0xad,0x5a,0x0b,0xa6,0x1f,0x6a,0x48,0x2e,0x8d,0xda,0x95,0xc6,0x0e,0x14,0xde,0xf7,
0x22,0x55,0xa8,0x6b,0x25,0xdf,0xa2,0xab,0x33,0x65,0x56,0xfc,0x78,0x4f,0x62,0xdf,
0x48,0xdd,0xce,0x8b,0xe1,0x76,0xf4,0xf6,0x7f,0x02,0x1d,0x00,0xac,0xb0,0xb8,0x92,
0x3b,0x6b,0x61,0xcf,0x36,0x6d,0xf2,0x1e,0x5d,0xe0,0x7b,0xf5,0x73,0x48,0xa3,0x8b,
0x86,0x9e,0x88,0xce,0x40,0xf8,0x27,0x6d,0x02,0x82,0x01,0x00,0x77,0x6b,0x89,0xd6,
0x8f,0x3d,0xce,0x52,0x30,0x74,0xb2,0xa1,0x13,0x96,0xd5,0x92,0xf2,0xf1,0x6b,0x10,
0x31,0x0b,0xf3,0x69,0xaa,0xbf,0x4b,0x6c,0xcb,0x3f,0x6d,0x58,0x76,0x44,0x09,0xf9,
0x28,0xef,0xa0,0xe4,0x55,0x77,0x57,0xe0,0xfb,0xcc,0x9a,0x6a,0x2c,0x90,0xec,0x72,
0x24,0x0b,0x43,0xc5,0xbc,0x31,0xed,0x1a,0x46,0x2c,0x76,0x42,0x9e,0xc0,0x82,0xfc,
0xff,0xf9,0x7e,0xe2,0x1f,0x39,0xf3,0x3b,0xdb,0x27,0x36,0xe7,0xf5,0x3b,0xc2,0x23,
0xb6,0xd0,0xcf,0x5b,0x85,0x2e,0x1b,0x00,0x5b,0x31,0xaa,0x72,0x8f,0x37,0xee,0x56,
0x71,0xc4,0xfd,0x3c,0x8d,0xfa,0x5b,0xab,0xb1,0xa9,0x52,0x76,0xa0,0xe4,0xe3,0x78,
0x83,0x64,0x5d,0xd7,0x6c,0xec,0x9b,0x40,0x65,0xe2,0x0a,0x11,0x19,0x60,0xdd,0xce,
0x29,0x9f,0xc6,0x1d,0x0a,0xab,0x8e,0x59,0x25,0xc5,0x0b,0x9c,0x02,0x45,0xba,0x99,
0x74,0x22,0x1d,0xc1,0x57,0xca,0x50,0x8c,0x5e,0xdf,0xd8,0x5d,0x43,0xae,0x06,0x28,
0x29,0x82,0xf6,0x5a,0xa9,0x51,0xa2,0x04,0x1d,0xbf,0x88,0x15,0x98,0xce,0x8a,0xb4,
0x3b,0xe5,0x30,0x29,0xce,0x0c,0x9b,0xf8,0xdb,0xbf,0x06,0x9f,0xd0,0x59,0x18,0xd4,
0x0b,0x94,0xbf,0xe9,0x67,0x6b,0x9e,0xf0,0x72,0xc6,0xbf,0x79,0x8f,0x1e,0xa3,0x95,
0x24,0xe3,0xcb,0x58,0xb5,0x67,0xd3,0xae,0x79,0xb0,0x28,0x9c,0x9a,0xd0,0xa4,0xe7,
0x22,0x15,0xc1,0x8b,0x04,0xb9,0x8a,0xa8,0xb7,0x1b,0x62,0x44,0xc6,0xef,0x4b,0x74,
0xd0,0xfd,0xa9,0xb4,0x4e,0xdd,0x7d,0x38,0x60,0xd1,0x40,0xcd
};
# endif

# ifndef OPENSSL_NO_EC
static const unsigned char ecparam_bin[] = {
0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
};
# endif

static const struct {
    int type;
    const unsigned char *param_bin;
    size_t param_bin_len;
} pkey_params [] = {
# ifndef OPENSSL_NO_DH
    { EVP_PKEY_DH, dhparam_bin, sizeof(dhparam_bin) },
# endif
# ifndef OPENSSL_NO_DSA
    { EVP_PKEY_DSA, dsaparam_bin, sizeof(dsaparam_bin) },
# endif
# ifndef OPENSSL_NO_EC
    { EVP_PKEY_EC, ecparam_bin, sizeof(ecparam_bin) }
# endif
};

static int params_bio_test(int id)
{
    int ret, out_len;
    BIO *in = NULL, *out = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *in_key = NULL, *out_key = NULL;
    unsigned char *out_bin;
    int type = pkey_params[id].type;

    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_id(type, NULL))
        && TEST_ptr(in = BIO_new_mem_buf(pkey_params[id].param_bin,
                                        (int)pkey_params[id].param_bin_len))
        /* Load in pkey params from binary */
        && TEST_ptr(d2i_KeyParams_bio(type, &in_key, in))
        && TEST_ptr(out = BIO_new(BIO_s_mem()))
        /* Save pkey params to binary */
        && TEST_int_gt(i2d_KeyParams_bio(out, in_key), 0)
        /* test the output binary is the expected value */
        && TEST_int_gt(out_len = BIO_get_mem_data(out, &out_bin), 0)
        && TEST_mem_eq(pkey_params[id].param_bin,
                       (int)pkey_params[id].param_bin_len,
                       out_bin, out_len);

    BIO_free(in);
    BIO_free(out);
    EVP_PKEY_free(in_key);
    EVP_PKEY_free(out_key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_KEYPARAMS
    TEST_note("No DH/DSA/EC support");
#else
    ADD_ALL_TESTS(params_bio_test, OSSL_NELEM(pkey_params));
#endif
    return 1;
}
