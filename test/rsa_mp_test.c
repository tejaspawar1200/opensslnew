/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 BaishanCloud. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This aims to test the setting functions */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "testutil.h"

#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>

#define NUM_EXTRA_PRIMES 1

static int key2048p3(RSA *key)
{
    /* C90 requires string should <= 509 bytes */
    static const unsigned char n[] =
        "\x92\x60\xd0\x75\x0a\xe1\x17\xee\xe5\x5c\x3f\x3d\xea\xba\x74\x91"
        "\x75\x21\xa2\x62\xee\x76\x00\x7c\xdf\x8a\x56\x75\x5a\xd7\x3a\x15"
        "\x98\xa1\x40\x84\x10\xa0\x14\x34\xc3\xf5\xbc\x54\xa8\x8b\x57\xfa"
        "\x19\xfc\x43\x28\xda\xea\x07\x50\xa4\xc4\x4e\x88\xcf\xf3\xb2\x38"
        "\x26\x21\xb8\x0f\x67\x04\x64\x43\x3e\x43\x36\xe6\xd0\x03\xe8\xcd"
        "\x65\xbf\xf2\x11\xda\x14\x4b\x88\x29\x1c\x22\x59\xa0\x0a\x72\xb7"
        "\x11\xc1\x16\xef\x76\x86\xe8\xfe\xe3\x4e\x4d\x93\x3c\x86\x81\x87"
        "\xbd\xc2\x6f\x7b\xe0\x71\x49\x3c\x86\xf7\xa5\x94\x1c\x35\x10\x80"
        "\x6a\xd6\x7b\x0f\x94\xd8\x8f\x5c\xf5\xc0\x2a\x09\x28\x21\xd8\x62"
        "\x6e\x89\x32\xb6\x5c\x5b\xd8\xc9\x20\x49\xc2\x10\x93\x2b\x7a\xfa"
        "\x7a\xc5\x9c\x0e\x88\x6a\xe5\xc1\xed\xb0\x0d\x8c\xe2\xc5\x76\x33"
        "\xdb\x26\xbd\x66\x39\xbf\xf7\x3c\xee\x82\xbe\x92\x75\xc4\x02\xb4"
        "\xcf\x2a\x43\x88\xda\x8c\xf8\xc6\x4e\xef\xe1\xc5\xa0\xf5\xab\x80"
        "\x57\xc3\x9f\xa5\xc0\x58\x9c\x3e\x25\x3f\x09\x60\x33\x23\x00\xf9"
        "\x4b\xea\x44\x87\x7b\x58\x8e\x1e\xdb\xde\x97\xcf\x23\x60\x72\x7a"
        "\x09\xb7\x75\x26\x2d\x7e\xe5\x52\xb3\x31\x9b\x92\x66\xf0\x5a\x25";

    static const unsigned char e[] = "\x01\x00\x01";

    static const unsigned char d[] =
        "\x6a\x7d\xf2\xca\x63\xea\xd4\xdd\xa1\x91\xd6\x14\xb6\xb3\x85\xe0"
        "\xd9\x05\x6a\x3d\x6d\x5c\xfe\x07\xdb\x1d\xaa\xbe\xe0\x22\xdb\x08"
        "\x21\x2d\x97\x61\x3d\x33\x28\xe0\x26\x7c\x9d\xd2\x3d\x78\x7a\xbd"
        "\xe2\xaf\xcb\x30\x6a\xeb\x7d\xfc\xe6\x92\x46\xcc\x73\xf5\xc8\x7f"
        "\xdf\x06\x03\x01\x79\xa2\x11\x4b\x76\x7d\xb1\xf0\x83\xff\x84\x1c"
        "\x02\x5d\x7d\xc0\x0c\xd8\x24\x35\xb9\xa9\x0f\x69\x53\x69\xe9\x4d"
        "\xf2\x3d\x2c\xe4\x58\xbc\x3b\x32\x83\xad\x8b\xba\x2b\x8f\xa1\xba"
        "\x62\xe2\xdc\xe9\xac\xcf\xf3\x79\x9a\xae\x7c\x84\x00\x16\xf3\xba"
        "\x8e\x00\x48\xc0\xb6\xcc\x43\x39\xaf\x71\x61\x00\x3a\x5b\xeb\x86"
        "\x4a\x01\x64\xb2\xc1\xc9\x23\x7b\x64\xbc\x87\x55\x69\x94\x35\x1b"
        "\x27\x50\x6c\x33\xd4\xbc\xdf\xce\x0f\x9c\x49\x1a\x7d\x6b\x06\x28"
        "\xc7\xc8\x52\xbe\x4f\x0a\x9c\x31\x32\xb2\xed\x3a\x2c\x88\x81\xe9"
        "\xaa\xb0\x7e\x20\xe1\x7d\xeb\x07\x46\x91\xbe\x67\x77\x76\xa7\x8b"
        "\x5c\x50\x2e\x05\xd9\xbd\xde\x72\x12\x6b\x37\x38\x69\x5e\x2d\xd1"
        "\xa0\xa9\x8a\x14\x24\x7c\x65\xd8\xa7\xee\x79\x43\x2a\x09\x2c\xb0"
        "\x72\x1a\x12\xdf\x79\x8e\x44\xf7\xcf\xce\x0c\x49\x81\x47\xa9\xb1";

    static const unsigned char p[] =
        "\x06\x77\xcd\xd5\x46\x9b\xc1\xd5\x58\x00\x81\xe2\xf3\x0a\x36\xb1"
        "\x6e\x29\x89\xd5\x2f\x31\x5f\x92\x22\x3b\x9b\x75\x30\x82\xfa\xc5"
        "\xf5\xde\x8a\x36\xdb\xc6\xe5\x8f\xef\x14\x37\xd6\x00\xf9\xab\x90"
        "\x9b\x5d\x57\x4c\xf5\x1f\x77\xc4\xbb\x8b\xdd\x9b\x67\x11\x45\xb2"
        "\x64\xe8\xac\xa8\x03\x0f\x16\x0d\x5d\x2d\x53\x07\x23\xfb\x62\x0d"
        "\xe6\x16\xd3\x23\xe8\xb3";

    static const unsigned char q[] =
        "\x06\x66\x9a\x70\x53\xd6\x72\x74\xfd\xea\x45\xc3\xc0\x17\xae\xde"
        "\x79\x17\xae\x79\xde\xfc\x0e\xf7\xa4\x3a\x8c\x43\x8f\xc7\x8a\xa2"
        "\x2c\x51\xc4\xd0\x72\x89\x73\x5c\x61\xbe\xfd\x54\x3f\x92\x65\xde"
        "\x4d\x65\x71\x70\xf6\xf2\xe5\x98\xb9\x0f\xd1\x0b\xe6\x95\x09\x4a"
        "\x7a\xdf\xf3\x10\x16\xd0\x60\xfc\xa5\x10\x34\x97\x37\x6f\x0a\xd5"
        "\x5d\x8f\xd4\xc3\xa0\x5b";

    static const unsigned char dmp1[] =
        "\x05\x7c\x9e\x1c\xbd\x90\x25\xe7\x40\x86\xf5\xa8\x3b\x7a\x3f\x99"
        "\x56\x95\x60\x3a\x7b\x95\x4b\xb8\xa0\xd7\xa5\xf1\xcc\xdc\x5f\xb5"
        "\x8c\xf4\x62\x95\x54\xed\x2e\x12\x62\xc2\xe8\xf6\xde\xce\xed\x8e"
        "\x77\x6d\xc0\x40\x25\x74\xb3\x5a\x2d\xaa\xe1\xac\x11\xcb\xe2\x2f"
        "\x0a\x51\x23\x1e\x47\xb2\x05\x88\x02\xb2\x0f\x4b\xf0\x67\x30\xf0"
        "\x0f\x6e\xef\x5f\xf7\xe7";

    static const unsigned char dmq1[] =
        "\x01\xa5\x6b\xbc\xcd\xe3\x0e\x46\xc6\x72\xf5\x04\x56\x28\x01\x22"
        "\x58\x74\x5d\xbc\x1c\x3c\x29\x41\x49\x6c\x81\x5c\x72\xe2\xf7\xe5"
        "\xa3\x8e\x58\x16\xe0\x0e\x37\xac\x1f\xbb\x75\xfd\xaf\xe7\xdf\xe9"
        "\x1f\x70\xa2\x8f\x52\x03\xc0\x46\xd9\xf9\x96\x63\x00\x27\x7e\x5f"
        "\x38\x60\xd6\x6b\x61\xe2\xaf\xbe\xea\x58\xd3\x9d\xbc\x75\x03\x8d"
        "\x42\x65\xd6\x6b\x85\x97";

    static const unsigned char iqmp[] =
        "\x03\xa1\x8b\x80\xe4\xd8\x87\x25\x17\x5d\xcc\x8d\xa9\x8a\x22\x2b"
        "\x6c\x15\x34\x6f\x80\xcc\x1c\x44\x04\x68\xbc\x03\xcd\x95\xbb\x69"
        "\x37\x61\x48\xb4\x23\x13\x08\x16\x54\x6a\xa1\x7c\xf5\xd4\x3a\xe1"
        "\x4f\xa4\x0c\xf5\xaf\x80\x85\x27\x06\x0d\x70\xc0\xc5\x19\x28\xfe"
        "\xee\x8e\x86\x21\x98\x8a\x37\xb7\xe5\x30\x25\x70\x93\x51\x2d\x49"
        "\x85\x56\xb3\x0c\x2b\x96";

    static const unsigned char ex_prime[] =
        "\x03\x89\x22\xa0\xb7\x3a\x91\xcb\x5e\x0c\xfd\x73\xde\xa7\x38\xa9"
        "\x47\x43\xd6\x02\xbf\x2a\xb9\x3c\x48\xf3\x06\xd6\x58\x35\x50\x56"
        "\x16\x5c\x34\x9b\x61\x87\xc8\xaa\x0a\x5d\x8a\x0a\xcd\x9c\x41\xd9"
        "\x96\x24\xe0\xa9\x9b\x26\xb7\xa8\x08\xc9\xea\xdc\xa7\x15\xfb\x62"
        "\xa0\x2d\x90\xe6\xa7\x55\x6e\xc6\x6c\xff\xd6\x10\x6d\xfa\x2e\x04"
        "\x50\xec\x5c\x66\xe4\x05";

    static const unsigned char ex_exponent[] =
        "\x02\x0a\xcd\xc3\x82\xd2\x03\xb0\x31\xac\xd3\x20\x80\x34\x9a\x57"
        "\xbc\x60\x04\x57\x25\xd0\x29\x9a\x16\x90\xb9\x1c\x49\x6a\xd1\xf2"
        "\x47\x8c\x0e\x9e\xc9\x20\xc2\xd8\xe4\x8f\xce\xd2\x1a\x9c\xec\xb4"
        "\x1f\x33\x41\xc8\xf5\x62\xd1\xa5\xef\x1d\xa1\xd8\xbd\x71\xc6\xf7"
        "\xda\x89\x37\x2e\xe2\xec\x47\xc5\xb8\xe3\xb4\xe3\x5c\x82\xaa\xdd"
        "\xb7\x58\x2e\xaf\x07\x79";

    static const unsigned char ex_coefficient[] =
        "\x00\x9c\x09\x88\x9b\xc8\x57\x08\x69\x69\xab\x2d\x9e\x29\x1c\x3c"
        "\x6d\x59\x33\x12\x0d\x2b\x09\x2e\xaf\x01\x2c\x27\x01\xfc\xbd\x26"
        "\x13\xf9\x2d\x09\x22\x4e\x49\x11\x03\x82\x88\x87\xf4\x43\x1d\xac"
        "\xca\xec\x86\xf7\x23\xf1\x64\xf3\xf5\x81\xf0\x37\x36\xcf\x67\xff"
        "\x1a\xff\x7a\xc7\xf9\xf9\x67\x2d\xa0\x9d\x61\xf8\xf6\x47\x5c\x2f"
        "\xe7\x66\xe8\x3c\x3a\xe8";

    BIGNUM **pris = NULL, **exps = NULL, **coeffs = NULL;
    int rv = 256; /* public key length */

    if (!TEST_int_eq(RSA_set0_key(key,
                                  BN_bin2bn(n, sizeof(n) - 1, NULL),
                                  BN_bin2bn(e, sizeof(e) - 1, NULL),
                                  BN_bin2bn(d, sizeof(d) - 1, NULL)), 1))
        goto err;

    if (!TEST_int_eq(RSA_set0_factors(key,
                                      BN_bin2bn(p, sizeof(p) - 1, NULL),
                                      BN_bin2bn(q, sizeof(q) - 1, NULL)), 1))
        goto err;

    if (!TEST_int_eq(RSA_set0_crt_params(key,
                                         BN_bin2bn(dmp1, sizeof(dmp1) - 1, NULL),
                                         BN_bin2bn(dmq1, sizeof(dmq1) - 1, NULL),
                                         BN_bin2bn(iqmp, sizeof(iqmp) - 1,
                                                   NULL)), 1))
        return 0;

    pris = OPENSSL_zalloc(sizeof(BIGNUM *));
    exps = OPENSSL_zalloc(sizeof(BIGNUM *));
    coeffs = OPENSSL_zalloc(sizeof(BIGNUM *));
    if (!TEST_ptr(pris) || !TEST_ptr(exps) || !TEST_ptr(coeffs))
        goto err;

    pris[0] = BN_bin2bn(ex_prime, sizeof(ex_prime) - 1, NULL);
    exps[0] = BN_bin2bn(ex_exponent, sizeof(ex_exponent) - 1, NULL);
    coeffs[0] = BN_bin2bn(ex_coefficient, sizeof(ex_coefficient) - 1, NULL);
    if (!TEST_ptr(pris[0]) || !TEST_ptr(exps[0]) || !TEST_ptr(coeffs[0]))
        goto err;

    if (!TEST_true(RSA_set0_multi_prime_params(key, pris, exps,
                                               coeffs, NUM_EXTRA_PRIMES)))
        goto err;

 ret:
    OPENSSL_free(pris);
    OPENSSL_free(exps);
    OPENSSL_free(coeffs);
    return rv;
 err:
    if (pris != NULL)
        BN_free(pris[0]);
    if (exps != NULL)
        BN_free(exps[0]);
    if (coeffs != NULL)
        BN_free(coeffs[0]);
    rv = 0;
    goto ret;
}

static int test_rsa_mp(void)
{
    int ret = 0;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    int plen;
    int clen = 0;
    int num;

    plen = sizeof(ptext_ex) - 1;
    key = RSA_new();
    if (!TEST_ptr(key))
        goto err;
    clen = key2048p3(key);
    if (!TEST_int_eq(clen, 256))
        goto err;

    if (!TEST_true(RSA_check_key_ex(key, NULL)))
        goto err;

    num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
                             RSA_PKCS1_PADDING);
    if (!TEST_int_eq(num, clen))
        goto err;

    num = RSA_private_decrypt(num, ctext, ptext, key, RSA_PKCS1_PADDING);
    if (!TEST_mem_eq(ptext, num, ptext_ex, plen))
        goto err;

    ret = 1;
err:
    RSA_free(key);
    return ret;
}

#define NUM_INSECURE_EXTRA_PRIMES 5

static int key4096p7(RSA *key)
{
    /* C90 requires string should <= 509 bytes */

    static unsigned char n1[] =
        "\x00\xeb\xa2\x2b\x74\x76\x32\x33\xbf\xb9\x9a\xe4\xb0\x84\xac"
        "\x9a\x20\x1b\xe6\x1a\x22\x3f\xcd\x13\xe1\x42\xee\xd8\x1a\x6e"
        "\xe3\xd5\x91\x1e\xee\x32\x5c\x78\x76\x8b\x5d\x82\x6f\xd0\xaf"
        "\xa3\x56\xd6\x15\x5f\x64\xb3\x5a\xcf\xc8\x7d\xa3\xb1\x3d\x10"
        "\xbf\x47\x00\xa9\xc9\x96\x9d\xfd\x7c\x82\x4f\xb5\x70\x39\xd4"
        "\xd9\x0f\xd7\xd9\x86\xd4\xd4\x35\x06\x35\x07\xa3\x1b\x8c\xf4"
        "\x35\xb8\xb2\xd4\xa3\xbe\x6c\x64\x7d\x74\x17\x88\x36\x07\x32"
        "\x6f\x84\x48\xd4\xb8\x4a\x12\xba\xe8\x40\x5b\xc6\xa5\xa4\x11"
        "\x0d\x8a\xa6\x60\x3d\x98\x8b\xf8\x11\x8f\x43\xab\x2f\x95\x0f"
        "\x3b\x20\x3f\x48\x88\xaa\x3d\x20\xa6\xaf\x6a\xdf\xc0\x95\x38"
        "\xff\x47\x7c\x8a\x8b\xec\x76\x45\x43\xd0\x06\x7c\x71\x76\x5f"
        "\x0d\x11\x58\x0a\xa9\x0e\x7e\x07\xe9\x89\xc1\x9e\x56\x6d\x08"
        "\xe4\xe3\x16\xb4\xa0\x03\x7a\x49\x96\xa8\x88\xcf\x89\xe3\xdb"
        "\x47\x0c\xd2\x1b\x6f\x67\x4d\xc8\xee\x53\xe9\x0b\x3d\xe5\x11"
        "\x9d\x85\x75\xfe\x26\x4a\x99\x58\x79\x28\x91\x03\x8b\xe4\xbf"
        "\x49\xd3\xfa\x8e\x25\xe3\xb1\xb2\xc2\x33\xd9\x8b\xe0\x9d\x1b"
        "\xa4\xa0\xcf\x05\x5f\xb9\x19\x65\x74\x24\xae\x2e\x33\xc8\xd9";

    static unsigned char n2[] =
        "\x55\xae\xcb\x37\xa1\x3b\x95\xf7\x5f\xff\x1f\x06\x4a\xab\x85"
        "\x94\x37\x15\x6f\xf2\xc8\x9b\x73\xb9\x1d\x8e\x30\x63\x5a\xa1"
        "\x84\x31\xa8\xbe\x7e\x4f\xeb\xa0\xe6\x73\xc7\xbe\xd4\x5e\xe7"
        "\x5e\xae\x5d\xfd\xf7\xf5\xa4\xb6\xb8\x3c\x15\xac\x1b\xcd\x3a"
        "\xb6\xbd\xa9\x11\xd0\x44\xa5\x08\x7e\x60\x1d\x1d\x4d\xa6\xd7"
        "\x06\xe5\x4f\x37\x0d\x5c\xbd\xad\x8d\x40\x18\xbd\xc7\x58\x20"
        "\xed\xa8\x4d\xd8\x29\xdc\x42\x4f\x50\xa6\x03\xf0\xa5\xa2\x18"
        "\x2b\xdd\x1c\x0e\x89\x3f\xbc\x5d\x35\xac\xa8\x55\x6d\x17\x28"
        "\xae\xee\x78\xeb\x6d\x7a\x21\xd6\x6c\xdd\x21\x1d\xcc\xe5\xb0"
        "\xf2\xef\x7f\x1d\x8a\xb7\x95\xaf\x40\xb5\x5c\x8b\x0d\x59\x45"
        "\x21\x86\x34\x6d\x13\xd7\x14\xa5\x0e\xca\x88\x32\x57\xfe\x2d"
        "\xd1\xcb\xad\x14\xbe\x30\xb1\x69\x9b\x72\x82\xad\x47\xb5\x45"
        "\xc8\x65\x83\xce\x07\x21\x15\x6b\x65\x9d\xf3\x4d\x92\x19\xbe"
        "\x67\x73\xd0\x60\x9f\xc7\xef\xee\xfa\xb0\xd3\xa4\x95\x81\xb0"
        "\xbd\x4b\xd5\xf8\xbd\xbd\x9f\x41\x41\xc0\xfd\xe9\x17\xe3\x16"
        "\xd3\xdc\xc8\xe2\xa5\xca\xff\xea\x91\xf4\x33\xc0\xfb\xdc\x02"
        "\x62\x0a\x4e\x26\x92\xb5\x13\xec\x43\xd2\x25\x19\xe2\x6d\xef"
        "\xea\x38\x75";

    static unsigned char e[] = "\x01\x00\x01";

    static unsigned char d1[] =
        "\x60\x43\x92\x69\x33\xd8\x72\x97\xc3\x25\xea\x83\xca\xd0\x10"
        "\xef\x49\x36\x8a\x3a\xaf\xc2\x02\x7b\x26\xb3\x19\x0a\x43\x7f"
        "\x44\xc2\xd2\xd6\x11\x31\x01\xed\xbc\x25\xe9\xa1\xf0\xa9\xb0"
        "\x9b\x4b\x3e\xd4\x07\xf9\xd6\x01\xc9\x30\xba\xed\x2f\xbb\x65"
        "\xc9\x86\x15\xd7\x4b\x77\x24\x15\xf7\xce\xc4\x9b\x21\x62\x4d"
        "\xde\x77\xf0\x1e\x62\x49\x54\xda\xda\xcd\xdd\x0f\x53\xe2\xd2"
        "\x39\x4f\x60\x8e\xec\xe3\x49\x1b\xe7\x9a\x3e\x17\x8e\x5a\x77"
        "\x4a\x15\xf6\x57\xc5\xfe\x2b\xa5\x94\x04\x94\x9c\xe7\xa8\xcc"
        "\x07\x4b\xd8\xb8\x55\xaa\xdf\x33\xca\x2c\x8c\xee\x61\x1a\x89"
        "\x0d\x3b\xcd\x16\x28\xb5\x50\x62\x2f\xb1\x9e\x61\x27\xd7\xf1"
        "\xe1\x22\x58\x84\xcd\x18\xc3\xbf\xde\x52\x25\xdd\xc1\xcd\x2a"
        "\x20\x78\x5e\xde\x65\x6a\x25\x12\x2d\x78\x28\xdb\x2c\x6f\x1b"
        "\x65\x71\x1b\x2e\x1c\x18\x62\xf6\x71\x82\xdc\xa8\x80\x0e\xb5"
        "\x8b\x09\x97\xc3\x81\xe1\x23\x2e\x40\x75\xbf\xd3\x78\xdc\xd5"
        "\xc3\xe6\x75\x8b\xb0\x48\x7a\x78\x7d\xfe\xcc\x4c\xa1\x40\x11"
        "\x20\xbe\x2a\xc1\xaf\x18\x53\x45\x6a\xb4\x2a\x0a\xc9\x01\x36"
        "\x60\xf1\x61\x97\x73\xde\xac\x3e\x24\xff\x5b\x25\xdb\x93\x97";

    static unsigned char d2[] =
        "\x03\xf4\xef\x4a\x73\x47\xa8\x31\xd1\x63\x5b\xba\xa6\xe2\x7a"
        "\xd8\xef\xea\x2f\x04\x76\x3c\x7a\x8d\x4e\xc1\x81\xc5\x39\x4f"
        "\x09\xc4\xb1\xfb\x75\xd0\xae\x32\x2e\x44\xa3\xb6\xdc\x60\xc6"
        "\x60\x1e\x40\x6f\x04\xc2\x7a\xd3\x0f\x8a\xa4\x23\x8f\x0e\x2e"
        "\x2a\xcd\x65\x2a\x6e\x97\xa8\xe5\x01\x96\xd1\x41\x27\xa5\x16"
        "\x2f\xb0\x15\x0a\x33\x06\x72\x40\xa5\xe4\x74\xbe\x4a\x87\x28"
        "\x8a\x68\xea\x39\x42\x08\x47\xff\x9d\x9e\x06\x03\xfa\x4a\x6a"
        "\xbb\xe5\x6f\x97\x05\x5f\xae\x47\xe6\xc4\xe0\x48\x62\x65\x9b"
        "\x91\x50\xda\x84\xcf\xa3\xb2\x9d\x51\x84\x02\x4b\xe6\x12\xa2"
        "\x87\x6e\x1f\x43\x2f\x90\x36\xb1\x15\xc6\xf6\xe0\xde\x52\x39"
        "\x8e\x22\x39\x8c\x4f\x1c\x08\xac\x55\x5c\xa9\x69\x4e\x77\x8d"
        "\x74\x6e\x0b\x06\xda\x61\xcd\xe2\xc8\xc6\x02\x54\x70\x05\xc1"
        "\x50\x6d\x5e\x3e\x66\x7d\x41\x3c\x57\x68\x8a\x16\xb9\xd8\x29"
        "\xfb\xeb\x05\x57\x87\xdc\x88\xc6\x91\x67\x3c\xcc\x19\x28\xa1"
        "\x23\x54\xc3\x88\xc4\x28\x63\xca\xf7\xb2\xea\x34\xa1\x9e\xc1"
        "\xca\x9b\x96\xe7\x4d\x82\x22\xf9\xcb\xc3\x2a\x3f\x19\xe3\x7c"
        "\xce\x8c\x66\x45\xfe\xe6\x31\x31\x66\xd4\x1a\xb5\x47\x98\xea"
        "\x80\x01";

    static unsigned char p[] =
        "\x03\xf5\x90\x21\xf3\xa6\x13\xdd\x33\x2a\x4c\x1f\x53\xd6\x9e"
        "\x64\x1d\xfc\xed\xfb\xa1\xe6\xd0\x80\xd1\x6a\xcd\x20\x68\xea"
        "\x75\x72\x59\x24\x8b\x1b\x28\x37\xbd\x8f\xc4\xc9\xb6\xda\xef"
        "\x55\xb9\x0e\x26\x93\x8a\x8a\xec\x2f\x47\xe6\x4e\xa9\x42\xfb"
        "\x02\x28\x5e\x37\xb7\x5a\x61\xfa\x39\xab\x63\x61\x1b\xbb";

    static unsigned char q[] =
        "\x01\xea\x64\x6e\x7d\xaa\xd7\x6a\xfa\x0c\x52\xfa\x2b\x00\x51"
        "\x7d\x4d\xc3\x9f\x1d\x21\xb2\x62\x11\xd4\x7d\x0e\xc2\xe7\xdf"
        "\xd0\x04\xd6\x30\x02\x54\xb2\xa5\xb7\x85\xd5\x96\xc7\x24\x83"
        "\x8e\x3d\x60\xc3\x42\xa5\xa3\x76\xdd\x6e\x60\xa0\xbf\x85\x05"
        "\xb6\x52\x32\xeb\x41\x6f\x08\xc8\x56\x43\xd8\x80\x06\xf7";

    static unsigned char dmp1[] =
        "\x03\xcc\x5c\xe7\x45\x91\x49\xb3\x47\x77\xc7\xa9\xb2\x4b\xce"
        "\x8e\xab\xfa\x4f\xf1\xbd\x63\xeb\x19\xfa\x4e\x64\xd6\x37\xf0"
        "\xde\x95\xc2\x11\x7d\xe6\xa2\xd1\xbe\xe9\x23\x58\x85\x35\x4a"
        "\xb0\xc9\xa5\x5a\xba\xe7\x09\xda\x06\x8e\x0a\xd3\xe2\x2c\x61"
        "\x14\xb3\xd7\x97\xca\x2e\x4a\x9a\xbd\x22\xc0\x67\x94\x2b";

    static unsigned char dmq1[] =
        "\x01\x66\x28\x8d\xce\x38\x8d\x76\xb3\x43\x77\x03\x01\x8f\x0c"
        "\xf5\x40\x6b\x84\x75\x69\x5b\xf8\x66\x5f\x54\x2b\x08\xcd\x03"
        "\x58\xd1\x7f\x81\xb6\xe2\x17\x4c\x13\x3a\xab\x21\xa1\x36\x98"
        "\xe2\xb5\x0f\x4b\xed\x0c\x3e\xd4\x1c\xab\x75\xe5\x51\x9b\x9c"
        "\xed\x69\x21\x89\x52\xd3\xfe\x8d\x1a\xfc\x18\x4e\x81\x47";

    static unsigned char iqmp[] =
        "\x02\x31\xad\xe8\xa5\xa9\x5d\x52\x70\x68\xc1\x6e\x6b\x4e\xb5"
        "\x0b\xc2\xd9\x89\xe5\xbc\x46\xca\xac\xac\x04\xe2\x39\x7f\xc4"
        "\xa0\xe4\x9e\x8a\xb8\x1e\x67\x66\x85\xb8\x3e\x42\x7c\xc7\x2c"
        "\x02\x64\x7c\xd3\x40\xda\x5d\x9f\x38\xa7\x7c\x30\xcd\x6b\x7d"
        "\x4d\xd0\x77\x2d\x9b\xd1\xc3\x55\x03\x69\x3d\xda\x48\xe2";

    static char *primes[] = {
        "\x01\xb2\xe2\xf7\x3b\x29\xdc\x90\xf9\xc4\x5a\x75\x09\x00\xbe"
        "\xec\xa6\x97\xbc\x47\x89\x24\x71\x48\xa7\xc9\xc8\xed\x9c\x88"
        "\xb9\x9f\xcd\x79\xc9\x2d\xb1\x78\xf7\x54\x2c\x28\x01\x37\x01"
        "\xa0\xff\xf2\x69\x52\x93\xf0\x16\x08\xaa\x2f\xff\x35\x14\x2d"
        "\x65\x8d\x21\x05\x30\x84\x9b\xcb\x58\x42\xc6\x9b\xa7\xb5",

        "\x01\xb7\x66\xfe\xb5\x94\xf8\x46\xcb\x06\x2a\x7a\xd4\x35\xe4"
        "\x68\x6d\xcf\x58\x0b\xb3\x12\xe6\x7b\x66\xee\x36\xf5\x1f\x79"
        "\x8f\x82\x1e\xd9\x97\x33\x45\x37\xa3\x84\x54\xab\x4b\x12\x96"
        "\x76\x9f\xf9\x98\x02\xf1\x5e\xcb\x97\xe8\x13\xde\x91\x0b\xd5"
        "\xec\x7f\x2b\x27\x55\xc1\x69\x58\xad\x8b\xaa\xce\x68\xc5",

        "\x01\xbe\xdf\xa5\x33\xfb\xa1\xfa\xf6\xd2\x43\xcd\x76\x3e\x23"
        "\xa2\xf7\x29\xeb\x65\xe5\xae\xe8\xfc\xfd\xca\x55\x16\x01\x57"
        "\xcd\xca\x9e\x83\xf9\x61\x6a\x17\xac\x61\xec\x04\x32\x9f\x69"
        "\xb8\x6d\x66\x33\x9b\xef\xf4\x91\xf1\x99\x02\xc2\xea\x58\x6e"
        "\xad\x3d\x0e\xa9\x87\x17\x7c\x9b\x72\xcc\xab\x1c\x93\x2b",

        "\x03\x2f\x4a\x9c\x49\x66\x9d\xbc\xae\xec\x54\x7d\xe6\x07\x52"
        "\xc2\x9a\x09\xf5\xa7\x56\xa6\x68\x45\x38\x75\x7d\xb0\x0e\xee"
        "\xf3\x23\xec\x74\x1e\x3b\xc0\x58\x1d\x43\xd9\x35\x15\x7e\x2f"
        "\x28\xff\x08\x7a\x79\x44\xfc\x24\x06\xc5\x3f\xaa\xe0\xfa\xb2"
        "\x1f\xd9\x4e\xd8\xc8\xda\xed\x1f\xaa\x77\x64\xae\xb3\xe3",

        "\x01\xea\xaa\x9d\x90\x67\x3b\x2f\x9a\xe3\x7b\x56\x5c\x35\x9f"
        "\x65\x0b\x0c\x3b\xa6\x60\x5f\x98\x36\x2c\xb6\xaa\xdb\xb2\x86"
        "\x8b\x20\xba\xa4\x85\x7b\xa8\x80\x41\xee\x22\x1c\x7a\x92\xf5"
        "\x39\x4e\x4a\x0b\x29\x0b\xe7\xdd\x3c\xb6\x51\xec\xc3\x26\xbc"
        "\x33\x11\xbc\x29\x7a\x10\x68\x32\x55\xb4\x15\xd9\x8e\xc1"
    };

    static int primes_len[] = { 74, 74, 74, 74, 74 };

    static char *exponents[] = {
        "\x01\xa4\x49\xb7\x57\xc5\x50\x36\x08\x3c\xdc\x93\x29\x1d\x40"
        "\x67\x63\x65\x57\x7f\xe7\x29\x82\x16\x0e\x9a\x74\x06\x37\x76"
        "\xe7\xb6\x6a\x15\x5d\xf9\x3c\x00\x45\x3f\x62\xe1\x52\xb3\x3f"
        "\x6e\xc2\x8d\x1b\x7e\xc4\x1c\x8e\x9e\xd7\x23\x45\xc8\x9d\x74"
        "\x76\x25\x5b\x99\x31\x57\xa7\x5d\x71\x32\x2f\xd1\x74\xd5",

        "\x01\x3a\xa4\x6d\x05\xf7\xeb\xa5\x3d\xe2\x67\x6e\xd7\x20\xd4"
        "\x33\x17\x56\xdf\x34\x59\x81\xd2\x3b\x51\x64\x89\x44\x13\xca"
        "\xc7\x41\xa4\xf7\xa8\xf6\xd4\xbc\xd7\xc1\x7d\xa3\xbf\x39\x4b"
        "\x37\x1c\xac\xec\xf6\x46\x82\xdc\x05\x25\xf1\x7c\x71\x9e\xe9"
        "\x0b\xd5\xb0\x40\x15\x7f\x4f\x01\x6a\x1c\x56\x2e\x42\x05",

        "\x00\x9b\xd7\x14\x9e\xcf\x47\x4a\xe5\x1e\xa8\xc4\x93\x52\xd2"
        "\x4c\xb7\xd3\x67\xa3\x4e\x79\x34\x09\x5e\x5c\x5c\x55\xe3\x3c"
        "\x02\xa9\x81\xa4\x56\xa8\xb1\x3d\xf6\x40\xe3\xf5\x06\xce\x6f"
        "\x29\x01\x05\xde\x43\xa8\x67\xeb\x29\x8d\x09\xd8\x7d\xaf\x3f"
        "\x51\xac\xf4\x5b\x0c\xa0\x95\x35\x04\xd0\xf9\x6f\x6a\xa7",

        "\x02\xfd\x38\x42\x48\x82\x90\x3a\xb0\xd4\x10\xd9\xba\x35\xd5"
        "\x6f\xe1\xb4\xc7\x65\x30\xe7\x2f\xa7\x08\xbe\xfe\x21\x69\x62"
        "\xcd\xc3\x42\x04\x1a\xfc\x6a\x24\x4a\x13\x8c\xa3\x4e\x71\x09"
        "\x42\xa9\x5d\x03\xd7\x1e\xf0\xa9\xbf\xd1\x13\x59\x07\xa1\x45"
        "\xde\xae\xd0\x5a\x98\xeb\x22\xf5\x3d\xc2\xa2\x35\x77\x91",

        "\x13\x1d\x2c\x60\x28\xb5\x54\x88\x6b\x1e\x2d\xe2\x0f\xb0\xb2"
        "\xe5\xf8\x47\x06\x97\x30\x82\x24\x72\x1f\x77\x8e\x71\x68\xee"
        "\x58\x8b\x0c\xc7\xaa\x66\x89\x00\x88\x7f\x49\xae\xb8\xb4\xd6"
        "\xd3\xa6\xec\xc2\x5f\x95\x5b\xb7\xf6\xbe\x40\x43\xe5\xe9\x64"
        "\xef\xe6\xed\x92\xb4\xba\xea\x63\x0e\x4d\xdf\x98\xc1"
    };

    static int exps_len[] = { 74, 74, 74, 74, 73 };

    static char *coefficients[] = {
        "\x18\x19\x50\xc2\x69\x6a\x63\x66\x40\x6a\x43\xa6\x7d\x0d\x12"
        "\x0f\x04\x3a\xe7\xb2\x1c\xe3\xfc\x6f\xa7\x8b\x5e\x99\xe3\x43"
        "\x97\x68\x10\xee\x68\x73\x01\xc6\xaf\x5e\x26\xaf\xcc\x1f\x39"
        "\x9c\x8d\xa9\x06\x80\x21\x7a\xaa\x29\x8a\x4b\x71\x03\xb0\x9a"
        "\x2f\xd6\x6b\xb0\x0b\x93\xc9\x4d\x0b\x9d\x3f\xe6\x21",

        "\x00\xa4\x80\x6e\xef\x34\xba\x3f\xe7\x96\xec\x25\x16\x25\xe9"
        "\x77\x5f\x61\xb1\x48\xdb\x03\xfa\x80\xf3\xbd\x20\xd1\x60\x9a"
        "\x10\x9d\xf0\x1b\xff\xb8\x50\x14\x54\x75\x53\x2b\x89\x9f\x39"
        "\x96\x63\x05\x89\xfb\xfb\x7f\x59\x93\xdc\x61\xe2\x8c\xfc\x5a"
        "\x6f\x2c\x6a\xcf\xd4\xac\xa5\x81\xf2\xdd\x68\x75\xd4\x48",

        "\x00\xf6\xec\xd6\x98\x10\x42\x38\x94\x30\x2c\xd4\xe7\xb1\x5f"
        "\xa2\xfd\xc9\xc4\x92\x78\xf6\x31\x34\xb7\x26\xa1\x7f\x0b\xa3"
        "\xc3\xf6\x4f\xd0\x05\x4e\x98\x1b\xa5\x98\xde\x26\xb8\xc2\x14"
        "\x12\xa4\xae\x2f\xd8\x48\x39\x1b\x33\x1d\x0f\x72\xaf\xd3\x8d"
        "\xd8\xb0\x9f\x52\x42\x5d\xae\xf6\x3c\xe1\xd2\x09\xd8\x53",

        "\x00\xb3\xce\x4b\x87\x41\x21\x34\x7b\xe3\x64\x74\xef\x9f\x71"
        "\xcc\x01\x19\x50\x69\xbb\x5f\x69\xc8\xbc\x62\x8b\x4d\xa9\x73"
        "\x23\x7f\xc6\xce\xfa\xe7\x96\xa7\x22\x44\x33\x32\x47\x60\x23"
        "\xb4\xd2\x5e\xa4\xa1\xbd\x31\x1f\x04\x1a\xdf\xdb\x05\xe9\x4c"
        "\x44\xfb\x9b\x73\xfe\x25\x3d\x7a\x61\xc2\x22\x9a\xd6\x18",

        "\x01\x8d\x43\x63\x89\x6d\x97\xf3\x4a\x3e\x10\xa0\x94\x46\x1a"
        "\x1c\x34\x22\xb3\xe3\x21\xff\xad\xf2\x1b\x56\x74\x32\xdc\xd2"
        "\x0e\xd7\x3a\x9c\xe9\x87\xcc\xf1\x9c\x56\xfe\xff\x2f\x3d\xec"
        "\x70\xba\xfb\x5d\x37\xa8\x57\xd1\xc4\xa9\x1b\xc9\xdc\x76\x68"
        "\xca\x7d\x39\x59\x97\x2d\x07\x03\x52\xf6\x8d\xb6\x0e\x24"
    };

    static int coeffs_len[] = { 73, 74, 74, 74, 74 };

    BIGNUM **pris = NULL, **exps = NULL, **coeffs = NULL;
    int i, rv = 512;
    unsigned char *n, *d;
    size_t len_n, len_d;

    len_n = sizeof(n1) + sizeof(n2) - 2;
    n = OPENSSL_zalloc(len_n);
    if (n == NULL)
        return 0;

    memcpy(n, n1, sizeof(n1) - 1);
    memcpy(n + sizeof(n1) - 1, n2, sizeof(n2) - 1);

    len_d = sizeof(d1) + sizeof(d2) - 2;
    d = OPENSSL_zalloc(len_d);
    if (d == NULL)
        goto err;

    memcpy(d, d1, sizeof(d1) - 1);
    memcpy(d + sizeof(d1) - 1, d2, sizeof(d2) - 1);

    if (!TEST_int_eq(RSA_set0_key(key,
                                  BN_bin2bn(n, len_n, NULL),
                                  BN_bin2bn(e, sizeof(e) - 1, NULL),
                                  BN_bin2bn(d, len_d, NULL)), 1))
        goto err;

    if (!TEST_int_eq(RSA_set0_factors(key,
                                      BN_bin2bn(p, sizeof(p) - 1, NULL),
                                      BN_bin2bn(q, sizeof(q) - 1, NULL)), 1))
        goto err;

    if (!TEST_int_eq(RSA_set0_crt_params(key,
                                         BN_bin2bn(dmp1, sizeof(dmp1) - 1,
                                                   NULL),
                                         BN_bin2bn(dmq1, sizeof(dmq1) - 1,
                                                   NULL),
                                         BN_bin2bn(iqmp, sizeof(iqmp) - 1,
                                                   NULL)), 1))
        return 0;

    pris = OPENSSL_zalloc(sizeof(BIGNUM *) * NUM_INSECURE_EXTRA_PRIMES);
    exps = OPENSSL_zalloc(sizeof(BIGNUM *) * NUM_INSECURE_EXTRA_PRIMES);
    coeffs = OPENSSL_zalloc(sizeof(BIGNUM *) * NUM_INSECURE_EXTRA_PRIMES);

    if (!TEST_ptr(pris) || !TEST_ptr(exps) || !TEST_ptr(coeffs))
        goto err;

    for (i = 0; i < NUM_INSECURE_EXTRA_PRIMES; i++) {
        pris[i] = BN_bin2bn((unsigned char *)primes[i], primes_len[i], NULL);
        exps[i] = BN_bin2bn((unsigned char *)exponents[i], exps_len[i], NULL);
        coeffs[i] = BN_bin2bn((unsigned char *)coefficients[i],
                              coeffs_len[i], NULL);
        if (!TEST_ptr(pris[i]) || !TEST_ptr(exps[i]) || !TEST_ptr(coeffs[i]))
            goto err;
    }

    if (!TEST_ptr(pris[0]) || !TEST_ptr(exps[0]) || !TEST_ptr(coeffs[0]))
        goto err;

    if (!TEST_true(RSA_set0_multi_prime_params(key, pris, exps,
                                               coeffs,
                                               NUM_INSECURE_EXTRA_PRIMES)))
        goto err;

 ret:
    OPENSSL_free(pris);
    OPENSSL_free(exps);
    OPENSSL_free(coeffs);
    OPENSSL_free(n);
    OPENSSL_free(d);
    return rv;
 err:
    for (i = 0; i < 5; i++) {
        if (pris != NULL)
            BN_free(pris[i]);
        if (exps != NULL)
            BN_free(exps[i]);
        if (coeffs != NULL)
            BN_free(coeffs[i]);
    }

    rv = 0;
    goto ret;
}

static int test_rsa_mp_insecure(void)
{
    int ret = 0;
    RSA *key;
    unsigned char ptext[512];
    unsigned char ctext[512];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    int plen;
    int clen = 0;
    int num;

    plen = sizeof(ptext_ex) - 1;
    key = RSA_new();
    if (!TEST_ptr(key))
        goto err;
    clen = key4096p7(key);
    if (!TEST_int_eq(clen, 512))
        goto err;

    RSA_set_flags(key, RSA_FLAG_INSECURE_PRIMES);

    if (!TEST_true(RSA_check_key_ex(key, NULL)))
        goto err;

    num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
                             RSA_PKCS1_PADDING);
    if (!TEST_int_eq(num, clen))
        goto err;

    num = RSA_private_decrypt(num, ctext, ptext, key, RSA_PKCS1_PADDING);
    if (!TEST_mem_eq(ptext, num, ptext_ex, plen))
        goto err;

    ret = 1;
err:
    RSA_free(key);
    return ret;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_RSA
    ADD_TEST(test_rsa_mp);
    ADD_TEST(test_rsa_mp_insecure);
#endif
    return 1;
}
