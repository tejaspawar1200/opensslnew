/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/bnerr.h>
#include "crypto/bnerr.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA BN_str_reasons[] = {
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_ARG2_LT_ARG3), "arg2 lt arg3"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_BAD_RECIPROCAL), "bad reciprocal"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_BIGNUM_TOO_LONG), "bignum too long"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_BITS_TOO_SMALL), "bits too small"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_CALLED_WITH_EVEN_MODULUS),
    "called with even modulus"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO), "div by zero"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_ENCODING_ERROR), "encoding error"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA),
    "expand on static bignum data"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_INPUT_NOT_REDUCED), "input not reduced"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_LENGTH), "invalid length"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_RANGE), "invalid range"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_SHIFT), "invalid shift"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_A_SQUARE), "not a square"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_INITIALIZED), "not initialized"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_INVERSE), "no inverse"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_SOLUTION), "no solution"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_SUITABLE_DIGEST), "no suitable digest"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_PRIVATE_KEY_TOO_LARGE),
    "private key too large"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_P_IS_NOT_PRIME), "p is not prime"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_ITERATIONS), "too many iterations"},
    {ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_TEMPORARY_VARIABLES),
    "too many temporary variables"},
    {0, NULL}
};

#endif

int ossl_load_BN_strings_int(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(BN_str_reasons[0].error) == NULL)
        ERR_load_strings_const(BN_str_reasons);
#endif
    return 1;
}
