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
#include <openssl/x509err.h>
#include "crypto/x509err.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA X509_str_reasons[] = {
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_AKID_MISMATCH), "akid mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_SELECTOR), "bad selector"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BAD_X509_FILETYPE), "bad x509 filetype"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_BASE64_DECODE_ERROR),
    "base64 decode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CANT_CHECK_DH_KEY), "cant check dh key"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CERTIFICATE_VERIFICATION_FAILED),
    "certificate verification failed"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CERT_ALREADY_IN_HASH_TABLE),
    "cert already in hash table"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_ALREADY_DELTA), "crl already delta"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_CRL_VERIFY_FAILURE),
    "crl verify failure"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_ERROR_GETTING_MD_BY_NID),
    "error getting md by nid"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_ERROR_USING_SIGINF_SET),
    "error using siginf set"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_IDP_MISMATCH), "idp mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_ATTRIBUTES),
    "invalid attributes"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_DIRECTORY), "invalid directory"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_DISTPOINT), "invalid distpoint"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_FIELD_NAME),
    "invalid field name"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_INVALID_TRUST), "invalid trust"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_ISSUER_MISMATCH), "issuer mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_TYPE_MISMATCH), "key type mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_KEY_VALUES_MISMATCH),
    "key values mismatch"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_CERT_DIR), "loading cert dir"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_LOADING_DEFAULTS), "loading defaults"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_METHOD_NOT_SUPPORTED),
    "method not supported"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NAME_TOO_LONG), "name too long"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NEWER_CRL_NOT_NEWER),
    "newer crl not newer"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_FOUND),
    "no certificate found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERTIFICATE_OR_CRL_FOUND),
    "no certificate or crl found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY),
    "no cert set for us to verify"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_FOUND), "no crl found"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_NO_CRL_NUMBER), "no crl number"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_DECODE_ERROR),
    "public key decode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_PUBLIC_KEY_ENCODE_ERROR),
    "public key encode error"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_SHOULD_RETRY), "should retry"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN),
    "unable to find parameters in chain"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY),
    "unable to get certs public key"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_KEY_TYPE), "unknown key type"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_NID), "unknown nid"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_PURPOSE_ID),
    "unknown purpose id"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_SIGID_ALGS),
    "unknown sigid algs"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNKNOWN_TRUST_ID), "unknown trust id"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM),
    "unsupported algorithm"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_LOOKUP_TYPE), "wrong lookup type"},
    {ERR_PACK(ERR_LIB_X509, 0, X509_R_WRONG_TYPE), "wrong type"},
    {0, NULL}
};

#endif

int ossl_load_X509_strings_int(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(X509_str_reasons[0].error) == NULL)
        ERR_load_strings_const(X509_str_reasons);
#endif
    return 1;
}
