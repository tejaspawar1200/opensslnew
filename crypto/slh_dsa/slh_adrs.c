/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <string.h>
#include "slh_adrs.h"

/* See FIPS 205 - Section 4.3 Table 1  Uncompressed Addresses */
#define SLH_ADRS_OFF_LAYER_ADR      0
#define SLH_ADRS_OFF_TREE_ADR       4
#define SLH_ADRS_OFF_TYPE          16
#define SLH_ADRS_OFF_KEYPAIR_ADDR  20
#define SLH_ADRS_OFF_CHAIN_ADDR    24
#define SLH_ADRS_OFF_HASH_ADDR     28
#define SLH_ADRS_OFF_TREE_INDEX    SLH_ADRS_OFF_HASH_ADDR
#define SLH_ADRS_SIZE_TYPE          4
/* Number of bytes after type to clear */
#define SLH_ADRS_SIZE_TYPECLEAR    SLH_ADRS_SIZE - (SLH_ADRS_OFF_TYPE + SLH_ADRS_SIZE_TYPE)
#define SLH_ADRS_SIZE_KEYPAIR_ADDR 4

/* See FIPS 205 - Section 11.2 Table 3 Compressed Addresses */
#define SLH_ADRSC_OFF_LAYER_ADR     0
#define SLH_ADRSC_OFF_TREE_ADR      1
#define SLH_ADRSC_OFF_TYPE          9
#define SLH_ADRSC_OFF_KEYPAIR_ADDR  10
#define SLH_ADRSC_OFF_CHAIN_ADDR    14
#define SLH_ADRSC_OFF_HASH_ADDR     18
#define SLH_ADRSC_OFF_TREE_INDEX    SLH_ADRSC_OFF_HASH_ADDR
#define SLH_ADRSC_SIZE_TYPE         1
#define SLH_ADRSC_SIZE_TYPECLEAR    SLH_ADRS_SIZE_TYPECLEAR
#define SLH_ADRSC_SIZE_KEYPAIR_ADDR SLH_ADRS_SIZE_KEYPAIR_ADDR

#define slh_adrsc_set_tree_height slh_adrsc_set_chain_address
#define slh_adrsc_set_tree_index slh_adrsc_set_hash_address

static OSSL_SLH_ADRS_FUNC_set_layer_address slh_adrsc_set_layer_address;
static OSSL_SLH_ADRS_FUNC_set_tree_address slh_adrsc_set_tree_address;
static OSSL_SLH_ADRS_FUNC_set_type_and_clear slh_adrsc_set_type_and_clear;
static OSSL_SLH_ADRS_FUNC_set_keypair_address slh_adrsc_set_keypair_address;
static OSSL_SLH_ADRS_FUNC_copy_keypair_address slh_adrsc_copy_keypair_address;
static OSSL_SLH_ADRS_FUNC_set_chain_address slh_adrsc_set_chain_address;
static OSSL_SLH_ADRS_FUNC_set_hash_address slh_adrsc_set_hash_address;
static OSSL_SLH_ADRS_FUNC_zero slh_adrsc_zero;
static OSSL_SLH_ADRS_FUNC_copy slh_adrsc_copy;

/* Variants of the FIPS 205 Algorithm 3 toByte(x, n) for 32 and 64 bit integers */

/* Convert a 32 bit value |in| to 4 bytes |out| in big endian format */
static ossl_inline void U32TOSTR(unsigned char *out, uint32_t in)
{
    out[3] = (unsigned char)((in) & 0xff);
    out[2] = (unsigned char)((in >> 8) & 0xff);
    out[1] = (unsigned char)((in >> 16) & 0xff);
    out[0] = (unsigned char)((in >> 24) & 0xff);
}

/* Convert a 64 bit value |in| to 8 bytes |out| in big endian format */
static ossl_inline void U64TOSTR(unsigned char *out, uint64_t in)
{
    out[7] = (unsigned char)((in) & 0xff);
    out[6] = (unsigned char)((in >> 8) & 0xff);
    out[5] = (unsigned char)((in >> 16) & 0xff);
    out[4] = (unsigned char)((in >> 24) & 0xff);
    out[3] = (unsigned char)((in >> 32) & 0xff);
    out[2] = (unsigned char)((in >> 40) & 0xff);
    out[1] = (unsigned char)((in >> 48) & 0xff);
    out[0] = (unsigned char)((in >> 56) & 0xff);
}

/* Compressed versions of ADRS functions See Table 3 */
static void slh_adrsc_set_layer_address(SLH_ADRS adrsc, uint32_t layer)
{
    adrsc[SLH_ADRSC_OFF_LAYER_ADR] = (uint8_t)layer;
}
static void slh_adrsc_set_tree_address(SLH_ADRS adrsc, uint64_t in)
{
    U64TOSTR(adrsc + SLH_ADRSC_OFF_TREE_ADR, in);
}
static void slh_adrsc_set_type_and_clear(SLH_ADRS adrsc, uint32_t type)
{
    adrsc[SLH_ADRSC_OFF_TYPE] = (uint8_t)type;
    memset(adrsc + SLH_ADRSC_OFF_TYPE + SLH_ADRSC_SIZE_TYPE, 0, SLH_ADRSC_SIZE_TYPECLEAR);
}
static void slh_adrsc_set_keypair_address(SLH_ADRS adrsc, uint32_t in)
{
    U32TOSTR(adrsc + SLH_ADRSC_OFF_KEYPAIR_ADDR, in);
}
static void slh_adrsc_copy_keypair_address(SLH_ADRS dst, const SLH_ADRS src)
{
    memcpy(dst + SLH_ADRSC_OFF_KEYPAIR_ADDR, src + SLH_ADRSC_OFF_KEYPAIR_ADDR,
           SLH_ADRSC_SIZE_KEYPAIR_ADDR);
}
static void slh_adrsc_set_chain_address(SLH_ADRS adrsc, uint32_t in)
{
    U32TOSTR(adrsc + SLH_ADRSC_OFF_CHAIN_ADDR, in);
}
static void slh_adrsc_set_hash_address(SLH_ADRS adrsc, uint32_t in)
{
    U32TOSTR(adrsc + SLH_ADRSC_OFF_HASH_ADDR, in);
}
static void slh_adrsc_zero(SLH_ADRS adrsc)
{
    memset(adrsc, 0, SLH_ADRSC_SIZE);
}
static void slh_adrsc_copy(SLH_ADRS dst, const SLH_ADRS src)
{
    memcpy(dst, src, SLH_ADRSC_SIZE);
}

const SLH_ADRS_FUNC *ossl_slh_get_adrs_fn(int is_compressed)
{
    static const SLH_ADRS_FUNC methods[] = {
        {
            slh_adrsc_set_layer_address,
            slh_adrsc_set_tree_address,
            slh_adrsc_set_type_and_clear,
            slh_adrsc_set_keypair_address,
            slh_adrsc_copy_keypair_address,
            slh_adrsc_set_chain_address,
            slh_adrsc_set_tree_height,
            slh_adrsc_set_hash_address,
            slh_adrsc_set_tree_index,
            slh_adrsc_zero,
            slh_adrsc_copy,
        }
    };
    return &methods[0];
}
