/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#ifndef OPENSSL_NO_ECH

static int verbose = 0;

/* general test vector values */

/* standard x25519 ech key pair with public key example.com */
static const char pem_kp1[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEILDIeo9Eqc4K9/uQ0PNAyMaP60qrxiSHT2tNZL3ksIZS\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/* standard x25519 ECHConfigList with public key example.com */
static const char pem_pk1[] =
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/*
 * This ECHConfigList has 4 entries with different versions,
 * from drafts: 13,10,13,9 - since our runtime no longer supports
 * version 9 or 10, we should see 2 configs loaded.
 */
static const char pem_4_to_2[] =
    "-----BEGIN ECHCONFIG-----\n"
    "APv+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS4K\n"
    "hu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACB3xsNUtSgi\n"
    "piYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAEAAQALZXhhbXBsZS5jb20AAP4J\n"
    "ADsAC2V4YW1wbGUuY29tACCjJCv5w/yaHjbOc6nVuM/GksIGLgDR+222vww9dEk8\n"
    "FwAgAAQAAQABAAAAAA==\n"
    "-----END ECHCONFIG-----\n";

/* single-line base64(ECHConfigList) form of pem_pk1 */
static const char b64_pk1[] =
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA"
    "AQALZXhhbXBsZS5jb20AAA==";

/* single-line base64(ECHConfigList) form of pem_6_to3 */
static const char b64_6_to_3[] =
    "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"
    "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"
    "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"
    "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"
    "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"
    "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"
    "AA==";

/* same as above but binary encoded */
static const unsigned char bin_6_to_3[] = {
    0x01, 0x79, 0xfe, 0x0d, 0x00, 0x3a, 0xc5, 0x00,
    0x20, 0x00, 0x20, 0x66, 0xe7, 0x82, 0x92, 0x20,
    0xf5, 0xee, 0xfa, 0x94, 0x2a, 0xda, 0x86, 0x35,
    0xf3, 0x7c, 0x2d, 0xdf, 0x26, 0xf1, 0xec, 0x22,
    0x9b, 0x05, 0x85, 0xf4, 0xa2, 0x03, 0xea, 0xe6,
    0xee, 0x85, 0x7a, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0a, 0x00, 0x3c, 0xd2, 0x00, 0x20, 0x00,
    0x20, 0x83, 0xfe, 0xd1, 0x0b, 0x74, 0x58, 0x60,
    0x45, 0xdc, 0x7e, 0x5f, 0xcf, 0xc1, 0xee, 0x85,
    0x54, 0x53, 0x08, 0x43, 0x2e, 0x1d, 0x2e, 0x0a,
    0x86, 0xee, 0xa2, 0x6d, 0x1f, 0xfa, 0xa8, 0x44,
    0x78, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x09, 0x00, 0x3b, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x20, 0xa3, 0x24, 0x2b, 0xf9, 0xc3,
    0xfc, 0x9a, 0x1e, 0x36, 0xce, 0x73, 0xa9, 0xd5,
    0xb8, 0xcf, 0xc6, 0x92, 0xc2, 0x06, 0x2e, 0x00,
    0xd1, 0xfb, 0x6d, 0xb6, 0xbf, 0x0c, 0x3d, 0x74,
    0x49, 0x3c, 0x17, 0x00, 0x20, 0x00, 0x04, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe,
    0x0d, 0x00, 0x3a, 0x43, 0x00, 0x20, 0x00, 0x20,
    0x77, 0xc6, 0xc3, 0x54, 0xb5, 0x28, 0x22, 0xa6,
    0x26, 0x29, 0x52, 0x45, 0xba, 0x39, 0x2a, 0xeb,
    0x83, 0x4d, 0xc8, 0xe3, 0x32, 0x04, 0x34, 0xc1,
    0x5a, 0xd0, 0x94, 0x76, 0xf8, 0xc9, 0xb5, 0x5b,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0a, 0x00,
    0x3c, 0x03, 0x00, 0x20, 0x00, 0x20, 0x7d, 0x01,
    0xa0, 0x07, 0x62, 0x24, 0x25, 0xfc, 0xf2, 0x0b,
    0xfc, 0x9d, 0x8a, 0x46, 0x55, 0x7e, 0x41, 0xa4,
    0x60, 0x5a, 0xf7, 0x24, 0xf4, 0x3d, 0xa7, 0x37,
    0x2b, 0x0c, 0x7a, 0x8b, 0xc5, 0x11, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0d, 0x00,
    0x3a, 0x43, 0x00, 0x20, 0x00, 0x20, 0xdc, 0x64,
    0x80, 0x31, 0xec, 0xe7, 0x0e, 0x89, 0x0b, 0xa4,
    0xf7, 0x45, 0x55, 0xef, 0xf0, 0xce, 0xe2, 0x51,
    0x50, 0xaf, 0x92, 0x37, 0x67, 0x0f, 0x6d, 0x55,
    0xb2, 0xbc, 0x30, 0x6c, 0x35, 0x76, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x00
};

/* base64(ECHConfigList) with corrupt ciphersuite length and public_name */
static const char b64_bad_cs[] =
    "AD7+DQA6uAAgACAogff+HZbirYdQCfXI01GBPP8AEKYyK/D/0DoeXD84fgAQAAE"
    "AAQgLZXhhbUNwbGUuYwYAAAAAQwA=";

/*
 * An ascii-hex ECHConfigList with one ECHConfig
 * but of the wrong version
 */
static const unsigned char bin_bad_ver[] = {
    0x00, 0x3e, 0xfe, 0xff, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * An ECHConflgList with 2 ECHConfig values that are both
 * of the wrong version. The versions here are 0xfe03 (we
 * currently support only 0xfe0d)
 */
static const unsigned char bin_bad_ver2[] = {
    0x00, 0x80, 0xfe, 0x03, 0x00, 0x3c, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x71, 0xa5, 0xe0, 0xb4, 0x6d,
    0xdf, 0xa4, 0xda, 0xed, 0x69, 0xa5, 0xc7, 0x8b,
    0x9d, 0xa5, 0x13, 0x0c, 0x36, 0x83, 0x7a, 0x03,
    0x72, 0x1d, 0xf6, 0x1e, 0xc5, 0x83, 0x1a, 0x11,
    0x73, 0xce, 0x2d, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0d, 0x70, 0x61, 0x72, 0x74, 0x31,
    0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x00, 0x00, 0xfe, 0x03, 0x00, 0x3c, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x69, 0x88, 0xfd, 0x8f, 0xc9,
    0x0b, 0xb7, 0x2d, 0x96, 0x6d, 0xe0, 0x22, 0xf0,
    0xc8, 0x1b, 0x62, 0x2b, 0x1c, 0x94, 0x96, 0xad,
    0xef, 0x55, 0xdb, 0x9f, 0xeb, 0x0d, 0xa1, 0x4b,
    0x0c, 0xd7, 0x36, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0d, 0x70, 0x61, 0x72, 0x74, 0x32,
    0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x00, 0x00
};

/*
 * An ascii-hex ECHConfigList with one ECHConfig
 * with an all-zero public value.
 * This should be ok, for 25519, but hey, just in case:-)
 */
static const unsigned char bin_zero[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * The next set of samples are syntactically invalid
 * Proper fuzzing is still needed but no harm having
 * these too. Generally these are bad version of
 * echconfig_ah with some octet(s) replaced by 0xFF
 * values. Other hex letters are lowercase so you
 * can find the altered octet(s).
 */

/* wrong oveall length (replacing 0x3e with 0xFF) */
static const unsigned char bin_bad_olen[] = {
    0x00, 0xFF, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0xFF, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong ECHConfig inner length (replacing 0x3a with 0xFF) */
static const unsigned char bin_bad_ilen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0xFF, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for public key (replaced 0x20 with 0xFF) */
static const unsigned char bin_bad_pklen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0xFF, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for ciphersuites (replaced 0x04 with 0xFF) */
static const unsigned char bin_bad_cslen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0xFF, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for public name (replaced 0x0b with 0xFF) */
static const unsigned char bin_bad_pnlen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0xFF, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* non-zero extension length (0xFF at end) but no extension value */
static const unsigned char bin_bad_extlen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0xFF
};

/*
 * The next set have bad kem, kdf or aead values - this time with
 * 0xAA as the replacement value
 */

/* wrong KEM ID (replaced 0x20 with 0xAA) */
static const unsigned char bin_bad_kemid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0xAA, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong KDF ID (replaced 0x01 with 0xAA) */
static const unsigned char bin_bad_kdfid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0xAA, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong AEAD ID (replaced 0x01 with 0xAA) */
static const unsigned char bin_bad_aeadid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0xAA, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * sorta wrong AEAD ID; replaced 0x0001 with 0xFFFF
 * which is the export only pseudo-aead-id - that
 * should not work in our test, same as the others,
 * but worth a specific test, as it'll fail in a
 * different manner
 */
static const unsigned char bin_bad_aeadid_ff[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0xFF,
    0xFF, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * An ECHConfigList with a bad ECHConfig
 * (aead is 0xFFFF), followed by a good
 * one.
 */
static const unsigned char bin_bad_then_good[] = {
    0x00, 0x7c, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0xFF,
    0xFF, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00, 0x20, 0x00,
    0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2, 0xc5, 0xfe,
    0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c, 0xa4, 0x33,
    0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e, 0x5a, 0x42,
    0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73, 0x60, 0x16,
    0x3c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* struct for ingest test vector and results */
typedef struct INGEST_TV_T {
    char *name; /* name for verbose output */
    const unsigned char *tv; /* test vector */
    size_t len; /* len(tv) - sizeof(tv) if binary, subtract 1 for strings */
    int pemenc; /* whether PEM encoded (1) or not (0) */
    int read; /* result expected from read function on tv */
    int keysb4; /* the number of private keys expected before downselect */
    int entsb4; /* the number of public keys b4 */
    int index; /* the index to use for downselect */
    int expected; /* the result expected from a downselect */
    int keysaftr; /* the number of keys expected after downselect */
    int entsaftr; /* the number of public keys after */
} ingest_tv_t;

static ingest_tv_t ingest_tvs[] = {
    /* PEM test vectors */
    { "PEM basic/last", (unsigned char *)pem_kp1, sizeof(pem_kp1) - 1,
      1, 1, 1, 1, OSSL_ECHSTORE_LAST, 1, 1, 1 },
    { "PEM basic/0", (unsigned char *)pem_pk1, sizeof(pem_kp1) - 1,
      1, 1, 0, 1, 0, 1, 0, 1 },
    { "PEM basic/2nd", (unsigned char *)pem_pk1, sizeof(pem_kp1) - 1,
      1, 1, 0, 1, 2, 0, 0, 1 },
    /* downselect from the 2, at each position */
    { "PEM 4->2/0", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 0, 1, 0, 1 },
    { "PEM 4->2/1", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 1, 1, 0, 1 },
    /* in the next one below, downselect fails, so we still have 2 entries */
    { "PEM 4->2/2", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 3, 0, 0, 2 },
    /* b64 test vectors */
    { "B64 basic/last", (unsigned char *)b64_pk1, sizeof(b64_pk1) - 1,
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "B64 6->3/2", (unsigned char *)b64_6_to_3, sizeof(b64_6_to_3) - 1,
      0, 1, 0, 3, 2, 1, 0, 1 },
    { "B64 bad suitelen", (unsigned char *)b64_bad_cs, sizeof(b64_bad_cs) - 1,
      0, 0, 0, 0, 0, 0, 0, 0 },
    /* binary test vectors */
    { "bin 6->3/2", (unsigned char *)bin_6_to_3, sizeof(bin_6_to_3),
      0, 1, 0, 3, 2, 1, 0, 1 },
    { "bin all-zero pub", (unsigned char *)bin_zero, sizeof(bin_zero),
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "bin bad ver", (unsigned char *)bin_bad_ver, sizeof(bin_bad_ver),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin 2 bad ver", (unsigned char *)bin_bad_ver2, sizeof(bin_bad_ver2),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad len", (unsigned char *)bin_bad_olen, sizeof(bin_bad_olen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad inner len", (unsigned char *)bin_bad_ilen, sizeof(bin_bad_ilen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad pk len", (unsigned char *)bin_bad_pklen, sizeof(bin_bad_pklen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad suitelen", (unsigned char *)bin_bad_cslen, sizeof(bin_bad_cslen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad pn len", (unsigned char *)bin_bad_pnlen, sizeof(bin_bad_pnlen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad extlen", (unsigned char *)bin_bad_extlen, sizeof(bin_bad_extlen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad kemid", (unsigned char *)bin_bad_kemid, sizeof(bin_bad_kemid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad kdfid", (unsigned char *)bin_bad_kdfid, sizeof(bin_bad_kdfid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad aeadid", (unsigned char *)bin_bad_aeadid, sizeof(bin_bad_aeadid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin exp aeadid", (unsigned char *)bin_bad_aeadid_ff,
      sizeof(bin_bad_aeadid_ff),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad,good", (unsigned char *)bin_bad_then_good,
      sizeof(bin_bad_then_good),
      0, 0, 0, 0, 0, 0, 0, 0 },
};

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH tests\n" },
        { NULL }
    };
    return test_options;
}

/*
 * For the relevant test vector in our array above:
 * - try decode
 * - if not expected to decode, we're done
 * - check we got the right number of keys/ECHConfig values
 * - do some calls with getting info, downselecting etc. and
 *   check results as expected
 * - do a write_pem call on the results
 * - flush keys 'till now and check they're all gone
 */
static int ech_ingest_test(int run)
{
    OSSL_ECHSTORE *es = NULL;
    OSSL_ECH_INFO *ei = NULL;
    BIO *in = NULL, *out = NULL;
    int rv = 0, keysb4, keysaftr, entsb4, entsaftr;
    ingest_tv_t *tv = &ingest_tvs[run];
    time_t now = 0;

    if ((in = BIO_new(BIO_s_mem())) == NULL
        || BIO_write(in, tv->tv, tv->len) <= 0
        || (out = BIO_new(BIO_s_mem())) == NULL
        || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL)
        goto end;
    if (verbose)
        TEST_info("Iteration: %d %s", run + 1, tv->name);
    /* just in case of bad edits to table */
    if (tv->pemenc != 1 && tv->pemenc != 0) {
        TEST_info("Bad test vector entry");
        goto end;
    }
    if (tv->pemenc == 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_pem(es, in, OSSL_ECH_NO_RETRY),
                        tv->read)) {
        TEST_info("OSSL_ECSTORE_read_pem unexpected fail");
        goto end;
    }
    if (tv->pemenc != 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_echconfiglist(es, in),
                        tv->read)) {
        TEST_info("OSSL_ECSTORE_read_echconfiglist unexpected fail");
        goto end;
    }
    /* if we provided a deliberately bad tv then we're done */
    if (tv->read != 1) {
        rv = 1;
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysb4), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysb4, tv->keysb4)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected number of keys (b4)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_get1_info(es, &ei, &entsb4), 1)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected fail");
        goto end;
    }
    OSSL_ECH_INFO_free(ei, entsb4);
    ei = NULL;
    if (!TEST_int_eq(entsb4, tv->entsb4)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected number of entries (b4)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_downselect(es, tv->index), tv->expected)) {
        TEST_info("OSSL_ECSTORE_downselect unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysaftr), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysaftr, tv->keysaftr)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected number of keys (aftr)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_get1_info(es, &ei, &entsaftr), 1)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected fail");
        goto end;
    }
    OSSL_ECH_INFO_free(ei, entsaftr);
    ei = NULL;
    if (!TEST_int_eq(entsaftr, tv->entsaftr)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected number of entries (aftr)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_write_pem(es, OSSL_ECHSTORE_ALL, out), 1)) {
        TEST_info("OSSL_ECSTORE_write_pem unexpected fail");
        goto end;
    }
    now = time(0);
    if (!TEST_int_eq(OSSL_ECHSTORE_flush_keys(es, now), 1)) {
        TEST_info("OSSL_ECSTORE_flush_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysaftr), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysaftr, 0)) {
        TEST_info("OSSL_ECSTORE_flush_keys unexpected non-zero");
        goto end;
    }
    rv = 1;
end:
    OSSL_ECHSTORE_free(es);
    BIO_free_all(in);
    BIO_free_all(out);
    return rv;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    ADD_ALL_TESTS(ech_ingest_test, OSSL_NELEM(ingest_tvs));
    /* TODO(ECH): we'll add more test code once other TODO's settle */
    return 1;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    ;
#endif
}
