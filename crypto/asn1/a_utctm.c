/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_locl.h"

/* This is the primary function used to parse ASN1_UTCTIME */
int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)
{
    /* wrapper around ans1_time_to_tm */
    if (d->type != V_ASN1_UTCTIME)
        return 0;
    return asn1_time_to_tm(tm, d);
}

/* Inverse of asn1_utctime_to_tm ()*/
ASN1_UTCTIME *asn1_utctime_from_tm(ASN1_UTCTIME *s, struct tm *ts)
{
    char *p;
    ASN1_UTCTIME *tmps = NULL;
    const size_t len = 20;

    if ((ts->tm_year < 50) || (ts->tm_year >= 150))
        return NULL;

    if (s == NULL)
        tmps = ASN1_UTCTIME_new();
    else
        tmps = s;
    if (tmps == NULL)
        return NULL;

    if (!ASN1_STRING_set(tmps, NULL, len))
        goto err;

    p = (char*) tmps->data;
    tmps->length = BIO_snprintf(p, len, "%02d%02d%02d%02d%02d%02dZ",
                                ts->tm_year % 100, ts->tm_mon + 1,
                                ts->tm_mday, ts->tm_hour, ts->tm_min,
                                ts->tm_sec);
    tmps->type = V_ASN1_UTCTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(tmps->data, tmps->data, tmps->length);
#endif
    return tmps;
 err:
    if (tmps != s)
        ASN1_STRING_free(tmps);
    return NULL;
}

int ASN1_UTCTIME_check(const ASN1_UTCTIME *d)
{
    return asn1_utctime_to_tm(NULL, d);
}

/* Sets the string via simple copy without cleaning it up */
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
    ASN1_UTCTIME t;

    t.type = V_ASN1_UTCTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    if (!ASN1_UTCTIME_check(&t))
        return 0;

    if (s != NULL && !ASN1_STRING_copy(s, &t))
        return 0;

    return 1;
}

ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)
{
    return ASN1_UTCTIME_adj(s, t, 0, 0);
}

ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec)
{
    struct tm *ts;
    struct tm data;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        return NULL;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }

    return asn1_utctime_from_tm(s, ts);
}

int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t)
{
    struct tm stm, ttm;
    int day, sec;

    if (!asn1_utctime_to_tm(&stm, s))
        return -2;

    if (OPENSSL_gmtime(&t, &ttm) == NULL)
        return -2;

    if (!OPENSSL_gmtime_diff(&day, &sec, &ttm, &stm))
        return -2;

    if (day > 0 || sec > 0)
        return 1;
    if (day < 0 || sec < 0)
        return -1;
    return 0;
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm)
{
    if (tm->type != V_ASN1_UTCTIME)
        return 0;
    return ASN1_TIME_print(bp, tm);
}
