/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"

static int null_write(BIO *h, const char *buf, int num);
static int null_read(BIO *h, char *buf, int size);
static int null_puts(BIO *h, const char *str);
static int null_gets(BIO *h, char *str, int size);
static long null_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int null_new(BIO *h);
static int null_free(BIO *data);
static const BIO_METHOD null_method = {
    BIO_TYPE_NULL,
    "NULL",
    /* TODO: Convert to new style write function */
    bwrite_conv,
    null_write,
    /* TODO: Convert to new style read function */
    bread_conv,
    null_read,
    null_puts,
    null_gets,
    null_ctrl,
    null_new,
    null_free,
    NULL,
};

const BIO_METHOD *BIO_s_null(void)
{
    return (&null_method);
}

static int null_new(BIO *bi)
{
    bi->init = 1;
    bi->num = 0;
    bi->ptr = (NULL);
    return (1);
}

static int null_free(BIO *a)
{
    if (a == NULL)
        return (0);
    return (1);
}

static int null_read(BIO *b, char *out, int outl)
{
    (void)b;
    (void)out;
    (void)outl;
    return (0);
}

static int null_write(BIO *b, const char *in, int inl)
{
    (void)b;
    (void)in;
    return (inl);
}

static long null_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;

    (void)b;
    (void)num;
    (void)ptr;
    switch (cmd) {
    case BIO_CTRL_RESET:
    case BIO_CTRL_EOF:
    case BIO_CTRL_SET:
    case BIO_CTRL_SET_CLOSE:
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DUP:
        break;
    case BIO_CTRL_GET_CLOSE:
    case BIO_CTRL_INFO:
    case BIO_CTRL_GET:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int null_gets(BIO *bp, char *buf, int size)
{
    (void)bp;
    (void)buf;
    (void)size;
    return (0);
}

static int null_puts(BIO *bp, const char *str)
{
    (void)bp;
    if (str == NULL)
        return (0);
    return (strlen(str));
}
