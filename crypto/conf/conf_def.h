/*
 * WARNING: do not edit!
 * Generated by crypto/conf/keysets.pl
 *
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define CONF_NUMBER       1
#define CONF_UPPER        2
#define CONF_LOWER        4
#define CONF_UNDER        256
#define CONF_PUNCT        512
#define CONF_WS           16
#define CONF_ESC          32
#define CONF_QUOTE        64
#define CONF_DQUOTE       1024
#define CONF_COMMENT      128
#define CONF_FCOMMENT     2048
#define CONF_DOLLAR       4096
#define CONF_EOF          8
#define CONF_ALPHA        (CONF_UPPER|CONF_LOWER)
#define CONF_ALNUM        (CONF_ALPHA|CONF_NUMBER|CONF_UNDER)
#define CONF_ALNUM_PUNCT  (CONF_ALPHA|CONF_NUMBER|CONF_UNDER|CONF_PUNCT)


#define IS_COMMENT(conf,c)     is_keytype(conf, c, CONF_COMMENT)
#define IS_FCOMMENT(conf,c)    is_keytype(conf, c, CONF_FCOMMENT)
#define IS_EOF(conf,c)         is_keytype(conf, c, CONF_EOF)
#define IS_ESC(conf,c)         is_keytype(conf, c, CONF_ESC)
#define IS_NUMBER(conf,c)      is_keytype(conf, c, CONF_NUMBER)
#define IS_WS(conf,c)          is_keytype(conf, c, CONF_WS)
#define IS_ALNUM(conf,c)       is_keytype(conf, c, CONF_ALNUM)
#define IS_ALNUM_PUNCT(conf,c) is_keytype(conf, c, CONF_ALNUM_PUNCT)
#define IS_QUOTE(conf,c)       is_keytype(conf, c, CONF_QUOTE)
#define IS_DQUOTE(conf,c)      is_keytype(conf, c, CONF_DQUOTE)
#define IS_DOLLAR(conf,c)      is_keytype(conf, c, CONF_DOLLAR)

static const unsigned short CONF_type_default[128] = {
    0x0008, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0010, 0x0010, 0x0000, 0x0000, 0x0010, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0010, 0x0200, 0x0040, 0x0080, 0x1000, 0x0200, 0x0200, 0x0040,
    0x0000, 0x0000, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0000, 0x0200, 0x0000, 0x0000, 0x0000, 0x0200,
    0x0200, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0000, 0x0020, 0x0000, 0x0200, 0x0100,
    0x0040, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0000, 0x0200, 0x0000, 0x0200, 0x0000,
};

#ifndef OPENSSL_NO_DEPRECATED_3_0
static const unsigned short CONF_type_win32[128] = {
    0x0008, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0010, 0x0010, 0x0000, 0x0000, 0x0010, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0010, 0x0200, 0x0400, 0x0000, 0x1000, 0x0200, 0x0200, 0x0000,
    0x0000, 0x0000, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0000, 0x0A00, 0x0000, 0x0000, 0x0000, 0x0200,
    0x0200, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0000, 0x0000, 0x0000, 0x0200, 0x0100,
    0x0000, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0000, 0x0200, 0x0000, 0x0200, 0x0000,
};
#endif
