/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_INTERNAL_CONF_H
# define OPENSSL_INTERNAL_CONF_H

#include <openssl/conf.h>

#define DEFAULT_CONF_MFLAGS \
    (CONF_MFLAGS_DEFAULT_SECTION | \
     CONF_MFLAGS_IGNORE_MISSING_FILE | \
     CONF_MFLAGS_IGNORE_RETURN_CODES)

struct ossl_init_settings_st {
    char *filename;
    char *appname;
    unsigned long flags;
};

int openssl_config_int(const OPENSSL_INIT_SETTINGS *);
void openssl_no_config_int(void);
void conf_modules_free_int(void);

#endif
