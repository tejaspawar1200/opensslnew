/*
 * Written by Matt Caswell for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/e_os2.h>

#if defined(OPENSSL_SYS_WINDOWS) && !defined(_WIN32_WINNT)
/*
 * We default to requiring Windows Vista, Windows Server 2008 or later. We can
 * support lower versions if _WIN32_WINNT is explicity defined to something
 * less
 */
# define _WIN32_WINNT 0x0600
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "ssl_locl.h"

/* Implement "once" functionality */
#if !defined(OPENSSL_THREADS)
typedef int OPENSSL_INIT_ONCE;
# define OPENSSL_INIT_ONCE_STATIC_INIT          0
# define OPENSSL_INIT_ONCE_DYNAMIC_INIT(once)   (*(once) = 0)

static void ossl_init_once_run(OPENSSL_INIT_ONCE *once, void (*init)(void))
{
    if (*once == OPENSSL_INIT_ONCE_STATIC_INIT) {
        *once = 1;
        init();
    }
}
#elif defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>

# if _WIN32_WINNT < 0x0600

/*
 * Versions before 0x0600 (Windows Vista, Windows Server 2008 or later) do not
 * have InitOnceExecuteOnce, so we fall back to using a spinlock instead.
 */
typedef LONG OPENSSL_INIT_ONCE;
#  define OPENSSL_INIT_ONCE_STATIC_INIT          0
#  define OPENSSL_INIT_ONCE_DYNAMIC_INIT(once)   (*(once) = 0)

#  define ONCE_UNINITED     0
#  define ONCE_ININIT       1
#  define ONCE_DONE         2

static void ossl_init_once_run(OPENSSL_INIT_ONCE *once, void (*init)(void))
{
    LONG volatile *lock = (LONG *)once;
    LONG result;

    if (*lock == ONCE_DONE)
        return;

    do {
        result = InterlockedCompareExchange(lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init();
            *lock = ONCE_DONE;
            return;
        }
    } while (result == ONCE_ININIT);
}

# else

typedef INIT_ONCE OPENSSL_INIT_ONCE;
#  define OPENSSL_INIT_ONCE_STATIC_INIT          INIT_ONCE_STATIC_INIT
#  define OPENSSL_INIT_ONCE_DYNAMIC_INIT(once) \
                InitOnceInitialize((PINIT_ONCE)(once))

static BOOL CALLBACK once_cb(PINIT_ONCE once, PVOID initfp, PVOID *unused)
{
    void (*init)(void) = initfp;

    init();

    return TRUE;
}

static void ossl_init_once_run(OPENSSL_INIT_ONCE *once, void (*init)(void))
{
    InitOnceExecuteOnce((INIT_ONCE *)once, once_cb, init, NULL);
}
# endif
#else /* pthreads */
# include <pthread.h>

typedef pthread_once_t OPENSSL_INIT_ONCE;
# define OPENSSL_INIT_ONCE_STATIC_INIT          PTHREAD_ONCE_INIT
# define OPENSSL_INIT_ONCE_DYNAMIC_INIT(once)   (*(once) = PTHREAD_ONCE_INIT)

static void ossl_init_once_run(OPENSSL_INIT_ONCE *once, void (*init)(void))
{
    pthread_once(once, init);
}
#endif

static void ssl_library_stop(void);

static OPENSSL_INIT_ONCE ssl_base = OPENSSL_INIT_ONCE_STATIC_INIT;
static int ssl_base_inited = 0;
static void ossl_init_ssl_base(void)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
                    "Adding SSL ciphers and digests\n");
#endif
#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
#endif
#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_cbc());
#endif
#ifndef OPENSSL_NO_RC4
    EVP_add_cipher(EVP_rc4());
# ifndef OPENSSL_NO_MD5
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif
#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_cbc());
    /*
     * Not actually used for SSL/TLS but this makes PKCS#12 work if an
     * application only calls SSL_library_init().
     */
    EVP_add_cipher(EVP_rc2_40_cbc());
#endif
#ifndef OPENSSL_NO_AES
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
#endif
#ifndef OPENSSL_NO_CAMELLIA
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_256_cbc());
#endif
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    EVP_add_cipher(EVP_chacha20_poly1305());
#endif

#ifndef OPENSSL_NO_SEED
    EVP_add_cipher(EVP_seed_cbc());
#endif

#ifndef OPENSSL_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
# ifndef OPENSSL_NO_SHA
    EVP_add_digest(EVP_md5_sha1());
# endif
#endif
    EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
#ifndef OPENSSL_NO_COMP
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
                    "SSL_COMP_get_compression_methods()\n");
#endif
    /*
     * This will initialise the built-in compression algorithms. The value
     * returned is a STACK_OF(SSL_COMP), but that can be discarded safely
     */
    SSL_COMP_get_compression_methods();
#endif
    /* initialize cipher/digest methods table */
    ssl_load_ciphers();

#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
                    "SSL_add_ssl_module()\n");
#endif
    SSL_add_ssl_module();
    /*
     * We ignore an error return here. Not much we can do - but not that bad
     * either. We can still safely continue.
     */
    OPENSSL_INIT_register_stop_handler(ssl_library_stop);
    ssl_base_inited = 1;
}

static OPENSSL_INIT_ONCE ssl_strings = OPENSSL_INIT_ONCE_STATIC_INIT;
static int ssl_strings_inited = 0;
static void ossl_init_load_ssl_strings(void)
{
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ossl_init_load_ssl_strings: "
                        "ERR_load_SSL_strings()\n");
#endif
    ERR_load_SSL_strings();
    ssl_strings_inited = 1;
}

static void ossl_init_no_load_ssl_strings(void)
{
    /* Do nothing in this case */
    return;
}

static void ssl_library_stop(void)
{
    if (ssl_base_inited) {
#ifndef OPENSSL_NO_COMP
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ssl_library_stop: "
                        "SSL_COMP_free_compression_methods()\n");
#endif
        SSL_COMP_free_compression_methods();
        ssl_base_inited = 0;
        OPENSSL_INIT_ONCE_DYNAMIC_INIT(&ssl_base);
#endif
    }

    if (ssl_strings_inited) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ssl_library_stop: "
                        "ERR_free_strings()\n");
#endif
        /*
         * If both crypto and ssl error strings are inited we will end up
         * calling ERR_free_strings() twice - but that's ok. The second time
         * will be a no-op. It's easier to do that than to try and track
         * between the two libraries whether they have both been inited.
         */
        ERR_free_strings();
        ssl_strings_inited = 0;
        OPENSSL_INIT_ONCE_DYNAMIC_INIT(&ssl_strings);
    }
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any OpenSSL functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
void OPENSSL_INIT_ssl_library_start(uint64_t opts,
                                 const OPENSSL_INIT_SETTINGS *settings)
{
    OPENSSL_INIT_crypto_library_start(opts | OPENSSL_INIT_ADD_ALL_CIPHERS
                                   | OPENSSL_INIT_ADD_ALL_DIGESTS, settings);

    ossl_init_once_run(&ssl_base, ossl_init_ssl_base);

    if (opts & OPENSSL_INIT_NO_LOAD_SSL_STRINGS)
        ossl_init_once_run(&ssl_strings, ossl_init_no_load_ssl_strings);

    if (opts & OPENSSL_INIT_LOAD_SSL_STRINGS)
        ossl_init_once_run(&ssl_strings, ossl_init_load_ssl_strings);
}

