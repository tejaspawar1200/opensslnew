/* evp_test.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/* Remove spaces from beginning and end of a string */

static void remove_space(char **pval)
{
    unsigned char *p = (unsigned char *)*pval;

    while (isspace(*p))
        p++;

    *pval = (char *)p;

    p = p + strlen(*pval) - 1;

    /* Remove trailing space */
    while (isspace(*p))
        *p-- = 0;
}

/*
 * Given a line of the form:
 *      name = value # comment
 * extract name and value. NB: modifies passed buffer.
 */

static int parse_line(char **pkw, char **pval, char *linebuf)
{
    char *p;

    p = linebuf + strlen(linebuf) - 1;

    if (*p != '\n') {
        fprintf(stderr, "FATAL: missing EOL\n");
        exit(1);
    }

    /* Look for # */

    p = strchr(linebuf, '#');

    if (p)
        *p = '\0';

    /* Look for = sign */
    p = strchr(linebuf, '=');

    /* If no '=' exit */
    if (!p)
        return 0;

    *p++ = '\0';

    *pkw = linebuf;
    *pval = p;

    /* Remove spaces from keyword and value */
    remove_space(pkw);
    remove_space(pval);

    return 1;
}

/* For a hex string "value" convert to a binary allocated buffer */
static int test_bin(const char *value, unsigned char **buf, size_t *buflen)
{
    long len;
    if (!*value) {
        /* Don't return NULL for zero length buffer */
        *buf = OPENSSL_malloc(1);
        if (!*buf)
            return 0;
        **buf = 0;
        *buflen = 0;
        return 1;
    }
    *buf = string_to_hex(value, &len);
    if (!*buf) {
        fprintf(stderr, "Value=%s\n", value);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    /* Size of input buffer means we'll never overflow */
    *buflen = len;
    return 1;
}

/* Structure holding test information */
struct evp_test {
    /* method for this test */
    const struct evp_test_method *meth;
    /* current line being processed */
    unsigned int line;
    /* start line of current test */
    unsigned int start_line;
    /* Error string for test */
    const char *err;
    /* Expected error value of test */
    char *expected_err;
    /* Number of tests */
    int ntests;
    /* Error count */
    int errors;
    /* test specific data */
    void *data;
};
/* Test method structure */
struct evp_test_method {
    /* Name of test as it appears in file */
    const char *name;
    /* Initialise test for "alg" */
    int (*init) (struct evp_test * t, const char *alg);
    /* Clean up method */
    void (*cleanup) (struct evp_test * t);
    /* Test specific name value pair processing */
    int (*parse) (struct evp_test * t, const char *name, const char *value);
    /* Run the test itself */
    int (*run_test) (struct evp_test * t);
};

static const struct evp_test_method digest_test_method, cipher_test_method;
static const struct evp_test_method aead_test_method;

static const struct evp_test_method *evp_test_list[] = {
    &digest_test_method,
    &cipher_test_method,
    NULL,
};

static const struct evp_test_method *evp_find_test(const char *name)
{
    const struct evp_test_method **tt;
    for (tt = evp_test_list; *tt; tt++) {
        if (!strcmp(name, (*tt)->name))
            return *tt;
    }
    return NULL;
}

static int check_test_error(struct evp_test *t)
{
    if (!t->err && !t->expected_err)
        return 1;
    if (t->err && !t->expected_err) {
        fprintf(stderr, "Test line %d: unexpected error %s\n",
                t->start_line, t->err);
        return 0;
    }
    if (!t->err && t->expected_err) {
        fprintf(stderr, "Test line %d: succeeded expecting %s\n",
                t->start_line, t->expected_err);
        return 0;
    }
    if (!strcmp(t->err, t->expected_err))
        return 1;

    fprintf(stderr, "Test line %d: expecting %s got %s\n",
            t->start_line, t->expected_err, t->err);
    return 0;
}

/* Setup a new test, run any existing test */

static int setup_test(struct evp_test *t, const struct evp_test_method *tmeth)
{
    /* If we already have a test set up run it */
    if (t->meth) {
        t->ntests++;
        t->err = NULL;
        if (t->meth->run_test(t) != 1) {
            fprintf(stderr, "%s test error line %d\n",
                    t->meth->name, t->start_line);
            return 0;
        }
        if (!check_test_error(t)) {
            if (t->err)
                ERR_print_errors_fp(stderr);
            t->errors++;
        }
        ERR_clear_error();
        t->meth->cleanup(t);
        /* If new test type free old data */
        if (tmeth != t->meth && t->data) {
            OPENSSL_free(t->data);
            t->data = NULL;
        }
        if (t->expected_err) {
            OPENSSL_free(t->expected_err);
            t->expected_err = NULL;
        }
    }
    t->meth = tmeth;
    return 1;
}

static int process_test(struct evp_test *t, char *buf, int verbose)
{
    char *keyword, *value;
    int rv = 0;
    const struct evp_test_method *tmeth;
    if (verbose)
        fputs(buf, stdout);
    if (!parse_line(&keyword, &value, buf))
        return 1;
    /* See if keyword corresponds to a test start */
    tmeth = evp_find_test(keyword);
    if (tmeth) {
        if (!setup_test(t, tmeth))
            return 0;
        t->start_line = t->line;
        if (!tmeth->init(t, value)) {
            fprintf(stderr, "Unknown %s: %s\n", keyword, value);
            return 0;
        }
        return 1;
    } else if (!strcmp(keyword, "Result")) {
        if (t->expected_err) {
            fprintf(stderr, "Line %d: multiple result lines\n", t->line);
            return 0;
        }
        t->expected_err = BUF_strdup(value);
        if (!t->expected_err)
            return 0;
    } else {
        /* Must be test specific line: try to parse it */
        if (t->meth)
            rv = t->meth->parse(t, keyword, value);

        if (rv == 0)
            fprintf(stderr, "line %d: unexpected keyword %s\n",
                    t->line, keyword);

        if (rv < 0)
            fprintf(stderr, "line %d: error processing keyword %s\n",
                    t->line, keyword);
        if (rv <= 0)
            return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    FILE *in = NULL;
    char buf[10240];
    struct evp_test t;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    t.meth = NULL;
    t.err = NULL;
    t.line = 0;
    t.start_line = -1;
    t.errors = 0;
    t.ntests = 0;
    in = fopen(argv[1], "r");
    while (fgets(buf, sizeof(buf), in)) {
        t.line++;
        if (!process_test(&t, buf, 0))
            exit(1);
    }
    /* Run any final test we have */
    if (!setup_test(&t, NULL))
        exit(1);
    fprintf(stderr, "%d tests completed with %d errors\n",
            t.ntests, t.errors);
    fclose(in);
    return 0;
}

static void test_free(void *d)
{
    if (d)
        OPENSSL_free(d);
}

/* Message digest tests */

struct digest_data {
    /* Digest this test is for */
    const EVP_MD *digest;
    /* Input to digest */
    unsigned char *input;
    size_t input_len;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
};

static int digest_test_init(struct evp_test *t, const char *alg)
{
    const EVP_MD *digest;
    struct digest_data *mdat = t->data;
    digest = EVP_get_digestbyname(alg);
    if (!digest)
        return 0;
    mdat = OPENSSL_malloc(sizeof(struct digest_data));
    mdat->digest = digest;
    mdat->input = NULL;
    mdat->output = NULL;
    t->data = mdat;
    return 1;
}

static void digest_test_cleanup(struct evp_test *t)
{
    struct digest_data *mdat = t->data;
    test_free(mdat->input);
    test_free(mdat->output);
}

static int digest_test_parse(struct evp_test *t,
                             const char *keyword, const char *value)
{
    struct digest_data *mdata = t->data;
    if (!strcmp(keyword, "Input"))
        return test_bin(value, &mdata->input, &mdata->input_len);
    if (!strcmp(keyword, "Output"))
        return test_bin(value, &mdata->output, &mdata->output_len);
    return 0;
}

static int digest_test_run(struct evp_test *t)
{
    struct digest_data *mdata = t->data;
    const char *err = "INTERNAL_ERROR";
    EVP_MD_CTX *mctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    mctx = EVP_MD_CTX_create();
    if (!mctx)
        goto err;
    err = "DIGESTINIT_ERROR";
    if (!EVP_DigestInit_ex(mctx, mdata->digest, NULL))
        goto err;
    err = "DIGESTUPDATE_ERROR";
    if (!EVP_DigestUpdate(mctx, mdata->input, mdata->input_len))
        goto err;
    err = "DIGESTFINAL_ERROR";
    if (!EVP_DigestFinal(mctx, md, &md_len))
        goto err;
    err = "DIGEST_LENGTH_MISMATCH";
    if (md_len != mdata->output_len)
        goto err;
    err = "DIGEST_MISMATCH";
    if (memcmp(mdata->output, md, md_len))
        goto err;
    err = NULL;
 err:
    if (mctx)
        EVP_MD_CTX_destroy(mctx);
    t->err = err;
    return err ? 0 : 1;
}

static const struct evp_test_method digest_test_method = {
    "Digest",
    digest_test_init,
    digest_test_cleanup,
    digest_test_parse,
    digest_test_run
};

/* Cipher tests */
struct cipher_data {
    const EVP_CIPHER *cipher;
    int enc;
    /* Set to EVP_CIPH_GCM_MODE or EVP_CIPH_CCM_MODE if AEAD */
    int aead;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char *plaintext;
    size_t plaintext_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    /* GCM, CCM only */
    unsigned char *aad;
    size_t aad_len;
    unsigned char *tag;
    size_t tag_len;
};

static int cipher_test_init(struct evp_test *t, const char *alg)
{
    const EVP_CIPHER *cipher;
    struct cipher_data *cdat = t->data;
    cipher = EVP_get_cipherbyname(alg);
    if (!cipher)
        return 0;
    cdat = OPENSSL_malloc(sizeof(struct cipher_data));
    cdat->cipher = cipher;
    cdat->enc = -1;
    cdat->key = NULL;
    cdat->iv = NULL;
    cdat->ciphertext = NULL;
    cdat->plaintext = NULL;
    cdat->aad = NULL;
    cdat->tag = NULL;
    t->data = cdat;
    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE
        || EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE)
        cdat->aead = EVP_CIPHER_mode(cipher);
    else
        cdat->aead = 0;

    return 1;
}

static void cipher_test_cleanup(struct evp_test *t)
{
    struct cipher_data *cdat = t->data;
    test_free(cdat->key);
    test_free(cdat->iv);
    test_free(cdat->ciphertext);
    test_free(cdat->plaintext);
    test_free(cdat->aad);
    test_free(cdat->tag);
}

static int cipher_test_parse(struct evp_test *t, const char *keyword,
                             const char *value)
{
    struct cipher_data *cdat = t->data;
    if (!strcmp(keyword, "Key"))
        return test_bin(value, &cdat->key, &cdat->key_len);
    if (!strcmp(keyword, "IV"))
        return test_bin(value, &cdat->iv, &cdat->iv_len);
    if (!strcmp(keyword, "Plaintext"))
        return test_bin(value, &cdat->plaintext, &cdat->plaintext_len);
    if (!strcmp(keyword, "Ciphertext"))
        return test_bin(value, &cdat->ciphertext, &cdat->ciphertext_len);
    if (cdat->aead) {
        if (!strcmp(keyword, "AAD"))
            return test_bin(value, &cdat->aad, &cdat->aad_len);
        if (!strcmp(keyword, "Tag"))
            return test_bin(value, &cdat->tag, &cdat->tag_len);
    }

    if (!strcmp(keyword, "Operation")) {
        if (!strcmp(value, "ENCRYPT"))
            cdat->enc = 1;
        else if (!strcmp(value, "DECRYPT"))
            cdat->enc = 0;
        else
            return 0;
        return 1;
    }
    return 0;
}

static int cipher_test_enc(struct evp_test *t, int enc)
{
    struct cipher_data *cdat = t->data;
    unsigned char *in, *out, *tmp = NULL;
    size_t in_len, out_len;
    int tmplen, tmpflen;
    EVP_CIPHER_CTX *ctx = NULL;
    const char *err;
    err = "INTERNAL_ERROR";
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto err;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (enc) {
        in = cdat->plaintext;
        in_len = cdat->plaintext_len;
        out = cdat->ciphertext;
        out_len = cdat->ciphertext_len;
    } else {
        in = cdat->ciphertext;
        in_len = cdat->ciphertext_len;
        out = cdat->plaintext;
        out_len = cdat->plaintext_len;
    }
    tmp = OPENSSL_malloc(in_len + 2 * EVP_MAX_BLOCK_LENGTH);
    if (!tmp)
        goto err;
    err = "CIPHERINIT_ERROR";
    if (!EVP_CipherInit_ex(ctx, cdat->cipher, NULL, NULL, NULL, enc))
        goto err;
    err = "INVALID_IV_LENGTH";
    if (cdat->iv) {
        if (cdat->aead == EVP_CIPH_GCM_MODE) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                     cdat->iv_len, 0))
                goto err;
        } else if (cdat->aead == EVP_CIPH_CCM_MODE) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
                                     cdat->iv_len, 0))
                goto err;
        } else if (cdat->iv_len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
            goto err;
    }
    if (cdat->aead) {
        unsigned char *tag;
        /*
         * If encrypting just set tag length. If decrypting set
         * tag length and value.
         */
        if (enc) {
            err = "TAG_LENGTH_SET_ERROR";
            tag = NULL;
        } else {
            err = "TAG_SET_ERROR";
            tag = cdat->tag;
        }
        if (cdat->aead == EVP_CIPH_GCM_MODE && tag) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                     cdat->tag_len, tag))
                goto err;
        } else if (cdat->aead == EVP_CIPH_CCM_MODE) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
                                     cdat->tag_len, tag))
                goto err;
        }
    }

    err = "INVALID_KEY_LENGTH";
    if (!EVP_CIPHER_CTX_set_key_length(ctx, cdat->key_len))
        goto err;
    err = "KEY_SET_ERROR";
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, cdat->key, cdat->iv, -1))
        goto err;

    if (cdat->aead == EVP_CIPH_CCM_MODE) {
        if (!EVP_CipherUpdate(ctx, NULL, &tmplen, NULL, out_len)) {
            err = "CCM_PLAINTEXT_LENGTH_SET_ERROR";
            goto err;
        }
    }
    if (cdat->aad) {
        if (!EVP_CipherUpdate(ctx, NULL, &tmplen, cdat->aad, cdat->aad_len)) {
            err = "AAD_SET_ERROR";
            goto err;
        }
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    err = "CIPHERUPDATE_ERROR";
    if (!EVP_CipherUpdate(ctx, tmp, &tmplen, in, in_len))
        goto err;
    if (cdat->aead == EVP_CIPH_CCM_MODE)
        tmpflen = 0;
    else {
        err = "CIPHERFINAL_ERROR";
        if (!EVP_CipherFinal_ex(ctx, tmp + tmplen, &tmpflen))
            goto err;
    }
    err = "LENGTH_MISMATCH";
    if (out_len != (size_t)(tmplen + tmpflen))
        goto err;
    err = "VALUE_MISMATCH";
    if (memcmp(out, tmp, out_len))
        goto err;
    if (enc && cdat->aead) {
        unsigned char rtag[16];
        if (cdat->tag_len > sizeof(rtag)) {
            err = "TAG_LENGTH_INTERNAL_ERROR";
            goto err;
        }
        /* EVP_CTRL_CCM_GET_TAG and EVP_CTRL_GCM_GET_TAG are equal. */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 cdat->tag_len, rtag)) {
            err = "TAG_RETRIEVE_ERROR";
            goto err;
        }
        if (memcmp(cdat->tag, rtag, cdat->tag_len)) {
            err = "TAG_VALUE_MISMATCH";
            goto err;
        }
    }
    err = NULL;
 err:
    if (tmp)
        OPENSSL_free(tmp);
    EVP_CIPHER_CTX_free(ctx);
    t->err = err;
    return err ? 0 : 1;
}

static int cipher_test_run(struct evp_test *t)
{
    struct cipher_data *cdat = t->data;
    int rv;
    if (!cdat->key) {
        t->err = "NO_KEY";
        return 0;
    }
    if (!cdat->iv && EVP_CIPHER_iv_length(cdat->cipher)) {
        /* IV is optional and usually omitted in wrap mode */
        if (EVP_CIPHER_mode(cdat->cipher) != EVP_CIPH_WRAP_MODE) {
            t->err = "NO_IV";
            return 0;
        }
    }
    if (cdat->aead && !cdat->tag) {
        t->err = "NO_TAG";
        return 0;
    }
    if (cdat->enc) {
        rv = cipher_test_enc(t, 1);
        /* Not fatal errors: return */
        if (rv != 1) {
            if (rv < 0)
                return 0;
            return 1;
        }
    }
    if (cdat->enc != 1) {
        rv = cipher_test_enc(t, 0);
        /* Not fatal errors: return */
        if (rv != 1) {
            if (rv < 0)
                return 0;
            return 1;
        }
    }
    return 1;
}

static const struct evp_test_method cipher_test_method = {
    "Cipher",
    cipher_test_init,
    cipher_test_cleanup,
    cipher_test_parse,
    cipher_test_run
};
