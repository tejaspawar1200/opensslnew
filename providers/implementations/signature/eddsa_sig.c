/*
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/der_ecx.h"
#include "crypto/ecx.h"

#ifdef S390X_EC_ASM
# include "s390x_arch.h"

# define S390X_CAN_SIGN(edtype)                                                \
((OPENSSL_s390xcap_P.pcc[1] & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_##edtype))    \
&& (OPENSSL_s390xcap_P.kdsa[0] & S390X_CAPBIT(S390X_EDDSA_SIGN_##edtype))      \
&& (OPENSSL_s390xcap_P.kdsa[0] & S390X_CAPBIT(S390X_EDDSA_VERIFY_##edtype)))

static int s390x_ed25519_digestsign(const ECX_KEY *edkey, unsigned char *sig,
                                    const unsigned char *tbs, size_t tbslen);
static int s390x_ed448_digestsign(const ECX_KEY *edkey, unsigned char *sig,
                                  const unsigned char *tbs, size_t tbslen);
static int s390x_ed25519_digestverify(const ECX_KEY *edkey,
                                      const unsigned char *sig,
                                      const unsigned char *tbs, size_t tbslen);
static int s390x_ed448_digestverify(const ECX_KEY *edkey,
                                    const unsigned char *sig,
                                    const unsigned char *tbs, size_t tbslen);

#endif /* S390X_EC_ASM */

enum ID_EdDSA_INSTANCE {
    ID_NOT_SET = 0,
    ID_Ed25519,
    ID_Ed25519ctx,
    ID_Ed25519ph,
    ID_Ed448,
    ID_Ed448ph
};

#define SN_Ed25519    "Ed25519"
#define SN_Ed25519ph  "Ed25519ph"
#define SN_Ed25519ctx "Ed25519ctx"
#define SN_Ed448      "Ed448"
#define SN_Ed448ph    "Ed448ph"

#define EDDSA_MAX_CONTEXT_STRING_LEN 255
#define EDDSA_PREHASH_OUTPUT_LEN 64

static OSSL_FUNC_signature_newctx_fn eddsa_newctx;
static OSSL_FUNC_signature_digest_sign_init_fn eddsa_digest_signverify_init;
static OSSL_FUNC_signature_digest_sign_fn ed25519_digest_sign;
static OSSL_FUNC_signature_digest_sign_fn ed448_digest_sign;
static OSSL_FUNC_signature_digest_verify_fn ed25519_digest_verify;
static OSSL_FUNC_signature_digest_verify_fn ed448_digest_verify;
static OSSL_FUNC_signature_freectx_fn eddsa_freectx;
static OSSL_FUNC_signature_dupctx_fn eddsa_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn eddsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn eddsa_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn eddsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn eddsa_settable_ctx_params;
static OSSL_FUNC_signature_digest_verify_update_fn ed25519_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn ed25519_verify_final;
static OSSL_FUNC_signature_set_signature_fn ed25519_verify_set_signature;

/* there are five EdDSA instances:

         Ed25519
         Ed25519ph
         Ed25519ctx
         Ed448
         Ed448ph

   Quoting from RFC 8032, Section 5.1:

     For Ed25519, dom2(f,c) is the empty string.  The phflag value is
     irrelevant.  The context (if present at all) MUST be empty.  This
     causes the scheme to be one and the same with the Ed25519 scheme
     published earlier.

     For Ed25519ctx, phflag=0.  The context input SHOULD NOT be empty.

     For Ed25519ph, phflag=1 and PH is SHA512 instead.  That is, the input
     is hashed using SHA-512 before signing with Ed25519.

   Quoting from RFC 8032, Section 5.2:

     Ed448ph is the same but with PH being SHAKE256(x, 64) and phflag
     being 1, i.e., the input is hashed before signing with Ed448 with a
     hash constant modified.

     Value of context is set by signer and verifier (maximum of 255
     octets; the default is empty string) and has to match octet by octet
     for verification to be successful.

   Quoting from RFC 8032, Section 2:

     dom2(x, y)     The blank octet string when signing or verifying
                    Ed25519.  Otherwise, the octet string: "SigEd25519 no
                    Ed25519 collisions" || octet(x) || octet(OLEN(y)) ||
                    y, where x is in range 0-255 and y is an octet string
                    of at most 255 octets.  "SigEd25519 no Ed25519
                    collisions" is in ASCII (32 octets).

     dom4(x, y)     The octet string "SigEd448" || octet(x) ||
                    octet(OLEN(y)) || y, where x is in range 0-255 and y
                    is an octet string of at most 255 octets.  "SigEd448"
                    is in ASCII (8 octets).

   Note above that x is the pre-hash flag, and y is the context string.
*/

typedef struct {
    OSSL_LIB_CTX *libctx;
    ECX_KEY *key;
    EVP_MD_CTX *mdctx;

    /* The Algorithm Identifier of the signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* id indicating the EdDSA instance */
    int instance_id;

    unsigned int dom2_flag : 1;
    unsigned int prehash_flag : 1;

    /* indicates that a non-empty context string is required, as in Ed25519ctx */
    unsigned int context_string_flag : 1;

    unsigned char context_string[EDDSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;
    unsigned char *sig;
    size_t siglen;

} PROV_EDDSA_CTX;

static void *eddsa_newctx(void *provctx, const char *propq_unused)
{
    PROV_EDDSA_CTX *peddsactx;

    if (!ossl_prov_is_running())
        return NULL;

    peddsactx = OPENSSL_zalloc(sizeof(PROV_EDDSA_CTX));
    if (peddsactx == NULL)
        return NULL;

    peddsactx->libctx = PROV_LIBCTX_OF(provctx);

    return peddsactx;
}

static int eddsa_digest_signverify_init(void *vpeddsactx, const char *mdname,
                                        void *vedkey,
                                        const OSSL_PARAM params[])
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    ECX_KEY *edkey = (ECX_KEY *)vedkey;
    WPACKET pkt;
    int ret;

    if (!ossl_prov_is_running())
        return 0;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return 0;
    }

    if (edkey == NULL) {
        if (peddsactx->key != NULL)
            return eddsa_set_ctx_params(peddsactx, params);
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (!ossl_ecx_key_up_ref(edkey)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    peddsactx->dom2_flag = 0;
    peddsactx->prehash_flag = 0;
    peddsactx->context_string_flag = 0;
    peddsactx->context_string_len = 0;

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    peddsactx->aid_len = 0;
    ret = WPACKET_init_der(&pkt, peddsactx->aid_buf, sizeof(peddsactx->aid_buf));
    switch (edkey->type) {
    case ECX_KEY_TYPE_ED25519:
        ret = ret && ossl_DER_w_algorithmIdentifier_ED25519(&pkt, -1, edkey);
        peddsactx->instance_id = ID_Ed25519;
        break;
    case ECX_KEY_TYPE_ED448:
        ret = ret && ossl_DER_w_algorithmIdentifier_ED448(&pkt, -1, edkey);
        peddsactx->instance_id = ID_Ed448;
        break;
    default:
        /* Should never happen */
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ossl_ecx_key_free(edkey);
        return 0;
    }
    if (ret && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &peddsactx->aid_len);
        peddsactx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    peddsactx->key = edkey;

    if (!eddsa_set_ctx_params(peddsactx, params))
        return 0;

    return 1;
}

int ed25519_digest_sign(void *vpeddsactx, unsigned char *sigret,
                        size_t *siglen, size_t sigsize,
                        const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    uint8_t md[EVP_MAX_MD_SIZE];
    size_t mdlen;

    if (!ossl_prov_is_running())
        return 0;

    if (sigret == NULL) {
        *siglen = ED25519_SIGSIZE;
        return 1;
    }
    if (sigsize < ED25519_SIGSIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (edkey->privkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }
#ifdef S390X_EC_ASM
    /* s390x_ed25519_digestsign() does not yet support dom2 or context-strings.
       fall back to non-accelerated sign if those options are set. */
    if (S390X_CAN_SIGN(ED25519)
            && !peddsactx->dom2_flag
            && !peddsactx->context_string_flag
            && peddsactx->context_string_len == 0) {
        if (s390x_ed25519_digestsign(edkey, sigret, tbs, tbslen) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
            return 0;
        }
        *siglen = ED25519_SIGSIZE;
        return 1;
    }
#endif /* S390X_EC_ASM */

    if (peddsactx->prehash_flag) {
        if (!EVP_Q_digest(peddsactx->libctx, SN_sha512, NULL, tbs, tbslen, md, &mdlen)
                || mdlen != EDDSA_PREHASH_OUTPUT_LEN)
            return 0;
        tbs = md;
        tbslen = mdlen;
    }

    if (ossl_ed25519_sign(sigret, tbs, tbslen, edkey->pubkey, edkey->privkey,
            peddsactx->dom2_flag, peddsactx->prehash_flag, peddsactx->context_string_flag,
            peddsactx->context_string, peddsactx->context_string_len,
            peddsactx->libctx, NULL) == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    *siglen = ED25519_SIGSIZE;
    return 1;
}

/* EVP_Q_digest() does not allow variable output length for XOFs,
   so we use this function */
static int ed448_shake256(OSSL_LIB_CTX *libctx,
                          const char *propq,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t outlen)
{
    int ret = 0;
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_MD *shake256 = EVP_MD_fetch(libctx, SN_shake256, propq);

    if (hash_ctx == NULL || shake256 == NULL)
        goto err;

    if (!EVP_DigestInit_ex(hash_ctx, shake256, NULL)
            || !EVP_DigestUpdate(hash_ctx, in, inlen)
            || !EVP_DigestFinalXOF(hash_ctx, out, outlen))
        goto err;

    ret = 1;

 err:
    EVP_MD_CTX_free(hash_ctx);
    EVP_MD_free(shake256);
    return ret;
}

int ed448_digest_sign(void *vpeddsactx, unsigned char *sigret,
                      size_t *siglen, size_t sigsize,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    uint8_t md[EDDSA_PREHASH_OUTPUT_LEN];
    size_t mdlen = sizeof(md);

    if (!ossl_prov_is_running())
        return 0;

    if (sigret == NULL) {
        *siglen = ED448_SIGSIZE;
        return 1;
    }
    if (sigsize < ED448_SIGSIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (edkey->privkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }
#ifdef S390X_EC_ASM
    /* s390x_ed448_digestsign() does not yet support context-strings or pre-hashing.
       fall back to non-accelerated sign if a context-string or pre-hasing is provided. */
    if (S390X_CAN_SIGN(ED448)
            && peddsactx->context_string_len == 0
            && peddsactx->prehash_flag == 0) {
        if (s390x_ed448_digestsign(edkey, sigret, tbs, tbslen) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
            return 0;
        }
        *siglen = ED448_SIGSIZE;
        return 1;
    }
#endif /* S390X_EC_ASM */

    if (peddsactx->prehash_flag) {
        if (!ed448_shake256(peddsactx->libctx, NULL, tbs, tbslen, md, mdlen))
            return 0;
        tbs = md;
        tbslen = mdlen;
    }

    if (ossl_ed448_sign(peddsactx->libctx, sigret, tbs, tbslen,
                        edkey->pubkey, edkey->privkey,
                        peddsactx->context_string, peddsactx->context_string_len,
                        peddsactx->prehash_flag, edkey->propq) == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    *siglen = ED448_SIGSIZE;
    return 1;
}

int ed25519_verify_set_signature(void *vpeddsactx,
                                 const unsigned char *sig, size_t siglen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running())
        return 0;
    if (siglen != ED25519_SIGSIZE)
        return 0;
    if (edkey == NULL)
        return 0;

    if (peddsactx->mdctx == NULL) {
        peddsactx->mdctx = EVP_MD_CTX_new();
        if (peddsactx->mdctx == NULL)
            return 0;
    } else {
        if (!EVP_MD_CTX_reset(peddsactx->mdctx))
            return 0;
    }
    /* Multiple calls of ed25519_verify_set_signature are not allowed */
    if (peddsactx->sig != NULL)
        return 0;
    peddsactx->sig = OPENSSL_memdup(sig, siglen);
    if (peddsactx->sig == NULL)
        return 0;
    peddsactx->siglen = siglen;
    return ossl_ed25519_verify_init(peddsactx->mdctx,
                                    peddsactx->sig, edkey->pubkey,
                                    peddsactx->dom2_flag, peddsactx->prehash_flag,
                                    peddsactx->context_string_flag,
                                    peddsactx->context_string,
                                    peddsactx->context_string_len,
                                    peddsactx->libctx, edkey->propq);
}

int ed25519_verify_update(void *vpeddsactx,
                          const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;

    if (!ossl_prov_is_running())
        return 0;
    if (peddsactx->mdctx == NULL)
        return 0;
    return ossl_ed25519_verify_update(peddsactx->mdctx, tbs, tbslen);
}

int ed25519_verify_final(void *vpeddsactx, const unsigned char *sig,
                        size_t siglen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running())
        return 0;

    return ossl_ed25519_verify_final(peddsactx->mdctx,
                                     peddsactx->sig, edkey->pubkey);
}

int ed25519_digest_verify(void *vpeddsactx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    uint8_t md[EVP_MAX_MD_SIZE];
    size_t mdlen;

    if (!ossl_prov_is_running() || siglen != ED25519_SIGSIZE)
        return 0;

#ifdef S390X_EC_ASM
    /* s390x_ed25519_digestverify() does not yet support dom2 or context-strings.
       fall back to non-accelerated verify if those options are set. */
    if (S390X_CAN_SIGN(ED25519)
            && !peddsactx->dom2_flag
            && !peddsactx->context_string_flag
            && peddsactx->context_string_len == 0) {
        return s390x_ed25519_digestverify(edkey, sig, tbs, tbslen);
    }
#endif /* S390X_EC_ASM */

    if (peddsactx->prehash_flag) {
        if (!EVP_Q_digest(peddsactx->libctx, SN_sha512, NULL, tbs, tbslen, md, &mdlen)
                || mdlen != EDDSA_PREHASH_OUTPUT_LEN)
            return 0;
        tbs = md;
        tbslen = mdlen;
    }

    return ossl_ed25519_verify(tbs, tbslen, sig, edkey->pubkey,
                               peddsactx->dom2_flag, peddsactx->prehash_flag, peddsactx->context_string_flag,
                               peddsactx->context_string, peddsactx->context_string_len,
                               peddsactx->libctx, edkey->propq);
}

int ed448_digest_verify(void *vpeddsactx, const unsigned char *sig,
                        size_t siglen, const unsigned char *tbs,
                        size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    uint8_t md[EDDSA_PREHASH_OUTPUT_LEN];
    size_t mdlen = sizeof(md);

    if (!ossl_prov_is_running() || siglen != ED448_SIGSIZE)
        return 0;

#ifdef S390X_EC_ASM
    /* s390x_ed448_digestverify() does not yet support context-strings or pre-hashing.
       fall back to non-accelerated verify if a context-string or pre-hasing is provided. */
    if (S390X_CAN_SIGN(ED448)
            && peddsactx->context_string_len == 0
            && peddsactx->prehash_flag == 0) {
        return s390x_ed448_digestverify(edkey, sig, tbs, tbslen);
    }
#endif /* S390X_EC_ASM */

    if (peddsactx->prehash_flag) {
        if (!ed448_shake256(peddsactx->libctx, NULL, tbs, tbslen, md, mdlen))
            return 0;
        tbs = md;
        tbslen = mdlen;
    }

    return ossl_ed448_verify(peddsactx->libctx, tbs, tbslen, sig, edkey->pubkey,
                             peddsactx->context_string, peddsactx->context_string_len,
                             peddsactx->prehash_flag, edkey->propq);
}

static void eddsa_freectx(void *vpeddsactx)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;

    OPENSSL_free(peddsactx->sig);
    EVP_MD_CTX_free(peddsactx->mdctx);
    ossl_ecx_key_free(peddsactx->key);

    OPENSSL_free(peddsactx);
}

static void *eddsa_dupctx(void *vpeddsactx)
{
    PROV_EDDSA_CTX *srcctx = (PROV_EDDSA_CTX *)vpeddsactx;
    PROV_EDDSA_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->key = NULL;
    dstctx->mdctx = NULL;
    dstctx->sig = NULL;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_dup(srcctx->mdctx);
        if (dstctx->mdctx == NULL)
            goto err;
    }
    if (srcctx->sig != NULL) {
        dstctx->sig = OPENSSL_memdup(srcctx->sig, srcctx->siglen);
        if (dstctx->sig == NULL)
            goto err;
    }

    if (srcctx->key != NULL && !ossl_ecx_key_up_ref(srcctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    dstctx->key = srcctx->key;

    return dstctx;
 err:
    eddsa_freectx(dstctx);
    return NULL;
}

static int eddsa_get_ctx_params(void *vpeddsactx, OSSL_PARAM *params)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    OSSL_PARAM *p;

    if (peddsactx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, peddsactx->aid,
                                                  peddsactx->aid_len))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *eddsa_gettable_ctx_params(ossl_unused void *vpeddsactx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int eddsa_set_ctx_params(void *vpeddsactx, const OSSL_PARAM params[])
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const OSSL_PARAM *p;

    if (peddsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_INSTANCE);
    if (p != NULL) {
        char instance_name[OSSL_MAX_NAME_SIZE] = "";
        char *pinstance_name = instance_name;

        if (!OSSL_PARAM_get_utf8_string(p, &pinstance_name, sizeof(instance_name)))
            return 0;

        if (OPENSSL_strcasecmp(pinstance_name, SN_Ed25519) == 0) {
            peddsactx->instance_id = ID_Ed25519;
            if (peddsactx->key->type != ECX_KEY_TYPE_ED25519) return 0;
            peddsactx->dom2_flag = 0;
            peddsactx->prehash_flag = 0;
            peddsactx->context_string_flag = 0;
        } else if (OPENSSL_strcasecmp(pinstance_name, SN_Ed25519ctx) == 0) {
            peddsactx->instance_id = ID_Ed25519ctx;
            if (peddsactx->key->type != ECX_KEY_TYPE_ED25519) return 0;
            peddsactx->dom2_flag = 1;
            peddsactx->prehash_flag = 0;
            peddsactx->context_string_flag = 1;
        } else if (OPENSSL_strcasecmp(pinstance_name, SN_Ed25519ph) == 0) {
            peddsactx->instance_id = ID_Ed25519ph;
            if (peddsactx->key->type != ECX_KEY_TYPE_ED25519) return 0;
            peddsactx->dom2_flag = 1;
            peddsactx->prehash_flag = 1;
            peddsactx->context_string_flag = 0;
        } else if (OPENSSL_strcasecmp(pinstance_name, SN_Ed448) == 0) {
            peddsactx->instance_id = ID_Ed448;
            if (peddsactx->key->type != ECX_KEY_TYPE_ED448) return 0;
            peddsactx->prehash_flag = 0;
            peddsactx->context_string_flag = 0;
        } else if (OPENSSL_strcasecmp(pinstance_name, SN_Ed448ph) == 0) {
            peddsactx->instance_id = ID_Ed448ph;
            if (peddsactx->key->type != ECX_KEY_TYPE_ED448) return 0;
            peddsactx->prehash_flag = 1;
            peddsactx->context_string_flag = 0;
        } else {
            /* we did not recognize the instance */
            return 0;
        }

    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *vp_context_string = peddsactx->context_string;

        if (!OSSL_PARAM_get_octet_string(p, &vp_context_string, sizeof(peddsactx->context_string), &(peddsactx->context_string_len))) {
            peddsactx->context_string_len = 0;
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *eddsa_settable_ctx_params(ossl_unused void *vpeddsactx,
                                                   ossl_unused void *provctx)
{
    return settable_ctx_params;
}

const OSSL_DISPATCH ossl_ed25519_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))ed25519_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))ed25519_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))eddsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_SIGNATURE,
      (void (*)(void))ed25519_verify_set_signature },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))ed25519_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))ed25519_verify_final },
    OSSL_DISPATCH_END
};

const OSSL_DISPATCH ossl_ed448_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))ed448_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))ed448_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))eddsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_settable_ctx_params },
    OSSL_DISPATCH_END
};

#ifdef S390X_EC_ASM

static int s390x_ed25519_digestsign(const ECX_KEY *edkey, unsigned char *sig,
                                    const unsigned char *tbs, size_t tbslen)
{
    int rc;
    union {
        struct {
            unsigned char sig[64];
            unsigned char priv[32];
        } ed25519;
        unsigned long long buff[512];
    } param;

    memset(&param, 0, sizeof(param));
    memcpy(param.ed25519.priv, edkey->privkey, sizeof(param.ed25519.priv));

    rc = s390x_kdsa(S390X_EDDSA_SIGN_ED25519, &param.ed25519, tbs, tbslen);
    OPENSSL_cleanse(param.ed25519.priv, sizeof(param.ed25519.priv));
    if (rc != 0)
        return 0;

    s390x_flip_endian32(sig, param.ed25519.sig);
    s390x_flip_endian32(sig + 32, param.ed25519.sig + 32);
    return 1;
}

static int s390x_ed448_digestsign(const ECX_KEY *edkey, unsigned char *sig,
                                  const unsigned char *tbs, size_t tbslen)
{
    int rc;
    union {
        struct {
            unsigned char sig[128];
            unsigned char priv[64];
        } ed448;
        unsigned long long buff[512];
    } param;

    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.priv + 64 - 57, edkey->privkey, 57);

    rc = s390x_kdsa(S390X_EDDSA_SIGN_ED448, &param.ed448, tbs, tbslen);
    OPENSSL_cleanse(param.ed448.priv, sizeof(param.ed448.priv));
    if (rc != 0)
        return 0;

    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(sig, param.ed448.sig, 57);
    memcpy(sig + 57, param.ed448.sig + 64, 57);
    return 1;
}

static int s390x_ed25519_digestverify(const ECX_KEY *edkey,
                                      const unsigned char *sig,
                                      const unsigned char *tbs, size_t tbslen)
{
    union {
        struct {
            unsigned char sig[64];
            unsigned char pub[32];
        } ed25519;
        unsigned long long buff[512];
    } param;

    memset(&param, 0, sizeof(param));
    s390x_flip_endian32(param.ed25519.sig, sig);
    s390x_flip_endian32(param.ed25519.sig + 32, sig + 32);
    s390x_flip_endian32(param.ed25519.pub, edkey->pubkey);

    return s390x_kdsa(S390X_EDDSA_VERIFY_ED25519,
                      &param.ed25519, tbs, tbslen) == 0 ? 1 : 0;
}

static int s390x_ed448_digestverify(const ECX_KEY *edkey,
                                    const unsigned char *sig,
                                    const unsigned char *tbs,
                                    size_t tbslen)
{
    union {
        struct {
            unsigned char sig[128];
            unsigned char pub[64];
        } ed448;
        unsigned long long buff[512];
    } param;

    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.sig, sig, 57);
    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    memcpy(param.ed448.sig + 64, sig + 57, 57);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(param.ed448.pub, edkey->pubkey, 57);
    s390x_flip_endian64(param.ed448.pub, param.ed448.pub);

    return s390x_kdsa(S390X_EDDSA_VERIFY_ED448,
                      &param.ed448, tbs, tbslen) == 0 ? 1 : 0;
}

#endif /* S390X_EC_ASM */
