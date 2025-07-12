// haetae_signature.c

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "haetae_context.h"

// Adjust the relative path to your sign.h as per your project structure
#include "sign.h"  // Your HAETAE crypto_sign_* functions declarations

// // Context struct for HAETAE signature operations
// typedef struct {
//     void *provctx;
//     uint8_t *privkey;
//     size_t privkey_len;
//     uint8_t *pubkey;
//     size_t pubkey_len;
// } HAETAE_CTX;

// Create new context
static void *haetae_newctx(void *provctx) {
    HAETAE_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->provctx = provctx;
    ctx->privkey = NULL;
    ctx->privkey_len = 0;
    ctx->pubkey = NULL;
    ctx->pubkey_len = 0;
    return ctx;
}

// Free the context and allocated keys
static void haetae_freectx(void *vctx) {
    HAETAE_CTX *ctx = vctx;
    if (!ctx)
        return;
    OPENSSL_free(ctx->privkey);
    OPENSSL_free(ctx->pubkey);
    OPENSSL_free(ctx);
}

// Initialize signing context by copying the private key from params
static int haetae_sign_init(void *vctx, void *provkey, const OSSL_PARAM params[]) {
    HAETAE_CTX *ctx = vctx;
    if (!ctx || !provkey)
        return 0;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!p || !p->data || p->data_size == 0)
        return 0;

    OPENSSL_free(ctx->privkey);
    ctx->privkey = OPENSSL_memdup(p->data, p->data_size);
    if (!ctx->privkey)
        return 0;
    ctx->privkey_len = p->data_size;

    return 1;
}

// Perform signing operation
static int haetae_sign(void *vctx,
                       unsigned char *sig, size_t *siglen, size_t sigsize,
                       const unsigned char *tbs, size_t tbslen) {
    HAETAE_CTX *ctx = vctx;
    if (!ctx || !ctx->privkey || !siglen)
        return 0;

    // If sig is NULL, just return signature size
    if (!sig) {
        *siglen = CRYPTO_BYTES;
        return 1;
    }

    if (sigsize < CRYPTO_BYTES)
        return 0;

    int ret = crypto_sign_signature(sig, siglen, tbs, tbslen, ctx->privkey);
    return (ret == 0);
}

// Initialize verification context by copying the public key from params
static int haetae_verify_init(void *vctx, void *provkey, const OSSL_PARAM params[]) {
    HAETAE_CTX *ctx = vctx;
    if (!ctx || !provkey)
        return 0;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p || !p->data || p->data_size == 0)
        return 0;

    OPENSSL_free(ctx->pubkey);
    ctx->pubkey = OPENSSL_memdup(p->data, p->data_size);
    if (!ctx->pubkey)
        return 0;
    ctx->pubkey_len = p->data_size;

    return 1;
}

// Perform verification operation
static int haetae_verify(void *vctx,
                        const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen) {
    HAETAE_CTX *ctx = vctx;
    if (!ctx || !ctx->pubkey)
        return 0;

    int ret = crypto_sign_verify(sig, siglen, tbs, tbslen, ctx->pubkey);
    return (ret == 0);
}

// Define dispatch table of signature functions for OpenSSL provider
static const OSSL_DISPATCH haetae_signature_functions_table[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))haetae_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))haetae_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))haetae_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))haetae_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))haetae_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))haetae_verify },
    { 0, NULL }
};

// Exported symbol for provider to load
const OSSL_DISPATCH *haetae_signature_functions(void) {
    return haetae_signature_functions_table;
}
