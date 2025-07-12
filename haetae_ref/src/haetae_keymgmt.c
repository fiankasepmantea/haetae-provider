#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "sign.h"  // HAETAE API header

extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define HAETAE_SECRET_KEY_LEN 3584
#define HAETAE_PUBLIC_KEY_LEN 1824

typedef struct {
    unsigned char sk[HAETAE_SECRET_KEY_LEN];
    unsigned char pk[HAETAE_PUBLIC_KEY_LEN];
    int has_private;
} HAETAE_KEY;

static void *haetae_key_new(void *provctx) {
    return OPENSSL_zalloc(sizeof(HAETAE_KEY));
}
static void haetae_key_free(void *keydata) {
    OPENSSL_cleanse(keydata, sizeof(HAETAE_KEY));
    OPENSSL_free(keydata);
}

static void *haetae_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) {
    HAETAE_KEY *k = genctx;
    if (!k || crypto_sign_keypair(k->pk, k->sk) != 0)
        return NULL;
    k->has_private = 1;
    return k;
}

static int haetae_export(void *keydata, int selection,
                         OSSL_CALLBACK *cb, void *cbarg) {
    HAETAE_KEY *k = keydata;
    OSSL_PARAM params[3];
    int idx = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && k->pk) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, k->pk, HAETAE_PUBLIC_KEY_LEN);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && k->has_private) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, k->sk, HAETAE_SECRET_KEY_LEN);
    }
    params[idx] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static int haetae_import(void *keydata, int selection,
                         const OSSL_PARAM params[]) {
    HAETAE_KEY *k = keydata;
    const OSSL_PARAM *p;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!p || p->data_size != HAETAE_PUBLIC_KEY_LEN) return 0;
        memcpy(k->pk, p->data, HAETAE_PUBLIC_KEY_LEN);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p || p->data_size != HAETAE_SECRET_KEY_LEN) return 0;
        memcpy(k->sk, p->data, HAETAE_SECRET_KEY_LEN);
        k->has_private = 1;
    }
    return 1;
}

static const OSSL_PARAM *haetae_types(int selection) {
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return types;
}

const OSSL_DISPATCH haetae_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))haetae_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))haetae_key_free },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))haetae_gen },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))haetae_export },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))haetae_import },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))haetae_types },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))haetae_types },
    { 0, NULL }
};
