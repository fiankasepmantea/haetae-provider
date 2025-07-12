#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

// Declare dispatch tables from other source files
extern const OSSL_DISPATCH haetae_keymgmt_functions[];
extern const OSSL_DISPATCH haetae_signature_functions[];

// Define algorithm lists
static const OSSL_ALGORITHM haetae_keymgmt_algorithms[] = {
    { "HAETAE", "provider=haetae", haetae_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM haetae_signature_algorithms[] = {
    { "HAETAE", "provider=haetae", haetae_signature_functions },
    { NULL, NULL, NULL }
};

// Optional provider info
static const OSSL_PARAM *haetae_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int haetae_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "HAETAE Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;

    return 1;
}

// Dispatch query
static int haetae_query(void *provctx, int operation_id,
                        const OSSL_ALGORITHM **algorithms,
                        const OSSL_DISPATCH **functions)
{
    switch (operation_id) {
        case OSSL_OP_KEYMGMT:
            *algorithms = haetae_keymgmt_algorithms;
            *functions = haetae_keymgmt_functions;
            return 1;

        case OSSL_OP_SIGNATURE:
            *algorithms = haetae_signature_algorithms;
            *functions = haetae_signature_functions;
            return 1;

        default:
            *algorithms = NULL;
            *functions = NULL;
            return 0;
    }
}

// Top-level provider dispatch table
static const OSSL_DISPATCH haetae_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))haetae_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))haetae_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))haetae_get_params },
    { 0, NULL }
};

// Provider entry point
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    *provctx = NULL;  // if you don't use provider context

    *out = haetae_dispatch_table;

    return 1;  // success
}


