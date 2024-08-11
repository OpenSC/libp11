#include <stdlib.h>

#include "pkcs11.h"
#include "prov_ctx.h"
#include "prov_kdf.h"

#include "libp11-int.h"
#include "libp11.h"

#define PROV_NAMES_HKDF "HKDF"
#define PROV_NAMES_TLS1_3_KDF "TLS13-KDF"
#define PROV_NAMES_SSKDF "SSKDF"
#define PROV_NAMES_PBKDF1 "PBKDF1"
#define PROV_NAMES_PBKDF2 "PBKDF2:1.2.840.113549.1.5.12"
#define PROV_NAMES_PVKKDF "PVKKDF"
#define PROV_NAMES_SSHKDF "SSHKDF"
#define PROV_NAMES_X963KDF "X963KDF:X942KDF-CONCAT"
#define PROV_NAMES_X942KDF_ASN1 "X942KDF-ASN1:X942KDF"
#define PROV_NAMES_TLS1_PRF "TLS1-PRF"
#define PROV_NAMES_KBKDF "KBKDF"
#define PROV_NAMES_PKCS12KDF "PKCS12KDF"
#define PROV_NAMES_SCRYPT "SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11"
#define PROV_NAMES_KRB5KDF "KRB5KDF"

extern int filter_mechanisms(PROVIDER_CTX* ctx, CK_FLAGS flag, PKCS11_MECHANISM** mechsp, unsigned long* mech_countp);
extern int get_mechanism(const PROVIDER_CTX* ctx, const CK_MECHANISM_TYPE type, PKCS11_MECHANISM** mechp);

// -------------------------------------------------------------------------------------------------

// static OSSL_FUNC_kdf_newctx_fn p11_kdf_newctx;
static void* p11_kdf_newctx(void* provctx, CK_MECHANISM_TYPE type);
static OSSL_FUNC_kdf_freectx_fn p11_kdf_freectx;
// static OSSL_FUNC_kdf_dupctx_fn p11_kdf_dupctx;

static OSSL_FUNC_kdf_reset_fn p11_kdf_reset;
static OSSL_FUNC_kdf_derive_fn p11_kdf_derive;

static OSSL_FUNC_kdf_get_params_fn p11_kdf_get_params;
static OSSL_FUNC_kdf_gettable_params_fn p11_kdf_gettable_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn p11_kdf_gettable_ctx_params;
static int p11_kdf_get_ctx_params(void* kctx, OSSL_PARAM params[], CK_MECHANISM_TYPE type);
// static OSSL_FUNC_kdf_get_ctx_params_fn p11_kdf_get_ctx_params;
// static OSSL_FUNC_kdf_settable_ctx_params_fn p11_kdf_settable_ctx_params;
static const OSSL_PARAM* p11_kdf_settable_ctx_params(void* kctx, void* provctx, CK_MECHANISM_TYPE type);
static OSSL_FUNC_kdf_set_ctx_params_fn p11_kdf_set_ctx_params;

// -------------------------------------------------------------------------------------------------

#define KDF_FUN(alg)                                       \
    static OSSL_FUNC_kdf_newctx_fn p11_kdf_##alg##_newctx; \
    static OSSL_FUNC_kdf_set_ctx_params_fn p11_kdf_set_ctx_params;

#define KDF_TBL(alg)                                                                          \
    const OSSL_DISPATCH p11_kdf_##alg##_tbl[] = {                                             \
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))p11_kdf_##alg##_newctx},                           \
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))p11_kdf_freectx},                                 \
    {OSSL_FUNC_KDF_RESET, (void (*)(void))p11_kdf_reset},                                     \
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))p11_kdf_derive},                                   \
    {OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void))p11_kdf_gettable_params},                 \
    {OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))p11_kdf_get_params},                           \
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))p11_kdf_gettable_ctx_params},         \
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))p11_kdf_##alg##_get_ctx_params},           \
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))p11_kdf_##alg##_settable_ctx_params}, \
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))p11_kdf_set_ctx_params},                   \
    {0, NULL}};

#define KDF_FUN_DEF(ckm, alg)                                                               \
    static void* p11_kdf_##alg##_newctx(void* provctx)                                      \
    {                                                                                       \
        return p11_kdf_newctx(provctx, ckm);                                                \
    }                                                                                       \
                                                                                            \
    static int p11_kdf_##alg##_get_ctx_params(void* kctx, OSSL_PARAM params[])              \
    {                                                                                       \
        return p11_kdf_get_ctx_params(kctx, params, ckm);                                   \
    }                                                                                       \
    static const OSSL_PARAM* p11_kdf_##alg##_settable_ctx_params(void* kctx, void* provctx) \
    {                                                                                       \
        return p11_kdf_settable_ctx_params(kctx, provctx, ckm);                             \
    }

#define DECLARE_ALG(p11alg, alg)   \
    KDF_FUN(alg)                   \
    KDF_FUN_DEF(CKM_##p11alg, alg) \
    KDF_TBL(alg)

struct p11_algorithm_map_t
{
    CK_MECHANISM_TYPE type;
    OSSL_ALGORITHM algorithm;
};

typedef struct p11_algorithm_map_t P11_ALGORITHM_MAP;

#define ALG_MAP(p11alg, alg)                                                                        \
    {                                                                                               \
        CKM_##p11alg, { PROV_NAMES_##alg, "provider=pkcs11,pkcs11.kdf", p11_kdf_##alg##_tbl, NULL } \
    }

// DECLARE_ALG(PKCS5_PBKD2, PBKDF2)
DECLARE_ALG(GENERIC_SECRET_KEY_GEN, PBKDF2)

static const P11_ALGORITHM_MAP p11_algorithm_map[] = {
// ALG_MAP(PKCS5_PBKD2, PBKDF2)};
ALG_MAP(GENERIC_SECRET_KEY_GEN, PBKDF2)};

#define FREE(x)  \
    if (x)       \
    {            \
        free(x); \
    }

// -------------------------------------------------------------------------------------------------

static PKCS11_KDF_CTX* __new_p11_kdfctx()
{
    return calloc(1, sizeof(PKCS11_KDF_CTX));
}

static void __free_p11_kdfctx(PKCS11_KDF_CTX* ptr)
{
    if (ptr)
    {
        free(ptr);
    }
}

// -------------------------------------------------------------------------------------------------

static int is_allowed(CK_MECHANISM_TYPE type, PKCS11_MECHANISM* mechanisms, unsigned long mechanism_count)
{
    unsigned long i;

    for (i = 0; i < mechanism_count; i++)
    {
        if (type == mechanisms[i].type)
        {
            return 1;
        }
    }

    return 0;
}

const OSSL_ALGORITHM* p11_get_ops_kdf(void* provctx, int* no_store)
{
    PROVIDER_CTX* ctx = provctx;
    OSSL_ALGORITHM* algorithms;
    PKCS11_MECHANISM* mechanisms = NULL;
    unsigned long mechanism_count = 0;
    unsigned long supported_count = 0;
    unsigned long algorithm_count = sizeof(p11_algorithm_map) / sizeof(*p11_algorithm_map);
    size_t i;

    (void)no_store;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    if (ctx->b_kdf_disabled)
    {
        return NULL;
    }

    if (!filter_mechanisms(ctx, CKF_GENERATE, &mechanisms, &mechanism_count) || mechanism_count < 1)
    {
        goto err;
    }

    algorithms = calloc(algorithm_count + 1, sizeof(*algorithms));
    if (!algorithms)
    {
        goto err;
    }

    for (i = 0; i < algorithm_count; i++)
    {
        if (is_allowed(p11_algorithm_map[i].type, mechanisms, mechanism_count))
        {
            memcpy(&algorithms[supported_count], &p11_algorithm_map[i].algorithm, sizeof(*algorithms));
            supported_count++;
        }
    }

    // new size is never bigger, hence assuming the pointer not changes
    algorithms = realloc(algorithms, (supported_count + 1) * sizeof(*algorithms));
    if (!algorithms)
    {
        goto err;
    }

    FREE(mechanisms);

    return algorithms;

err:
    FREE(mechanisms);

    return NULL;
}

// -------------------------------------------------------------------------------------------------

static void* p11_kdf_newctx(void* provctx, CK_MECHANISM_TYPE type)
{
    PKCS11_KDF_CTX* ctx = __new_p11_kdfctx();

    if (!ctx)
        goto err;

    ctx->provctx = provctx;
    ctx->slot = ctx->provctx->slot;
    ctx->type = type;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (!ctx->slot)
    {
        /* Look for a slot */
        ctx->slot = PKCS11_find_token(ctx->provctx->pkcs11_ctx, ctx->provctx->slot_list, ctx->provctx->slot_count);
        if (ctx->slot == NULL || ctx->slot->token == NULL)
        {
            goto err;
        }
    }

    // /* We need RW session, since openssl pumps the key from outside */
    // if (PKCS11_open_session(ctx->slot, 1))
    // {
    //     printf("Could not open session\n");
    //     goto err;
    // }

    if (pkcs11_get_session(PRIVSLOT(ctx->slot), 0, &ctx->session))
    {
        goto err;
    }

    ctx->mech = calloc(1, sizeof(*ctx->mech));
    if (!ctx->mech)
    {
        goto err;
    }

    ctx->mech->mechanism = ctx->type;

    return ctx;

err:
    if (ctx)
        __free_p11_kdfctx(ctx);

    return NULL;
}

static void p11_kdf_freectx(void* kctx)
{
    PKCS11_KDF_CTX* ctx = kctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    pkcs11_put_session(PRIVSLOT(ctx->slot), ctx->session);

    __free_p11_kdfctx(ctx);
}

// -------------------------------------------------------------------------------------------------

static void p11_kdf_reset(void* kctx)
{
    PKCS11_KDF_CTX* ctx = kctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);
}

#define GET_OCTET(param_id, octet_data, octet_size)                               \
    p = OSSL_PARAM_locate_const(params, param_id);                                \
    if (p != NULL && p->data != NULL && p->data_size != 0)                        \
    {                                                                             \
        OPENSSL_clear_free(octet_data, octet_size);                               \
        octet_data = NULL;                                                         \
        if (!OSSL_PARAM_get_octet_string(p, (void**)&octet_data, 0, &octet_size)) \
        {                                                                         \
            return 0;                                                             \
        }                                                                         \
    }

static int p11_kdf_derive(void* kctx, unsigned char* key, size_t keylen, const OSSL_PARAM params[])
{
    PKCS11_KDF_CTX* ctx = kctx;
    const OSSL_PARAM* p;
    int rc;

    ctx_log(ctx->provctx, 3, "%s: keylen=%lu\n", __FUNCTION__, keylen);

    ctx->keylen = keylen;

    // octet
    GET_OCTET(OSSL_KDF_PARAM_PASSWORD, ctx->pass, ctx->passlen);

    // octet
    GET_OCTET(OSSL_KDF_PARAM_SALT, ctx->salt, ctx->saltlen);

    // int
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->mode))
    {
        return 0;
    }

    // int
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &ctx->iter))
    {
        return 0;
    }

    // utf8 string
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &ctx->mdname))
    {
        return 0;
    }

    ctx_log(ctx->provctx, 3, "%s: passlen=%lu\n", __FUNCTION__, ctx->passlen);
    ctx_log(ctx->provctx, 3, "%s: saltlen=%lu\n", __FUNCTION__, ctx->saltlen);
    ctx_log(ctx->provctx, 3, "%s: secretlen=%lu\n", __FUNCTION__, ctx->secretlen);
    ctx_log(ctx->provctx, 3, "%s: iter=%d\n", __FUNCTION__, ctx->iter);
    ctx_log(ctx->provctx, 3, "%s: digest=%s\n", __FUNCTION__, ctx->mdname);

    // SP800-132 compliance checks
    if (ctx->mode == 0)
    {
        if (ctx->iter < 1000 || ctx->saltlen < 128/8 || keylen < 112/8)
        {
            return 0;
        }
    }

    // PBKDF2;
    CK_PKCS5_PBKD2_PARAMS2 meth_param = {
    .saltSource = CKZ_SALT_SPECIFIED,
    .pSaltSourceData = ctx->salt,
    .ulSaltSourceDataLen = ctx->saltlen,
    .iterations = ctx->iter,
    .prf = CKP_PKCS5_PBKD2_HMAC_SHA256,
    .pPrfData = ctx->secret,
    .ulPrfDataLen = ctx->secretlen,
    .pPassword = ctx->pass,
    .ulPasswordLen = ctx->passlen};

    ctx->mech->pParameter = &meth_param;
    ctx->mech->ulParameterLen = sizeof(meth_param);

    rc = pkcs11_generate_secret_key(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, ctx->mech, CKK_GENERIC_SECRET, ctx->keylen, key);

    ctx->mech->pParameter = NULL;
    ctx->mech->ulParameterLen = 0;

    return !rc;
}

// -------------------------------------------------------------------------------------------------

static const OSSL_PARAM get_params[] = {
OSSL_PARAM_END};

static const OSSL_PARAM get_ctx_params[] = {
OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
OSSL_PARAM_END};

static const OSSL_PARAM set_ctx_params[] = {
OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
OSSL_PARAM_END};

#define GET_PARAM(name, type, value)                   \
    p = OSSL_PARAM_locate(params, name);               \
    if (p != NULL && !OSSL_PARAM_set_##type(p, value)) \
    {                                                  \
        return 0;                                      \
    }

static const OSSL_PARAM* p11_kdf_gettable_params(void* provctx)
{
    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return get_params;
}

static int p11_kdf_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM* p;

    printf("%s\n", __FUNCTION__);

    return 1;
}

static const OSSL_PARAM* p11_kdf_gettable_ctx_params(void* cctx, void* provctx)
{
    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return get_ctx_params;
}

static int p11_kdf_get_ctx_params(void* kctx, OSSL_PARAM params[], CK_MECHANISM_TYPE type)
{
    PKCS11_KDF_CTX* ctx = kctx;
    PKCS11_MECHANISM* mechp = NULL;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    OSSL_PARAM* p;

    if (params == NULL)
    {
        return 1;
    }

    get_mechanism(ctx->provctx, type, &mechp);

    if (!mechp)
    {
        return 0;
    }

    // openssl: If the algorithm produces a variable amount of output, SIZE_MAX should be returned.
    ctx->param_size = (mechp->info.ulMinKeySize == mechp->info.ulMaxKeySize) ? mechp->info.ulMaxKeySize : SIZE_MAX;

    free(mechp);

    GET_PARAM(OSSL_KDF_PARAM_SIZE, size_t, ctx->param_size)

    return 1;
}

static const OSSL_PARAM* p11_kdf_settable_ctx_params(void* kctx, void* provctx, CK_MECHANISM_TYPE type)
{
    PKCS11_KDF_CTX* ctx = kctx;
    (void)type;

    // TODO: type not handled yet

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    return set_ctx_params;
}

static int p11_kdf_set_ctx_params(void* kctx, const OSSL_PARAM params[])
{
    PKCS11_KDF_CTX* ctx = kctx;
    const OSSL_PARAM* p;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (params == NULL)
    {
        return 1;
    }

    GET_OCTET(OSSL_KDF_PARAM_KEY, ctx->key, ctx->keylen)
    GET_OCTET(OSSL_KDF_PARAM_SECRET, ctx->secret, ctx->secretlen)
    GET_OCTET(OSSL_KDF_PARAM_SECRET, ctx->pass, ctx->passlen)

    return 0;
}
