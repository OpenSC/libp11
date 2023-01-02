/*
 * Code build on definitions from OpenSSL 3 documentation.
 *
 * Copyright (c) 2022 Zoltan Patocs
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/params.h>

#include "config.h"
#include "libp11.h"
#include "pkcs11.h"
#include "prov_ctx.h"

#include "prov_asym_cipher.h"
#include "prov_cipher.h"
#include "prov_digest.h"
#include "prov_kdf.h"
#include "prov_kem.h"
#include "prov_keyexch.h"
#include "prov_keymgmt.h"
#include "prov_mac.h"
#include "prov_rand.h"
#include "prov_signature.h"
#include "prov_storemgmt.h"

static const char* name = "libp11 PKCS#11 provider";

/* provider entry point (fixed name, exported) */
OSSL_provider_init_fn OSSL_provider_init;

/* functions offered by the provider to libcrypto */
#define PROVIDER_FN(name) static OSSL_FUNC_##name##_fn name
PROVIDER_FN(provider_teardown);
PROVIDER_FN(provider_gettable_params);
PROVIDER_FN(provider_get_params);
PROVIDER_FN(provider_query_operation);
PROVIDER_FN(provider_get_reason_strings);
#undef PROVIDER_FN

static const OSSL_DISPATCH provider_functions[] = {
{OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown},
{OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params},
{OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query_operation},
{OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))provider_get_reason_strings},
{0, NULL}};

/*
 * Provider global initialization mutex and refcount.
 * Used to serialize C_Initialize and C_Finalize calls: The pkcs11 module is
 * initialized when the first provider context is allocated and finalized when
 * the last provider context is freed. For details on pkcs11 multi-threading,
 * see [pkcs11 ug].
 */
struct
{
    pthread_mutex_t mutex;
    unsigned int refcount;
} provider_init = {
PTHREAD_MUTEX_INITIALIZER,
0};

/* ---------------------------------------------------------------------------------------- */

static int _get_all_core_functions(PROVIDER_CTX* ctx, const OSSL_DISPATCH* in)
{
    for (; in->function_id != 0; in++)
    {
        switch (in->function_id)
        {
#define CASE(uname, lname, mandatory)       \
    case OSSL_FUNC_##uname:                 \
        ctx->lname = OSSL_FUNC_##lname(in); \
        if (mandatory && !ctx->lname)       \
            goto err;                       \
        break;
            CASE(CORE_GETTABLE_PARAMS, core_gettable_params, FALSE);
            CASE(CORE_GET_PARAMS, core_get_params, TRUE);
            CASE(CORE_THREAD_START, core_thread_start, FALSE);
            CASE(CORE_GET_LIBCTX, core_get_libctx, TRUE);
            CASE(CORE_NEW_ERROR, core_new_error, FALSE);
            CASE(CORE_SET_ERROR_DEBUG, core_set_error_debug, FALSE);
            CASE(CORE_VSET_ERROR, core_vset_error, FALSE);
            CASE(CORE_SET_ERROR_MARK, core_set_error_mark, FALSE);
            CASE(CORE_CLEAR_LAST_ERROR_MARK, core_clear_last_error_mark, FALSE);
            CASE(CORE_POP_ERROR_TO_MARK, core_pop_error_to_mark, FALSE);
            CASE(CRYPTO_MALLOC, CRYPTO_malloc, FALSE);
            CASE(CRYPTO_ZALLOC, CRYPTO_zalloc, FALSE);
            CASE(CRYPTO_FREE, CRYPTO_free, FALSE);
            CASE(CRYPTO_CLEAR_FREE, CRYPTO_clear_free, FALSE);
            CASE(CRYPTO_REALLOC, CRYPTO_realloc, FALSE);
            CASE(CRYPTO_CLEAR_REALLOC, CRYPTO_clear_realloc, FALSE);
            CASE(CRYPTO_SECURE_MALLOC, CRYPTO_secure_malloc, FALSE);
            CASE(CRYPTO_SECURE_ZALLOC, CRYPTO_secure_zalloc, FALSE);
            CASE(CRYPTO_SECURE_FREE, CRYPTO_secure_free, FALSE);
            CASE(CRYPTO_SECURE_CLEAR_FREE, CRYPTO_secure_clear_free, FALSE);
            CASE(CRYPTO_SECURE_ALLOCATED, CRYPTO_secure_allocated, FALSE);
            CASE(OPENSSL_CLEANSE, OPENSSL_cleanse, FALSE);
            CASE(BIO_NEW_FILE, BIO_new_file, FALSE);
            CASE(BIO_NEW_MEMBUF, BIO_new_membuf, FALSE);
            CASE(BIO_READ_EX, BIO_read_ex, FALSE);
            CASE(BIO_FREE, BIO_free, FALSE);
            CASE(BIO_VPRINTF, BIO_vprintf, FALSE);
            CASE(SELF_TEST_CB, self_test_cb, FALSE);
#undef CASE
            default:
                break;
        }
    }

    return 1;

err:
    return 0;
}

static int _get_all_core_parameters(PROVIDER_CTX* ctx, const OSSL_DISPATCH* in)
{
    const OSSL_CORE_HANDLE* handle = ctx->handle;
    int rv;

    OSSL_PARAM core_params[] = {
    /* core default params */
    {OSSL_PROV_PARAM_CORE_VERSION, OSSL_PARAM_UTF8_PTR, &ctx->openssl_version, 0, 0},
    {OSSL_PROV_PARAM_CORE_PROV_NAME, OSSL_PARAM_UTF8_PTR, &ctx->provider_name, 0, 0},
    {OSSL_PROV_PARAM_CORE_MODULE_FILENAME, OSSL_PARAM_UTF8_PTR, &ctx->module_filename, 0, 0},
    /* provider specific params */
    {"module", OSSL_PARAM_UTF8_PTR, &ctx->module, 0, 0},                               /* provider library to load by openssl */
    {"pkcs11module", OSSL_PARAM_UTF8_PTR, &ctx->pkcs11module, 0, 0},                   /* PKCS#11 library */
    {"verbose", OSSL_PARAM_UTF8_PTR, &ctx->p_verbose, 0, 0},                           /* log level 0-9 (0 - off, 9 - all) */
    {"force_login", OSSL_PARAM_UTF8_PTR, &ctx->p_force_login, 0, 0},                   /* 1 - instructs p11 to login into the token anyway */
    {"reseed_interval", OSSL_PARAM_UTF8_PTR, &ctx->p_reseed_interval, 0, 0},           /* see prov_rand.h */
    {"reseed_time_interval", OSSL_PARAM_UTF8_PTR, &ctx->p_reseed_time_interval, 0, 0}, /* see prov_rand.h */
    {"max_random_length", OSSL_PARAM_UTF8_PTR, &ctx->p_max_random_length, 0, 0},       /* see prov_rand.h */
    {"min_entropy", OSSL_PARAM_UTF8_PTR, &ctx->p_min_entropy, 0, 0},                   /* see prov_rand.h */
    {"max_entropy", OSSL_PARAM_UTF8_PTR, &ctx->p_max_entropy, 0, 0},                   /* see prov_rand.h */
    {"asym_cipher_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_asym_cipher_disabled, 0, 0}, /* 1 - turns off asym_cipher in this provider (NO EFFECT currently) */
    {"cipher_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_cipher_disabled, 0, 0},           /* 1 - turns off cipher in this provider */
    {"digest_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_digest_disabled, 0, 0},           /* 1 - turns off digest in this provider */
    {"kdf_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_kdf_disabled, 0, 0},                 /* 1 - turns off kdf in this provider (NO EFFECT currently) */
    {"kem_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_kem_disabled, 0, 0},                 /* 1 - turns off kem in this provider (NO EFFECT currently) */
    {"keyexch_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_keyexch_disabled, 0, 0},         /* 1 - turns off keyexch in this provider (NO EFFECT currently) */
    {"keymgmt_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_keymgmt_disabled, 0, 0},         /* 1 - turns off keymgmt in this provider */
    {"mac_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_mac_disabled, 0, 0},                 /* 1 - turns off mac in this provider (NO EFFECT currently) */
    {"rand_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_rand_disabled, 0, 0},               /* 1 - turns off rand in this provider */
    {"signature_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_signature_disabled, 0, 0},     /* 1 - turns off signature in this provider (NO EFFECT currently) */
    {"storemgmt_disabled", OSSL_PARAM_UTF8_PTR, &ctx->p_storemgmt_disabled, 0, 0},     /* 1 - turns off storemgmt in this provider */
    {NULL, 0, NULL, 0, 0}};

    /* core_get_params() reads only OSSL_PARAM_UTF8_PTR */
    rv = ctx->core_get_params(handle, core_params);

    if (ctx->provider_name)
    {
        char* buffer = calloc(1, strlen(name) + strlen(ctx->provider_name) + 4);
        if (buffer)
        {
            sprintf(buffer, "%s (%s)", name, ctx->provider_name);
            ctx->provider_name = buffer;
        }
    }

    if (!ctx->provider_name)
    {
        ctx->provider_name = name;
    }

    return rv;
}

#define READENV(env, var)              \
    str = getenv("PKCS11" env);        \
    if (str != NULL && str[0] != '\0') \
        ctx->p_##var = str;

static int _get_all_environment_parameters(PROVIDER_CTX* ctx)
{
    char* str;

    str = getenv("PKCS11MODULE");
    if (str != NULL && str[0] != '\0')
        ctx->pkcs11module = str;

    READENV("VERBOSE", verbose)
    READENV("FORCELOGIN", force_login)
    READENV("RESEED_INTERVAL", reseed_interval)
    READENV("RESEED_TIME_INTERVAL", reseed_time_interval)

    return 1;
}

#undef READENV

#define READBOOL(arg)                                                                                       \
    if (ctx->p_##arg && *ctx->p_##arg != '\0')                                                              \
    {                                                                                                       \
        if (*ctx->p_##arg >= '0' && *ctx->p_##arg <= '9')                                                   \
        {                                                                                                   \
            ctx->b_##arg = (atoi(ctx->p_##arg) != 0);                                                       \
        }                                                                                                   \
        else                                                                                                \
        {                                                                                                   \
            ctx->b_##arg = (strcasecmp("true", ctx->p_##arg) == 0 || strcasecmp("yes", ctx->p_##arg) == 0); \
        }                                                                                                   \
    }

#define READINT(arg)                           \
    if (ctx->p_##arg && *ctx->p_##arg != '\0') \
        ctx->i_##arg = atoi(ctx->p_##arg);

static int _process_parameters(PROVIDER_CTX* ctx)
{
    READINT(verbose)
    READINT(reseed_interval)
    READINT(reseed_time_interval)
    READINT(max_random_length)
    READINT(min_entropy)
    READINT(max_entropy)

    READBOOL(force_login)
    READBOOL(asym_cipher_disabled)
    READBOOL(cipher_disabled)
    READBOOL(digest_disabled)
    READBOOL(kdf_disabled)
    READBOOL(kem_disabled)
    READBOOL(keyexch_disabled)
    READBOOL(keymgmt_disabled)
    READBOOL(mac_disabled)
    READBOOL(rand_disabled)
    READBOOL(signature_disabled)
    READBOOL(storemgmt_disabled)

    return 1;
}

#undef READINT
#undef READBOOL

static int _initialize_libp11(PROVIDER_CTX* ctx)
{
    PKCS11_CTX* pkcs11_ctx = PKCS11_CTX_new();
    PKCS11_SLOT* slot_list;
    unsigned int slot_count;

    if (!pkcs11_ctx)
    {
        return 0;
    }

    PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);

    if (PKCS11_CTX_load(pkcs11_ctx, ctx->pkcs11module))
    {
        goto err;
    }

    if (PKCS11_enumerate_slots(pkcs11_ctx, &slot_list, &slot_count) || slot_count == 0 || !slot_list)
    {
        PKCS11_CTX_unload(pkcs11_ctx);
        goto err;
    }

    ctx->pkcs11_ctx = pkcs11_ctx;
    ctx->slot_list = slot_list;
    ctx->slot_count = slot_count;

    return 1;

err:
    PKCS11_CTX_free(pkcs11_ctx);

    return 0;
}

static int _list_mechanisms(PROVIDER_CTX* ctx)
{
    PKCS11_MECHANISM* mechanism_list;
    unsigned long mechanism_count;

    if (!ctx->slot)
    {
        ctx->slot = PKCS11_find_token(ctx->pkcs11_ctx, ctx->slot_list, ctx->slot_count);
        if (ctx->slot == NULL || ctx->slot->token == NULL)
        {
            goto err;
        }
    }

    if (PKCS11_enumerate_slot_mechanisms(ctx->pkcs11_ctx, PKCS11_get_slotid_from_slot(ctx->slot), &mechanism_list, &mechanism_count))
    {
        goto err;
    }

    ctx->mechanism_list = mechanism_list;
    ctx->mechanism_count = mechanism_count;

    return 1;

err:

    return 0;
}

static void _close_libp11(PROVIDER_CTX* ctx)
{
    if (ctx->pkcs11_ctx)
    {
        PKCS11_CTX_unload(ctx->pkcs11_ctx);
        PKCS11_CTX_free(ctx->pkcs11_ctx);
        ctx->pkcs11_ctx = NULL;
    }

    if (ctx->slot_list)
    {
        free(ctx->slot_list);
        ctx->slot_count = 0;
        ctx->slot_list = NULL;
    }

    if (ctx->mechanism_list)
    {
        free(ctx->mechanism_list);
        ctx->mechanism_count = 0;
        ctx->mechanism_list = NULL;
    }
}

/* ---------------------------------------------------------------------------------------- */

#define CALL(fun) \
    if (!fun)     \
        goto err;

/*
 * This is the only directly exposed function of the provider.
 * When OpenSSL loads the library, this function gets called.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
                       const OSSL_DISPATCH* in,
                       const OSSL_DISPATCH** out,
                       void** provctx)
{
    PROVIDER_CTX* ctx = NULL;
    int rc;

    assert(handle != NULL);
    assert(in != NULL);
    assert(out != NULL);
    assert(provctx != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        goto err;

    /* Initialize mutex */
    CALL(!pthread_mutex_init(&ctx->lock, 0));

    /* Save core handle. */
    ctx->handle = handle;

    /* Get all core functions and check existence of required ones. */
    CALL(_get_all_core_functions(ctx, in));

    /* Save library context. */
    ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (ctx->libctx == NULL)
        goto err;

    /* Save corectx. */
    // ctx->corectx = ctx->core_get_libctx(handle);

    /* Get all core parameters. */
    CALL(_get_all_core_parameters(ctx, in));

    /* Overwrite parameters from environment */
    CALL(_get_all_environment_parameters(ctx));

    /* Process parameters */
    CALL(_process_parameters(ctx));

    /* Check required parameters */
    if (ctx->pkcs11module == NULL)
        goto err;

    /* Initialize the libp11 and check slots */
    CALL(_initialize_libp11(ctx));

    /* List supported algorithms / mechanisms */
    CALL(_list_mechanisms(ctx));

    /* Init successful */
    *out = provider_functions;
    *provctx = ctx;

    return 1;

err: /* Init failed. */
    provider_teardown(ctx);
    return 0;
}

#undef CALL

/* ---------------------------------------------------------------------------------------- */

/*
 * Cleans of provider related stuff.
 */
static void provider_teardown(void* provctx)
{
    struct provctx* ctx = provctx;

    assert(provctx != NULL);

    /* Close libp11 */
    _close_libp11(ctx);

    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->lock);

    free(ctx);
}

/*
 * provider_gettable_params() should return a constant array of descriptor
 * OSSL_PARAM, for parameters that provider_get_params() can handle.
 */
static const OSSL_PARAM* provider_gettable_params(void* provctx)
{
    static const OSSL_PARAM gettable_params[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END};

    assert(provctx != NULL);

    return gettable_params;
}

/*
 * provider_get_params() should process the OSSL_PARAM array params, setting
 * the values of the parameters it understands.
 */
static int provider_get_params(void* provctx, OSSL_PARAM params[])
{
    struct provctx* ctx = provctx;
    OSSL_PARAM* p;

    assert(provctx != NULL);
    assert(params != NULL);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->provider_name))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, VERSION))
        return 0;

    return 1;
}

/*
 * Returns the defined operations based on the operation_id value. Possible
 * list of operations are defined by OpenSSL3. This library defines only a
 * subset.
 */
static const OSSL_ALGORITHM* provider_query_operation(void* provctx,
                                                      int operation_id,
                                                      int* no_store)
{
    struct provctx* ctx = provctx;

    assert(provctx != NULL);
    assert(no_store != NULL);

    switch (operation_id)
    {
        case OSSL_OP_DIGEST:
            return p11_get_ops_digest(provctx, no_store);
        case OSSL_OP_CIPHER:
            return p11_get_ops_cipher(provctx, no_store);
        case OSSL_OP_MAC:
            return p11_get_ops_mac(provctx, no_store);
        case OSSL_OP_KDF:
            return p11_get_ops_kdf(provctx, no_store);
        case OSSL_OP_KEYMGMT:
            return p11_get_ops_keymgmt(provctx, no_store);
        case OSSL_OP_KEYEXCH:
            return p11_get_ops_keyexch(provctx, no_store);
        case OSSL_OP_SIGNATURE:
            return p11_get_ops_signature(provctx, no_store);
        case OSSL_OP_ASYM_CIPHER:
            return p11_get_ops_asym_cipher(provctx, no_store);
        case OSSL_OP_KEM:
            return p11_get_ops_kem(provctx, no_store);
        case OSSL_OP_STORE:
            return p11_get_ops_storemgmt(provctx, no_store);
        case OSSL_OP_RAND:
            return p11_get_ops_rand(provctx, no_store);
        default:
            break;
    }

    return NULL;
}

/*
 * provider_get_reason_strings() should return a constant OSSL_ITEM array that
 * provides reason strings for reason codes the provider may use when
 * reporting errors using core_put_error().
 */
static const OSSL_ITEM* provider_get_reason_strings(void* provctx)
{
    static const OSSL_ITEM reason_strings[] = {
#define REASON_STRING(ckr) {ckr, #ckr}
    REASON_STRING(CKR_CANCEL),
    REASON_STRING(CKR_HOST_MEMORY),
    REASON_STRING(CKR_SLOT_ID_INVALID),
    REASON_STRING(CKR_GENERAL_ERROR),
    REASON_STRING(CKR_FUNCTION_FAILED),
    REASON_STRING(CKR_ARGUMENTS_BAD),
    REASON_STRING(CKR_NO_EVENT),
    REASON_STRING(CKR_NEED_TO_CREATE_THREADS),
    REASON_STRING(CKR_CANT_LOCK),
    REASON_STRING(CKR_ATTRIBUTE_READ_ONLY),
    REASON_STRING(CKR_ATTRIBUTE_SENSITIVE),
    REASON_STRING(CKR_ATTRIBUTE_TYPE_INVALID),
    REASON_STRING(CKR_ATTRIBUTE_VALUE_INVALID),
    // REASON_STRING(CKR_ACTION_PROHIBITED),
    REASON_STRING(CKR_DATA_INVALID),
    REASON_STRING(CKR_DATA_LEN_RANGE),
    REASON_STRING(CKR_DEVICE_ERROR),
    REASON_STRING(CKR_DEVICE_MEMORY),
    REASON_STRING(CKR_DEVICE_REMOVED),
    REASON_STRING(CKR_ENCRYPTED_DATA_INVALID),
    REASON_STRING(CKR_ENCRYPTED_DATA_LEN_RANGE),
    // REASON_STRING(CKR_AEAD_DECRYPT_FAILED),
    REASON_STRING(CKR_FUNCTION_CANCELED),
    REASON_STRING(CKR_FUNCTION_NOT_PARALLEL),
    REASON_STRING(CKR_FUNCTION_NOT_SUPPORTED),
    REASON_STRING(CKR_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_KEY_SIZE_RANGE),
    REASON_STRING(CKR_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_KEY_NOT_NEEDED),
    REASON_STRING(CKR_KEY_CHANGED),
    REASON_STRING(CKR_KEY_NEEDED),
    REASON_STRING(CKR_KEY_INDIGESTIBLE),
    REASON_STRING(CKR_KEY_FUNCTION_NOT_PERMITTED),
    REASON_STRING(CKR_KEY_NOT_WRAPPABLE),
    REASON_STRING(CKR_KEY_UNEXTRACTABLE),
    REASON_STRING(CKR_MECHANISM_INVALID),
    REASON_STRING(CKR_MECHANISM_PARAM_INVALID),
    REASON_STRING(CKR_OBJECT_HANDLE_INVALID),
    REASON_STRING(CKR_OPERATION_ACTIVE),
    REASON_STRING(CKR_OPERATION_NOT_INITIALIZED),
    REASON_STRING(CKR_PIN_INCORRECT),
    REASON_STRING(CKR_PIN_INVALID),
    REASON_STRING(CKR_PIN_LEN_RANGE),
    REASON_STRING(CKR_PIN_EXPIRED),
    REASON_STRING(CKR_PIN_LOCKED),
    REASON_STRING(CKR_SESSION_CLOSED),
    REASON_STRING(CKR_SESSION_COUNT),
    REASON_STRING(CKR_SESSION_HANDLE_INVALID),
    REASON_STRING(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
    REASON_STRING(CKR_SESSION_READ_ONLY),
    REASON_STRING(CKR_SESSION_EXISTS),
    REASON_STRING(CKR_SESSION_READ_ONLY_EXISTS),
    REASON_STRING(CKR_SESSION_READ_WRITE_SO_EXISTS),
    REASON_STRING(CKR_SIGNATURE_INVALID),
    REASON_STRING(CKR_SIGNATURE_LEN_RANGE),
    REASON_STRING(CKR_TEMPLATE_INCOMPLETE),
    REASON_STRING(CKR_TEMPLATE_INCONSISTENT),
    REASON_STRING(CKR_TOKEN_NOT_PRESENT),
    REASON_STRING(CKR_TOKEN_NOT_RECOGNIZED),
    REASON_STRING(CKR_TOKEN_WRITE_PROTECTED),
    REASON_STRING(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_UNWRAPPING_KEY_SIZE_RANGE),
    REASON_STRING(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_USER_ALREADY_LOGGED_IN),
    REASON_STRING(CKR_USER_NOT_LOGGED_IN),
    REASON_STRING(CKR_USER_PIN_NOT_INITIALIZED),
    REASON_STRING(CKR_USER_TYPE_INVALID),
    REASON_STRING(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
    REASON_STRING(CKR_USER_TOO_MANY_TYPES),
    REASON_STRING(CKR_WRAPPED_KEY_INVALID),
    REASON_STRING(CKR_WRAPPED_KEY_LEN_RANGE),
    REASON_STRING(CKR_WRAPPING_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_WRAPPING_KEY_SIZE_RANGE),
    REASON_STRING(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_RANDOM_SEED_NOT_SUPPORTED),
    REASON_STRING(CKR_RANDOM_NO_RNG),
    REASON_STRING(CKR_DOMAIN_PARAMS_INVALID),
    // REASON_STRING(CKR_CURVE_NOT_SUPPORTED),
    REASON_STRING(CKR_BUFFER_TOO_SMALL),
    REASON_STRING(CKR_SAVED_STATE_INVALID),
    REASON_STRING(CKR_INFORMATION_SENSITIVE),
    REASON_STRING(CKR_STATE_UNSAVEABLE),
    REASON_STRING(CKR_CRYPTOKI_NOT_INITIALIZED),
    REASON_STRING(CKR_CRYPTOKI_ALREADY_INITIALIZED),
    REASON_STRING(CKR_MUTEX_BAD),
    REASON_STRING(CKR_MUTEX_NOT_LOCKED),
    // REASON_STRING(CKR_NEW_PIN_MODE),
    // REASON_STRING(CKR_NEXT_OTP),
    // REASON_STRING(CKR_EXCEEDED_MAX_ITERATIONS),
    // REASON_STRING(CKR_FIPS_SELF_TEST_FAILED),
    // REASON_STRING(CKR_LIBRARY_LOAD_FAILED),
    // REASON_STRING(CKR_PIN_TOO_WEAK),
    // REASON_STRING(CKR_PUBLIC_KEY_INVALID),
    REASON_STRING(CKR_FUNCTION_REJECTED),
#undef REASON_STRING
    {0, NULL}};

    assert(provctx != NULL);

    return reason_strings;
}

/******************************************************************************/

/*
 * Lists mechanisms where the given flag is true. Caller must free the returned data.
 */
int filter_mechanisms(const PROVIDER_CTX* ctx, const CK_FLAGS flag, PKCS11_MECHANISM** mechsp, unsigned long* mech_countp)
{
    PKCS11_MECHANISM* mechs;
    size_t count = 0;
    size_t i;

    for (i = 0; i < ctx->mechanism_count; i++)
    {
        if (ctx->mechanism_list[i].info.flags & flag)
            count++;
    }

    mechs = malloc(count * sizeof(*mechs));
    if (!mechs)
    {
        return 0;
    }

    count = 0;
    for (i = 0; i < ctx->mechanism_count; i++)
    {
        if (ctx->mechanism_list[i].info.flags & flag)
        {
            memcpy(&mechs[count], &ctx->mechanism_list[i], sizeof(*mechs));
            count++;
        }
    }

    *mechsp = mechs;
    *mech_countp = count;

    return 1;
}

/*
 * Looks for a given mechanism by type
 */
int get_mechanism(const PROVIDER_CTX* ctx, const CK_MECHANISM_TYPE type, PKCS11_MECHANISM** mechp)
{
    PKCS11_MECHANISM* mech;
    size_t count = 0;
    size_t i = 0;

    while (i < ctx->mechanism_count && ctx->mechanism_list[i].type != type)
    {
        i++;
    }

    if (i == ctx->mechanism_count)
    {
        /* Not found */
        return 0;
    }

    mech = malloc(sizeof(*mech));
    if (!mech)
    {
        return 0;
    }

    memcpy(mech, &ctx->mechanism_list[i], sizeof(*mech));

    *mechp = mech;

    return 1;
}
