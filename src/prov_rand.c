/*
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

#include <stdio.h>
#include <stdlib.h>

#include <openssl/core_dispatch.h>

#include "pkcs11.h"
#include "prov_ctx.h"
#include "prov_rand.h"

#include "libp11-int.h"
#include "libp11.h"

extern int filter_mechanisms(PROVIDER_CTX* ctx, CK_FLAGS flag, PKCS11_MECHANISM** mechsp, unsigned long* mech_countp);

/******************************************************************************/

/* https://www.openssl.org/docs/man3.0/man7/provider-rand.html */
static OSSL_FUNC_rand_newctx_fn p11_rand_newctx;
static OSSL_FUNC_rand_freectx_fn p11_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn p11_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn p11_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn p11_rand_generate;
static OSSL_FUNC_rand_reseed_fn p11_rand_reseed;
static OSSL_FUNC_rand_enable_locking_fn p11_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn p11_rand_lock;
static OSSL_FUNC_rand_unlock_fn p11_rand_unlock;
static OSSL_FUNC_rand_gettable_params_fn p11_rand_gettable_params;
static OSSL_FUNC_rand_gettable_ctx_params_fn p11_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn p11_rand_get_ctx_params;

/******************************************************************************/

static const OSSL_DISPATCH p11_rand_tbl[] = {
{OSSL_FUNC_RAND_NEWCTX, (void (*)(void))p11_rand_newctx},
{OSSL_FUNC_RAND_FREECTX, (void (*)(void))p11_rand_freectx},
{OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))p11_rand_instantiate},
{OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))p11_rand_uninstantiate},
{OSSL_FUNC_RAND_GENERATE, (void (*)(void))p11_rand_generate},
{OSSL_FUNC_RAND_RESEED, (void (*)(void))p11_rand_reseed},
{OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))p11_rand_enable_locking},
{OSSL_FUNC_RAND_LOCK, (void (*)(void))p11_rand_lock},
{OSSL_FUNC_RAND_UNLOCK, (void (*)(void))p11_rand_unlock},
{OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void))p11_rand_gettable_params},
{OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))p11_rand_gettable_ctx_params},
{OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))p11_rand_get_ctx_params},
{0, NULL}};

static const OSSL_ALGORITHM p11_dispatch_rand[] = {
{"CTR-DRBG", "provider=pkcs11", p11_rand_tbl, "PKCS#11 random"},
{NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM* p11_get_ops_rand(void* provctx, int* no_store)
{
    (void)no_store;

    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return !ctx->b_rand_disabled ? p11_dispatch_rand : NULL;
}

/******************************************************************************/

static P11_RAND_CTX* __new_p11_randctx()
{
    return calloc(1, sizeof(P11_RAND_CTX));
}

static void __free_p11_randctx(P11_RAND_CTX* ptr)
{
    if (ptr)
    {
        free(ptr);
    }
}

/******************************************************************************/

static const OSSL_DISPATCH* find_call(const OSSL_DISPATCH* dispatch,
                                      int function)
{
    if (dispatch != NULL)
        while (dispatch->function_id != 0)
        {
            if (dispatch->function_id == function)
                return dispatch;
            dispatch++;
        }
    return NULL;
}

static void* p11_rand_newctx(void* provctx, void* parent, const OSSL_DISPATCH* parent_calls)
{
    (void)parent;
    (void)parent_calls;

    P11_RAND_CTX* ctx = __new_p11_randctx();

    if (!ctx)
        goto err;

    ctx->provctx = provctx;
    ctx->parent = parent;
    ctx->parent_calls = parent_calls;

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

    if (pkcs11_get_session(PRIVSLOT(ctx->slot), 0, &ctx->session))
    {
        goto err;
    }

    if (ctx->parent != NULL && ctx->parent_calls != NULL)
    {
        /* Use parent for seeding */
        const OSSL_DISPATCH* pfunc_dispatch_get_seed = find_call(parent_calls, OSSL_FUNC_RAND_GET_SEED);
        const OSSL_DISPATCH* pfunc_dispatch_clear_seed = find_call(parent_calls, OSSL_FUNC_RAND_CLEAR_SEED);

        ctx->parent_get_seed = (pfunc_dispatch_get_seed) ? OSSL_FUNC_rand_get_seed(pfunc_dispatch_get_seed) : NULL;
        ctx->parent_clear_seed = (pfunc_dispatch_clear_seed) ? OSSL_FUNC_rand_clear_seed(pfunc_dispatch_clear_seed) : NULL;
    }

    /* copy configuration parameters and set default values where needed */
    ctx->max_random_length = ctx->provctx->i_max_random_length ? ctx->provctx->i_max_random_length : 256;
    ctx->reseed_interval = ctx->provctx->i_reseed_interval;
    ctx->reseed_time_interval = ctx->provctx->i_reseed_time_interval;
    ctx->min_entropy = ctx->provctx->i_min_entropy;
    ctx->max_entropy = ctx->provctx->i_max_entropy;

    return ctx;

err:
    if (ctx)
        __free_p11_randctx(ctx);

    return NULL;
}

static void p11_rand_freectx(void* rctx)
{
    P11_RAND_CTX* ctx = rctx;
    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    pkcs11_put_session(PRIVSLOT(ctx->slot), ctx->session);

    __free_p11_randctx(rctx);
}

static int p11_rand_instantiate(void* rctx, unsigned int strength,
                                int prediction_resistance,
                                const unsigned char* pstr, size_t pstr_len,
                                const OSSL_PARAM params[])
{
    P11_RAND_CTX* ctx = rctx;
    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (ctx->parent_get_seed && ctx->parent_clear_seed)
    {
        /* Use parent for seeding */
        unsigned char* buffer;

        size_t bytes = ctx->parent_get_seed(ctx->parent, &buffer, 0, 8, 16, prediction_resistance, (unsigned char*)&rctx, sizeof(rctx));

        if (bytes > 0)
        {
            p11_rand_reseed(ctx, prediction_resistance, buffer, bytes, (unsigned char*)&rctx, sizeof(rctx));

            ctx->parent_clear_seed(ctx->parent, buffer, bytes);
        }
    }

    return 1;
}

static int p11_rand_uninstantiate(void* rctx)
{
    P11_RAND_CTX* ctx = rctx;
    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    return 1;
}

int p11_rand_generate(void* rctx, unsigned char* out, size_t outlen,
                      unsigned int strength, int prediction_resistance,
                      const unsigned char* addin, size_t addin_len)
{
    P11_RAND_CTX* ctx = rctx;
    int reseed_required = 0;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (ctx->reseed_interval > 0)
    {
        if (ctx->generate_counter >= ctx->reseed_interval)
            reseed_required = 1;
    }

    if (ctx->reseed_time_interval > 0)
    {
        time_t now = time(NULL);
        if (now < ctx->reseed_time || now - ctx->reseed_time >= ctx->reseed_time_interval)
            reseed_required = 1;
    }

    if (reseed_required || prediction_resistance)
    {
        unsigned char* buffer = NULL;
        size_t bytes = 0;

        if (ctx->parent_get_seed && ctx->parent_clear_seed)
        {
            /* Use parent for seeding */
            bytes = ctx->parent_get_seed(ctx->parent, &buffer, 0, 8, 16, prediction_resistance, (unsigned char*)&rctx, sizeof(rctx));
            if (!bytes)
            {
                /* parent seed generation error */
                return 0;
            }
        }

        /* seed may be empty */
        if (p11_rand_reseed(ctx, prediction_resistance, buffer, bytes, addin, addin_len))
        {
            /* reseed error */
            return 0;
        }
    }

    if (ctx->reseed_interval > 0)
    {
        ctx->generate_counter++;
    }

    return pkcs11_rand_generate(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outlen, strength, prediction_resistance, addin, addin_len) ? 0 : 1;
}

int p11_rand_reseed(void* rctx, int prediction_resistance,
                    const unsigned char* ent, size_t ent_len,
                    const unsigned char* addin, size_t addin_len)
{
    P11_RAND_CTX* ctx = rctx;
    int res;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    res = pkcs11_rand_seed(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, prediction_resistance, ent, ent_len, addin, addin_len) ? 0 : 1;

    if (ctx->reseed_interval > 0)
    {
        ctx->generate_counter = 0;
    }

    if (ctx->reseed_time_interval > 0)
    {
        ctx->reseed_time = time(NULL);
    }

    ctx->reseed_counter++;

    return res;
}

static int p11_rand_enable_locking(void* rctx)
{
    P11_RAND_CTX* ctx = rctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    ctx->lock = CRYPTO_THREAD_lock_new();
    return 1;
}

static int p11_rand_lock(void* rctx)
{
    P11_RAND_CTX* ctx = rctx;

    if (ctx == NULL || ctx->lock == NULL)
        return 1;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    return CRYPTO_THREAD_write_lock(ctx->lock);
}

static void p11_rand_unlock(void* rctx)
{
    P11_RAND_CTX* ctx = rctx;

    if (ctx == NULL || ctx->lock == NULL)
        return;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    CRYPTO_THREAD_unlock(ctx->lock);
}

static const OSSL_PARAM* p11_rand_gettable_params(void* provctx)
{
    PROVIDER_CTX* pctx = provctx;

    ctx_log(pctx, 3, "%s\n", __FUNCTION__);

    return NULL;
}

static const OSSL_PARAM* p11_rand_gettable_ctx_params(void* rctx, void* provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),          /* Specifies the maximum number of bytes that can be generated in a single call to OSSL_FUNC_rand_generate. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_RESEED_REQUESTS, NULL),      /* Reads or set the number of generate requests before reseeding the associated RAND ctx. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, NULL), /* Reads or set the number of elapsed seconds before reseeding the associated RAND ctx. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, NULL),       /* Specify the minimum number of bytes of random material that can be used to seed the DRBG. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, NULL),       /* Specify the maximum number of bytes of random material that can be used to seed the DRBG. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_RESEED_COUNTER, NULL),       /* Specifies the number of times the DRBG has been seeded or reseeded. */
    OSSL_PARAM_size_t(OSSL_DRBG_PARAM_RESEED_TIME, NULL),
    OSSL_PARAM_END};

    PROVIDER_CTX* pctx = provctx;
    ctx_log(pctx, 3, "%s\n", __FUNCTION__);

    return known_gettable_ctx_params;
}

static int p11_rand_get_ctx_params(void* rctx, OSSL_PARAM params[])
{
    OSSL_PARAM* p;

    P11_RAND_CTX* ctx = rctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->max_random_length))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->reseed_time_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->min_entropy))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->max_entropy))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_COUNTER);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->reseed_counter))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->reseed_time))
        return 0;

    return 1;
}
