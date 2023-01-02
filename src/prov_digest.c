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
#include "prov_digest.h"

#include "libp11-int.h"
#include "libp11.h"

extern int filter_mechanisms(PROVIDER_CTX* ctx, CK_FLAGS flag, PKCS11_MECHANISM** mechsp, unsigned long* mech_countp);

/******************************************************************************/

static OSSL_FUNC_digest_freectx_fn p11_digest_freectx;
static OSSL_FUNC_digest_dupctx_fn p11_digest_dupctx;
static OSSL_FUNC_digest_init_fn p11_digest_init;
static OSSL_FUNC_digest_update_fn p11_digest_update;
static OSSL_FUNC_digest_final_fn p11_digest_final;
static OSSL_FUNC_digest_gettable_params_fn p11_digest_gettable_params;

/******************************************************************************/

#define DIGEST_FUN(alg)                                          \
    static OSSL_FUNC_digest_newctx_fn p11_digest_##alg##_newctx; \
    static OSSL_FUNC_digest_digest_fn p11_digest_##alg##_digest; \
    static OSSL_FUNC_digest_get_params_fn p11_digest_##alg##_get_params;

#define DIGEST_TBL(alg)                                                             \
    static const OSSL_DISPATCH p11_digest_##alg##_tbl[] = {                         \
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))p11_digest_##alg##_newctx},           \
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))p11_digest_freectx},                 \
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))p11_digest_dupctx},                   \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))p11_digest_init},                       \
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))p11_digest_update},                   \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))p11_digest_final},                     \
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))p11_digest_##alg##_digest},           \
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))p11_digest_gettable_params}, \
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))p11_digest_##alg##_get_params},   \
    {0, NULL}};

#define DECLARE_ALG(alg) \
    DIGEST_FUN(alg)      \
    DIGEST_TBL(alg)

DECLARE_ALG(SHA_1)
DECLARE_ALG(SHA224)
DECLARE_ALG(SHA256)
DECLARE_ALG(SHA384)
DECLARE_ALG(SHA512)
DECLARE_ALG(MD5)

struct p11_algorithm_map_t
{
    CK_MECHANISM_TYPE type;
    OSSL_ALGORITHM algorithm;
};

typedef struct p11_algorithm_map_t P11_ALGORITHM_MAP;

static const P11_ALGORITHM_MAP p11_algorithm_map[] = {
{CKM_SHA_1, {"SHA1:SHA-1:SSL3-SHA1", "provider=pkcs11,pkcs11.digest", p11_digest_SHA_1_tbl, NULL}},
{CKM_SHA224, {"SHA2-224:SHA-224:SHA224", "provider=pkcs11,pkcs11.digest", p11_digest_SHA256_tbl, NULL}},
{CKM_SHA256, {"SHA2-256:SHA-256:SHA256", "provider=pkcs11,pkcs11.digest", p11_digest_SHA256_tbl, NULL}},
{CKM_SHA384, {"SHA2-384:SHA-384:SHA384", "provider=pkcs11,pkcs11.digest", p11_digest_SHA384_tbl, NULL}},
{CKM_SHA512, {"SHA2-512:SHA-512:SHA512", "provider=pkcs11,pkcs11.digest", p11_digest_SHA512_tbl, NULL}},
{CKM_MD5, {"MD5:SSL3-MD5", "provider=pkcs11,pkcs11.digest", p11_digest_MD5_tbl, NULL}},
{0xFFFFFFFF, {NULL, NULL, NULL, NULL}}};

/******************************************************************************/

static P11_DIGEST_CTX* __new_p11_digestctx()
{
    return calloc(1, sizeof(P11_DIGEST_CTX));
}

static void __free_p11_digestctx(P11_DIGEST_CTX* ptr)
{
    if (ptr)
    {
        free(ptr);
    }
}

/******************************************************************************/

static const OSSL_ALGORITHM* find_algorithm(const P11_ALGORITHM_MAP* algorithm_map, const CK_MECHANISM_TYPE type)
{
    size_t i = 0;

    while (algorithm_map[i].type != 0xFFFFFFFF)
    {
        if (algorithm_map[i].type == type)
            return &algorithm_map[i].algorithm;

        i++;
    }

    return NULL;
}

const OSSL_ALGORITHM* p11_get_ops_digest(void* provctx, int* no_store)
{
    PROVIDER_CTX* ctx = provctx;
    OSSL_ALGORITHM* algorithms;
    PKCS11_MECHANISM* mechanisms = NULL;
    unsigned long mechanism_count = 0;
    unsigned long supported_count = 0;
    size_t i;

    (void)no_store;

    ctx_log(ctx, 3, "%s%s\n", __FUNCTION__, ctx->b_digest_disabled ? " disabled" : "");

    if (ctx->b_digest_disabled)
    {
        return NULL;
    }

    if (!filter_mechanisms(ctx, CKF_DIGEST, &mechanisms, &mechanism_count) || mechanism_count < 1)
    {
        goto err;
    }

    algorithms = calloc(mechanism_count + 1, sizeof(*algorithms));
    if (!algorithms)
    {
        goto err;
    }

    for (i = 0; i < mechanism_count; i++)
    {
        const OSSL_ALGORITHM* algorithm = find_algorithm(p11_algorithm_map, mechanisms[i].type);

        if (algorithm)
        {
            memcpy(&algorithms[supported_count], algorithm, sizeof(*algorithm));
            supported_count++;
        }
    }

    return algorithms;

err:
    if (mechanisms)
        free(mechanisms);

    return NULL;
}

/******************************************************************************/

static void* p11_digest_newctx(void* provctx, CK_MECHANISM_TYPE type)
{
    P11_DIGEST_CTX* ctx = __new_p11_digestctx();

    if (!ctx)
        goto err;

    ctx->provctx = provctx;
    ctx->slot = ctx->provctx->slot;
    ctx->type = type;

    ctx_log(ctx->provctx, 3, "%s [%p]\n", __FUNCTION__, ctx);

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

    return ctx;

err:
    if (ctx)
        __free_p11_digestctx(ctx);

    return NULL;
}

static void p11_digest_freectx(void* dctx)
{
    P11_DIGEST_CTX* ctx = dctx;

    ctx_log(ctx->provctx, 3, "%s [%p]\n", __FUNCTION__, ctx);

    if (!ctx->final)
    {
        pkcs11_digest_abort(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session);
    }

    pkcs11_put_session(PRIVSLOT(ctx->slot), ctx->session);

    __free_p11_digestctx(ctx);
}

static void* p11_digest_dupctx(void* dctx)
{
    P11_DIGEST_CTX* ctx = dctx;
    P11_DIGEST_CTX* new_ctx = malloc(sizeof(*new_ctx));

    if (!new_ctx)
    {
        goto err;
    }

    memcpy(new_ctx, ctx, sizeof(*new_ctx));

    if (pkcs11_get_session(PRIVSLOT(ctx->slot), 0, &new_ctx->session))
    {
        goto err;
    }

    if (pkcs11_copy_session_state(PRIVSLOT(ctx->slot), new_ctx->session, ctx->session))
    {
        goto err;
    }

    ctx_log(ctx->provctx, 3, "%s [%p -> %p]\n", __FUNCTION__, ctx, new_ctx);

    return new_ctx;

err:
    if (new_ctx)
    {
        free(new_ctx);
    }

    return NULL;
}

static int p11_digest_init(void* dctx, const OSSL_PARAM params[])
{
    P11_DIGEST_CTX* ctx = dctx;
    int rc = 1;

    ctx_log(ctx->provctx, 3, "%s [%p]\n", __FUNCTION__, ctx);

    if (!ctx->init)
    {
        rc = pkcs11_digest_init(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, ctx->type) ? 0 : 1;
        ctx->init = rc;
        ctx->final = 0;
    }

    return rc;
}

static int p11_digest_update(void* dctx, const unsigned char* in, size_t inl)
{
    P11_DIGEST_CTX* ctx = dctx;

    ctx_log(ctx->provctx, 3, "%s [%p]\n", __FUNCTION__, ctx);

    return pkcs11_digest_update(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, in, inl) ? 0 : 1;
}

static int p11_digest_final(void* dctx, unsigned char* out, size_t* outl, size_t outsz)
{
    P11_DIGEST_CTX* ctx = dctx;
    int rv;
    size_t old_outl = *outl;

    *outl = outsz;

    ctx_log(ctx->provctx, 3, "%s [%p]\n", __FUNCTION__, ctx);
    ctx->final = 1;

    rv = pkcs11_digest_final(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outl) ? 0 : 1;

    if (!rv)
    {
        *outl = old_outl;
    }
    else
    {
        ctx->init = 0;
    }

    return rv;
}

static int p11_digest_digest(void* provctx, const unsigned char* in, size_t inl, unsigned char* out, size_t* outl, size_t outsz, CK_MECHANISM_TYPE type)
{
    P11_DIGEST_CTX* ctx = p11_digest_newctx(provctx, type);
    int rv;
    size_t old_outl = *outl;

    *outl = outsz;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (!ctx)
    {
        return 0;
    }

    rv = pkcs11_digest(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, in, inl, out, outl) ? 0 : 1;

    if (!rv)
    {
        *outl = old_outl;
    }

    p11_digest_freectx(ctx);

    return rv;
}

static int p11_digest_get_params(OSSL_PARAM params[], size_t block, size_t size)
{
    OSSL_PARAM* p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;

    return 1;
}

static const OSSL_PARAM* p11_digest_gettable_params(void* provctx)
{
    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return NULL;
}

#define DEFINE_NEWCTX(alg)                                \
    static void* p11_digest_##alg##_newctx(void* provctx) \
    {                                                     \
        PROVIDER_CTX* ctx = provctx;                      \
        /* ctx_log(ctx, 3, "%s\n", __FUNCTION__);     */  \
        return p11_digest_newctx(provctx, CKM_##alg);     \
    }

#define DEFINE_DIGEST(alg)                                                                                                                   \
    static int p11_digest_##alg##_digest(void* provctx, const unsigned char* in, size_t inl, unsigned char* out, size_t* outl, size_t outsz) \
    {                                                                                                                                        \
        PROVIDER_CTX* ctx = provctx;                                                                                                         \
        /* ctx_log(ctx, 3, "%s\n", __FUNCTION__); */                                                                                         \
        return p11_digest_digest(provctx, in, inl, out, outl, outsz, CKM_##alg);                                                             \
    }

#define DEFINE_GET_PARAMS(alg, block, size)                       \
    static int p11_digest_##alg##_get_params(OSSL_PARAM params[]) \
    {                                                             \
        return p11_digest_get_params(params, block, size);        \
    }

#define DEFINE_ALG(alg, block, size) \
    DEFINE_NEWCTX(alg)               \
    DEFINE_DIGEST(alg)               \
    DEFINE_GET_PARAMS(alg, block, size)

DEFINE_ALG(SHA_1, 512 / 8, 160 / 8);
DEFINE_ALG(SHA224, 512 / 8, 224 / 8);
DEFINE_ALG(SHA256, 512 / 8, 256 / 8);
DEFINE_ALG(SHA384, 1024 / 8, 384 / 8);
DEFINE_ALG(SHA512, 1024 / 8, 512 / 8);
DEFINE_ALG(MD5, 512 / 8, 128 / 8);
