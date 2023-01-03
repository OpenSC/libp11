#include <openssl/evp.h>
#include <stdlib.h>

#include "prov_cipher.h"
#include "prov_ctx.h"

#include "libp11-int.h"

extern int filter_mechanisms(PROVIDER_CTX* ctx, CK_FLAGS flag, PKCS11_MECHANISM** mechsp, unsigned long* mech_countp);

/******************************************************************************/

static void* p11_cipher_newctx(void* provctx, CK_MECHANISM_TYPE type, CK_KEY_TYPE keyType, size_t block_size, size_t keylen, size_t ivlen, unsigned int mode);
static OSSL_FUNC_cipher_freectx_fn p11_cipher_freectx;
/* static OSSL_FUNC_cipher_dupctx_fn p11_cipher_dupctx; */

static OSSL_FUNC_cipher_decrypt_init_fn p11_cipher_decrypt_init;
static OSSL_FUNC_cipher_encrypt_init_fn p11_cipher_encrypt_init;

static OSSL_FUNC_cipher_update_fn p11_cipher_update;
static OSSL_FUNC_cipher_final_fn p11_cipher_final;

static int p11_cipher_get_params(OSSL_PARAM params[], CK_MECHANISM_TYPE type, size_t block_size, size_t keylen, size_t ivlen, unsigned int mode);
static OSSL_FUNC_cipher_gettable_params_fn p11_cipher_gettable_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn p11_cipher_gettable_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn p11_cipher_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn p11_cipher_settable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn p11_cipher_set_ctx_params;

/******************************************************************************/

#define CIPHER_FUN(alg, op_mode, keylen)                                                \
    static OSSL_FUNC_cipher_newctx_fn p11_cipher_##alg##_##keylen##_##op_mode##_newctx; \
    static OSSL_FUNC_cipher_get_params_fn p11_cipher_##alg##_##keylen##_##op_mode##_get_params;

#define CIPHER_TBL(alg, op_mode, keylen)                                                                 \
    const OSSL_DISPATCH p11_cipher_##alg##_##keylen##_##op_mode##_tbl[] = {                              \
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p11_cipher_##alg##_##keylen##_##op_mode##_newctx},         \
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p11_cipher_freectx},                                      \
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))p11_cipher_encrypt_init},                            \
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))p11_cipher_decrypt_init},                            \
    {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p11_cipher_update},                                        \
    {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p11_cipher_final},                                          \
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))p11_cipher_gettable_params},                      \
    {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p11_cipher_##alg##_##keylen##_##op_mode##_get_params}, \
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))p11_cipher_gettable_ctx_params},              \
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))p11_cipher_get_ctx_params},                        \
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))p11_cipher_settable_ctx_params},              \
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))p11_cipher_set_ctx_params},                        \
    {0, NULL}};

#define CIPHER_FUN_DEF(ckm, alg, op_mode, keylen, block_size, ivlen, mode, ckk)          \
    static void* p11_cipher_##alg##_##keylen##_##op_mode##_newctx(void* provctx)         \
    {                                                                                    \
        PROVIDER_CTX* ctx = provctx;                                                     \
        ctx_log(ctx, 3, "%s\n", __FUNCTION__);                                           \
        return p11_cipher_newctx(provctx, ckm, ckk, keylen, block_size, ivlen, mode);    \
    }                                                                                    \
                                                                                         \
    static int p11_cipher_##alg##_##keylen##_##op_mode##_get_params(OSSL_PARAM params[]) \
    {                                                                                    \
        return p11_cipher_get_params(params, ckm, keylen, block_size, ivlen, mode);      \
    }

#define DECLARE_ALG(p11alg, alg, op_mode, keylen, block_size, ivlen, mode)                                \
    CIPHER_FUN(alg, op_mode, keylen)                                                                      \
    CIPHER_FUN_DEF(CKM_##p11alg##_##op_mode, alg, op_mode, keylen, block_size, ivlen, mode, CKK_##p11alg) \
    CIPHER_TBL(alg, op_mode, keylen)

struct p11_algorithm_map_t
{
    CK_MECHANISM_TYPE type;
    size_t key_bits;
    OSSL_ALGORITHM algorithm;
};

typedef struct p11_algorithm_map_t P11_ALGORITHM_MAP;

#define ALG_MAP(p11alg, alg, op_mode, keylen)                                                                                   \
    {                                                                                                                           \
        CKM_##p11alg##_##op_mode, keylen,                                                                                       \
        {                                                                                                                       \
#alg "-" #keylen "-" #op_mode, "provider=pkcs11,pkcs11.cipher", p11_cipher_##alg##_##keylen##_##op_mode##_tbl, NULL \
        }                                                                                                                       \
    }

DECLARE_ALG(AES, AES, ECB, 128, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(AES, AES, ECB, 192, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(AES, AES, ECB, 256, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(AES, AES, CBC, 128, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(AES, AES, CBC, 192, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(AES, AES, CBC, 256, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(AES, AES, OFB, 128, 128, 0, EVP_CIPH_OFB_MODE)
DECLARE_ALG(AES, AES, OFB, 192, 128, 0, EVP_CIPH_OFB_MODE)
DECLARE_ALG(AES, AES, OFB, 256, 128, 0, EVP_CIPH_OFB_MODE)
DECLARE_ALG(AES, AES, CFB1, 128, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB1, 192, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB1, 256, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB8, 128, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB8, 192, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB8, 256, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB64, 128, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB64, 192, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB64, 256, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB128, 128, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB128, 192, 128, 128, EVP_CIPH_CFB_MODE)
DECLARE_ALG(AES, AES, CFB128, 256, 128, 128, EVP_CIPH_CFB_MODE)
#ifdef ALLOW_DEPRECATED_ALGO_DES
DECLARE_ALG(DES, DES, ECB, 64, 64, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(DES, DES, CBC, 64, 64, 64, EVP_CIPH_CBC_MODE)
DECLARE_ALG(DES3, DES3, ECB, 192, 192, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(DES3, DES3, CBC, 192, 192, 64, EVP_CIPH_CBC_MODE)
#endif
DECLARE_ALG(CAMELLIA, CAMELLIA, ECB, 128, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(CAMELLIA, CAMELLIA, ECB, 192, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(CAMELLIA, CAMELLIA, ECB, 256, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(CAMELLIA, CAMELLIA, CBC, 128, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(CAMELLIA, CAMELLIA, CBC, 192, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(CAMELLIA, CAMELLIA, CBC, 256, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(BLOWFISH, BF, CBC, 32, 64, 64, EVP_CIPH_CBC_MODE)  /* keylen: 0..448 */
DECLARE_ALG(BLOWFISH, BF, CBC, 448, 64, 64, EVP_CIPH_CBC_MODE) /* keylen: 0..448 */
DECLARE_ALG(TWOFISH, TWOFISH, CBC, 128, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(TWOFISH, TWOFISH, CBC, 192, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(TWOFISH, TWOFISH, CBC, 256, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(ARIA, ARIA, ECB, 128, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(ARIA, ARIA, ECB, 192, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(ARIA, ARIA, ECB, 256, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(ARIA, ARIA, CBC, 128, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(ARIA, ARIA, CBC, 192, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(ARIA, ARIA, CBC, 256, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(SEED, SEED, ECB, 128, 128, 0, EVP_CIPH_ECB_MODE)
DECLARE_ALG(SEED, SEED, CBC, 128, 128, 128, EVP_CIPH_CBC_MODE)
DECLARE_ALG(GOST28147, GOST28147, ECB, 256, 64, 0, EVP_CIPH_ECB_MODE)

static const P11_ALGORITHM_MAP p11_algorithm_map[] = {
ALG_MAP(AES, AES, ECB, 128),
ALG_MAP(AES, AES, ECB, 192),
ALG_MAP(AES, AES, ECB, 256),
ALG_MAP(AES, AES, CBC, 128),
ALG_MAP(AES, AES, CBC, 192),
ALG_MAP(AES, AES, CBC, 256),
ALG_MAP(AES, AES, OFB, 128),
ALG_MAP(AES, AES, OFB, 192),
ALG_MAP(AES, AES, OFB, 256),
ALG_MAP(AES, AES, CFB1, 128),
ALG_MAP(AES, AES, CFB1, 192),
ALG_MAP(AES, AES, CFB1, 256),
ALG_MAP(AES, AES, CFB8, 128),
ALG_MAP(AES, AES, CFB8, 192),
ALG_MAP(AES, AES, CFB8, 256),
ALG_MAP(AES, AES, CFB64, 128),
ALG_MAP(AES, AES, CFB64, 192),
ALG_MAP(AES, AES, CFB64, 256),
ALG_MAP(AES, AES, CFB128, 128),
ALG_MAP(AES, AES, CFB128, 192),
ALG_MAP(AES, AES, CFB128, 256),
#ifdef ALLOW_DEPRECATED_ALGO_DES
ALG_MAP(DES, DES, ECB, 64),
ALG_MAP(DES, DES, CBC, 64),
ALG_MAP(DES3, DES3, ECB, 192),
ALG_MAP(DES3, DES3, CBC, 192),
#endif
ALG_MAP(CAMELLIA, CAMELLIA, ECB, 128),
ALG_MAP(CAMELLIA, CAMELLIA, ECB, 192),
ALG_MAP(CAMELLIA, CAMELLIA, ECB, 256),
ALG_MAP(CAMELLIA, CAMELLIA, CBC, 128),
ALG_MAP(CAMELLIA, CAMELLIA, CBC, 192),
ALG_MAP(CAMELLIA, CAMELLIA, CBC, 256),
ALG_MAP(BLOWFISH, BF, CBC, 32),
ALG_MAP(BLOWFISH, BF, CBC, 448),
ALG_MAP(TWOFISH, TWOFISH, CBC, 128),
ALG_MAP(TWOFISH, TWOFISH, CBC, 192),
ALG_MAP(TWOFISH, TWOFISH, CBC, 256),
ALG_MAP(ARIA, ARIA, ECB, 128),
ALG_MAP(ARIA, ARIA, ECB, 192),
ALG_MAP(ARIA, ARIA, ECB, 256),
ALG_MAP(ARIA, ARIA, CBC, 128),
ALG_MAP(ARIA, ARIA, CBC, 192),
ALG_MAP(ARIA, ARIA, CBC, 256),
ALG_MAP(SEED, SEED, ECB, 128),
ALG_MAP(SEED, SEED, CBC, 128),
ALG_MAP(GOST28147, GOST28147, ECB, 256)};

#define FREE(x)  \
    if (x)       \
    {            \
        free(x); \
    }

/******************************************************************************/

static P11_CIPHER_CTX* __new_p11_cipherctx()
{
    return calloc(1, sizeof(P11_CIPHER_CTX));
}

static void __free_p11_cipherctx(P11_CIPHER_CTX* ptr)
{
    if (ptr)
    {
        FREE(ptr->key_object)
        FREE(ptr->mech)
        FREE(ptr->buffer)

        free(ptr);
    }
}

/******************************************************************************/

static int is_allowed(CK_MECHANISM_TYPE type, unsigned long key_bytes, PKCS11_MECHANISM* mechanisms, unsigned long mechanism_count)
{
    unsigned long i;

    for (i = 0; i < mechanism_count; i++)
    {
        if (type == mechanisms[i].type && key_bytes >= mechanisms[i].info.ulMinKeySize && key_bytes <= mechanisms[i].info.ulMaxKeySize)
        {
            return 1;
        }
    }

    return 0;
}

const OSSL_ALGORITHM* p11_get_ops_cipher(void* provctx, int* no_store)
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

    if (ctx->b_cipher_disabled)
    {
        return NULL;
    }

    /* Assuming that encrypt and decrypt is always together */
    if (!filter_mechanisms(ctx, CKF_ENCRYPT, &mechanisms, &mechanism_count) || mechanism_count < 1)
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
        if (is_allowed(p11_algorithm_map[i].type, p11_algorithm_map[i].key_bits / 8, mechanisms, mechanism_count))
        {
            memcpy(&algorithms[supported_count], &p11_algorithm_map[i].algorithm, sizeof(*algorithms));
            supported_count++;
        }
    }

    /* new size is never bigger, hence assuming the pointer not changes */
    if (!realloc(algorithms, (supported_count + 1) * sizeof(*algorithms)))
    {
        goto err;
    }

    FREE(mechanisms);

    return algorithms;

err:
    FREE(mechanisms);

    return NULL;
}

/******************************************************************************/

static void* p11_cipher_newctx(void* provctx, CK_MECHANISM_TYPE type, CK_KEY_TYPE key_type, size_t keylen, size_t block_size, size_t ivlen, unsigned int mode)
{
    P11_CIPHER_CTX* ctx = __new_p11_cipherctx();

    if (!ctx)
        goto err;

    ctx->provctx = provctx;
    ctx->slot = ctx->provctx->slot;
    ctx->type = type;
    ctx->key_type = key_type;
    ctx->keylen = keylen / 8;
    ctx->block_size = block_size / 8;
    ctx->ivlen = ivlen / 8;
    ctx->mode = mode;
    ctx->padding = 1;
    ctx->in_counter = 0;
    ctx->out_counter = 0;
    ctx->buffer = malloc(ctx->block_size);
    ctx->buflen = 0;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (!ctx->buffer)
    {
        goto err;
    }

    if (!ctx->slot)
    {
        /* Look for a slot */
        ctx->slot = PKCS11_find_token(ctx->provctx->pkcs11_ctx, ctx->provctx->slot_list, ctx->provctx->slot_count);
        if (ctx->slot == NULL || ctx->slot->token == NULL)
        {
            goto err;
        }
    }

    /* We need RW session, since openssl pumps the key from outside */
    if (PKCS11_open_session(ctx->slot, 1))
    {
        printf("Could not open session\n");
        goto err;
    }

    if (pkcs11_get_session(PRIVSLOT(ctx->slot), 1, &ctx->session))
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
        __free_p11_cipherctx(ctx);

    return NULL;
}

static void p11_cipher_freectx(void* cctx)
{
    P11_CIPHER_CTX* ctx = cctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (ctx->key_object)
    {
        pkcs11_destroy_cipher_key_object(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, &ctx->key_object);
    }

    pkcs11_put_session(PRIVSLOT(ctx->slot), ctx->session);

    __free_p11_cipherctx(ctx);
}

/* currently not used -- how to dup() if get_settion() fails? */
/*
static void* p11_cipher_dupctx(void* cctx)
{
    P11_CIPHER_CTX* ctx = cctx;
    P11_CIPHER_CTX* new_ctx = malloc(sizeof(*new_ctx));

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
*/

/******************************************************************************/

static int p11_cipher_encrypt_init(void* cctx, const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[])
{
    (void)params;
    int rv;
    P11_CIPHER_CTX* ctx = cctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    ctx->decrypt = 0;

    if (!key)
    {
        ctx_log(ctx->provctx, 3, "%s: key == NULL\n", __FUNCTION__);
        return 1;
    }

    if (iv)
    {
        /* the iv as mech parameter */
        ctx->mech->pParameter = (unsigned char*)iv;
        ctx->mech->ulParameterLen = ivlen;
    }

    rv = pkcs11_create_cipher_key_object(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, &ctx->key_object, ctx->key_type, key, keylen);
    if (rv != CKR_OK)
    {
        return 0;
    }

    rv = pkcs11_encrypt_init(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, ctx->mech, ctx->key_object, iv, ivlen);
    if (rv != CKR_OK)
    {
        goto err;
    }

    return 1;

err:
    pkcs11_destroy_cipher_key_object(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, &ctx->key_object);

    return 0;
}

static int p11_cipher_decrypt_init(void* cctx, const unsigned char* key, size_t keylen, const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[])
{
    (void)params;
    int rv;
    P11_CIPHER_CTX* ctx = cctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    ctx->decrypt = 1;
    ctx->buflen = 0;

    if (!key)
    {
        ctx_log(ctx->provctx, 3, "%s: key == NULL\n", __FUNCTION__);
        return 1;
    }

    if (iv)
    {
        /* the iv as mech parameter */
        ctx->mech->pParameter = (unsigned char*)iv;
        ctx->mech->ulParameterLen = ivlen;
    }

    rv = pkcs11_create_cipher_key_object(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, &ctx->key_object, ctx->key_type, key, keylen);
    if (rv != CKR_OK)
    {
        return 0;
    }

    rv = pkcs11_decrypt_init(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, ctx->mech, ctx->key_object, iv, ivlen);
    if (rv != CKR_OK)
    {
        goto err;
    }

    return 1;

err:
    pkcs11_destroy_cipher_key_object(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, &ctx->key_object);

    return 0;
}

static int p11_cipher_update(void* cctx, unsigned char* out, size_t* outl, size_t outsize, const unsigned char* in, size_t inl)
{
    P11_CIPHER_CTX* ctx = cctx;
    int rv;
    size_t written = 0;

    *outl = outsize;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (ctx->decrypt)
    {
        /* seemingly openssl reserves one block more for output, hence the below algorithm could work */
        if (ctx->padding)
        {
            if (ctx->buflen > 0)
            {
                /* buffer already contains the pad as that was used for compare */
                memcpy(out, ctx->buffer, ctx->buflen);
                out += ctx->buflen;
                outsize -= ctx->buflen;
                written = ctx->buflen;

                ctx->buflen = 0;
                *outl = outsize;
            }
        }

        rv = pkcs11_decrypt_update(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outl, (unsigned char*)in, inl);

        if (ctx->padding)
        {
            *outl += written;

            ctx->buflen = 0;

            if (*outl > 0 && out[*outl - 1] <= ctx->block_size)
            {
                /* potentially ends with padding */
                size_t padlen = out[*outl - 1];
                memset(ctx->buffer, padlen, padlen);

                if (!memcmp(out + *outl - padlen, ctx->buffer, padlen))
                {
                    /* looks like a padding */
                    ctx->buflen = padlen;
                    *outl -= padlen;
                }
            }
        }
    }
    else
    {
        rv = pkcs11_encrypt_update(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outl, (unsigned char*)in, inl);
    }

    if (rv)
    {
        goto err;
    }

    ctx->out_counter += *outl;
    ctx->in_counter += inl;

    return 1;

err:
    *outl = 0;
    return 0;
}

static int p11_cipher_final(void* cctx, unsigned char* out, size_t* outl, size_t outsize)
{
    P11_CIPHER_CTX* ctx = cctx;
    size_t written = 0;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (ctx->decrypt)
    {
        *outl = outsize;

        if (pkcs11_decrypt_final(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outl))
        {
            return 0;
        }
    }
    else
    {
        if (ctx->padding)
        {
            /* Padding */
            if (ctx->out_counter + ctx->block_size < ctx->in_counter)
            {
                ctx_log(ctx->provctx, 3, "%s padding off, but there are %ld bytes in crypt buffer\n", __FUNCTION__, ctx->in_counter - ctx->out_counter);
            }

            /* some bytes are not written */
            size_t padlen = ctx->block_size - ((ctx->in_counter - ctx->out_counter) % ctx->block_size);
            memset(ctx->buffer, (char)padlen, padlen);

            *outl = outsize;

            if (!p11_cipher_update(ctx, out, outl, outsize, ctx->buffer, padlen))
            {
                return 0;
            }

            out += *outl;
            outsize -= *outl;
            written += *outl;
        }

        /* finalize */
        *outl = outsize;

        if (pkcs11_encrypt_final(PRIVCTX(ctx->provctx->pkcs11_ctx), ctx->session, out, outl))
        {
            return 0;
        }

        if (outsize > *outl)
        {
            ctx_log(ctx->provctx, 2, "%s cannot write final bytes, %ld in access\n", __FUNCTION__, outsize - *outl);
            return 0;
        }

        /* before the final, we might called the update and that might produced output */
        *outl += written;
    }

    return 1;
}

/******************************************************************************/

static const OSSL_PARAM get_params[] = {
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
OSSL_PARAM_END};

static const OSSL_PARAM get_ctx_params[] = {
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
OSSL_PARAM_END};

static const OSSL_PARAM set_ctx_params[] = {
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
OSSL_PARAM_END};

#define GET_PARAM(name, type, value)                   \
    p = OSSL_PARAM_locate(params, name);               \
    if (p != NULL && !OSSL_PARAM_set_##type(p, value)) \
    {                                                  \
        return 0;                                      \
    }

static const OSSL_PARAM* p11_cipher_gettable_params(void* provctx)
{
    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return get_params;
}

static int p11_cipher_get_params(OSSL_PARAM params[], CK_MECHANISM_TYPE type, size_t keylen, size_t block_size, size_t ivlen, unsigned int mode)
{
    (void)type;
    OSSL_PARAM* p;

    if (params == NULL)
    {
        return 1;
    }

    GET_PARAM(OSSL_CIPHER_PARAM_BLOCK_SIZE, size_t, block_size / 8)
    GET_PARAM(OSSL_CIPHER_PARAM_KEYLEN, size_t, keylen / 8)
    GET_PARAM(OSSL_CIPHER_PARAM_IVLEN, size_t, ivlen / 8)
    GET_PARAM(OSSL_CIPHER_PARAM_MODE, uint, mode)

    return 1;
}

static const OSSL_PARAM* p11_cipher_gettable_ctx_params(void* cctx, void* provctx)
{
    (void)cctx;
    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return get_ctx_params;
}

static int p11_cipher_get_ctx_params(void* cctx, OSSL_PARAM params[])
{
    P11_CIPHER_CTX* ctx = cctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    OSSL_PARAM* p;

    if (params == NULL)
    {
        return 1;
    }

    GET_PARAM(OSSL_CIPHER_PARAM_KEYLEN, size_t, ctx->keylen)
    GET_PARAM(OSSL_CIPHER_PARAM_IVLEN, size_t, ctx->ivlen)
    GET_PARAM(OSSL_CIPHER_PARAM_PADDING, uint, ctx->padding)

    return 1;
}

static const OSSL_PARAM* p11_cipher_settable_ctx_params(void* cctx, void* provctx)
{
    (void)provctx;
    P11_CIPHER_CTX* ctx = cctx;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    return set_ctx_params;
}

static int p11_cipher_set_ctx_params(void* cctx, const OSSL_PARAM params[])
{
    P11_CIPHER_CTX* ctx = cctx;
    const OSSL_PARAM* p;

    ctx_log(ctx->provctx, 3, "%s\n", __FUNCTION__);

    if (params == NULL)
    {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &ctx->padding))
    {
        return 0;
    }

    return 1;
}
