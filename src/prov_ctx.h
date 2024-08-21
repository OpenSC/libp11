/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef P11_PROVCTX_H
#define P11_PROVCTX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "libp11.h"
#include "p11_pthread.h"

typedef struct PKCS11_ctx_st PKCS11_CTX;             /** Forward declaration: PKCS11 context */
typedef struct PKCS11_slot_st PKCS11_SLOT;           /** Forward declaration: PKCS11 slot: card reader */
typedef struct PKCS11_mechanism_st PKCS11_MECHANISM; /** Forward declaration: PKCS11 mechanism */

struct provctx
{
    const OSSL_CORE_HANDLE* handle;
    // OPENSSL_CORE_CTX* corectx;
    OSSL_LIB_CTX* libctx;
    PKCS11_CTX* pkcs11_ctx;

    /* default core params */
    const char* openssl_version;
    const char* provider_name;
    char* module_filename;
    char* module;
    /* custom core params */
    char* pkcs11module;
    char* p_verbose;
    char* p_force_login;
    char* p_reseed_interval;
    char* p_reseed_time_interval;
    char* p_max_random_length;
    char* p_min_entropy;
    char* p_max_entropy;
    char* p_asym_cipher_disabled;
    char* p_cipher_disabled;
    char* p_digest_disabled;
    char* p_kdf_disabled;
    char* p_kem_disabled;
    char* p_keyexch_disabled;
    char* p_keymgmt_disabled;
    char* p_mac_disabled;
    char* p_rand_disabled;
    char* p_signature_disabled;
    char* p_storemgmt_disabled;

    /* enabled/disabled functions */
    unsigned int b_asym_cipher_disabled;
    unsigned int b_cipher_disabled;
    unsigned int b_digest_disabled;
    unsigned int b_kdf_disabled;
    unsigned int b_kem_disabled;
    unsigned int b_keyexch_disabled;
    unsigned int b_keymgmt_disabled;
    unsigned int b_mac_disabled;
    unsigned int b_rand_disabled;
    unsigned int b_signature_disabled;
    unsigned int b_storemgmt_disabled;

    /* functions offered by libcrypto to the providers */
#define CORE_FN_PTR(name) OSSL_FUNC_##name##_fn* name
    CORE_FN_PTR(core_gettable_params);
    CORE_FN_PTR(core_get_params);
    CORE_FN_PTR(core_thread_start);
    CORE_FN_PTR(core_get_libctx);
    CORE_FN_PTR(core_new_error);
    CORE_FN_PTR(core_set_error_debug);
    CORE_FN_PTR(core_vset_error);
    CORE_FN_PTR(core_set_error_mark);
    CORE_FN_PTR(core_clear_last_error_mark);
    CORE_FN_PTR(core_pop_error_to_mark);
    CORE_FN_PTR(CRYPTO_malloc);
    CORE_FN_PTR(CRYPTO_zalloc);
    CORE_FN_PTR(CRYPTO_free);
    CORE_FN_PTR(CRYPTO_clear_free);
    CORE_FN_PTR(CRYPTO_realloc);
    CORE_FN_PTR(CRYPTO_clear_realloc);
    CORE_FN_PTR(CRYPTO_secure_malloc);
    CORE_FN_PTR(CRYPTO_secure_zalloc);
    CORE_FN_PTR(CRYPTO_secure_free);
    CORE_FN_PTR(CRYPTO_secure_clear_free);
    CORE_FN_PTR(CRYPTO_secure_allocated);
    CORE_FN_PTR(OPENSSL_cleanse);
    CORE_FN_PTR(BIO_new_file);
    CORE_FN_PTR(BIO_new_membuf);
    CORE_FN_PTR(BIO_read_ex);
    CORE_FN_PTR(BIO_free);
    CORE_FN_PTR(BIO_vprintf);
    CORE_FN_PTR(self_test_cb);
#undef CORE_FN

    /*
     * The PIN used for login. Cache for the ctx_get_pin function.
     * The memory for this PIN is always owned internally,
     * and may be freed as necessary. Before freeing, the PIN
     * must be whitened, to prevent security holes.
     */
    char* pin;
    size_t pin_length;
    int forced_pin;

    union
    {
        int verbose;
        int i_verbose;
    };

    char* init_args;
    OSSL_PASSPHRASE_CALLBACK* pw_cb;
    void* pw_cbarg;

    union
    {
        int force_login;
        int b_force_login;
    };

    pthread_mutex_t lock;

    PKCS11_SLOT* slot_list;
    unsigned int slot_count;

    PKCS11_SLOT* slot;
    PKCS11_MECHANISM* mechanism_list;
    unsigned long mechanism_count;

    /* random generator */
    unsigned int i_reseed_interval; /* Maximum number of generate requests until a reseed is required. This value is ignored if it is zero. */
    time_t i_reseed_time_interval;  /* Specifies the maximum time interval (in seconds) between reseeds. This value is ignored if it is zero. */
    size_t i_max_random_length;     /* Specifies the maximum number of bytes that can be generated in a single call to OSSL_FUNC_rand_generate. */
    size_t i_min_entropy;           /* Specify the minimum number of bytes of random material that can be used to seed the DRBG. */
    size_t i_max_entropy;           /* Specify the maximum number of bytes of random material that can be used to seed the DRBG. */
};

typedef struct provctx PROVIDER_CTX;

#define ctx_log(ctx, level, format, args...)                           \
    if (level <= ctx->verbose)                                         \
    /*fprintf(stderr, "[%s:%d] " format, __FILE__, __LINE__, ##args)*/ \
    fprintf(stderr, format, ##args)
#endif
