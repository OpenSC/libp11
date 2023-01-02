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

#ifndef _PROV_RAND_H
#define _PROV_RAND_H

#include <openssl/crypto.h>
#include <openssl/types.h>

struct p11_randctx_t
{
    PROVIDER_CTX* provctx;

    void* parent;
    const OSSL_DISPATCH* parent_calls;
    OSSL_FUNC_rand_get_seed_fn* parent_get_seed;
    OSSL_FUNC_rand_clear_seed_fn* parent_clear_seed;

    PKCS11_SLOT* slot;
    CK_SESSION_HANDLE session;
    CRYPTO_RWLOCK* lock;

    size_t max_random_length;      /* Specifies the maximum number of bytes that can be generated in a single call to OSSL_FUNC_rand_generate. */
    unsigned int generate_counter; /* Counts the number of generate requests since the last reseed (Starts at 1). */
    unsigned int reseed_interval;  /* Maximum number of generate requests until a reseed is required. This value is ignored if it is zero. */
    unsigned int reseed_counter;   /* Number of reseeds. */
    time_t reseed_time;            /* Stores the time when the last reseeding occurred */
    time_t reseed_time_interval;   /* Specifies the maximum time interval (in seconds) between reseeds. This value is ignored if it is zero. */
    size_t min_entropy;            /* Specify the minimum number of bytes of random material that can be used to seed the DRBG. */
    size_t max_entropy;            /* Specify the maximum number of bytes of random material that can be used to seed the DRBG. */
};

typedef struct p11_randctx_t P11_RAND_CTX;

const OSSL_ALGORITHM* p11_get_ops_rand(void* provctx, int* no_store);

#endif
