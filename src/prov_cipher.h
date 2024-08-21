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

#ifndef _PROV_CIPHER_H
#define _PROV_CIPHER_H

#include <openssl/types.h>

#include "libp11.h"
#include "pkcs11.h"
#include "prov_ctx.h"

struct p11_cipherctx_t
{
    PROVIDER_CTX* provctx;
    PKCS11_SLOT* slot;
    CK_SESSION_HANDLE session;
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_PTR mech;
    int decrypt;
    CK_OBJECT_HANDLE_PTR key_object;
    CK_KEY_TYPE key_type;
    size_t keylen;
    size_t block_size;
    size_t ivlen;
    unsigned int mode;
    unsigned int padding;

    size_t in_counter;
    size_t out_counter;
    size_t buflen;
    unsigned char* buffer;
};

typedef struct p11_cipherctx_t P11_CIPHER_CTX;

const OSSL_ALGORITHM* p11_get_ops_cipher(void* provctx, int* no_store);

#endif
