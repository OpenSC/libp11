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

#include "libp11-int.h"

int pkcs11_rand_generate(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t outlen, unsigned int strength, int prediction_resistance, const unsigned char* addin, size_t addin_len)
{
    int rv;

    (void)strength;
    (void)prediction_resistance;
    (void)addin;
    (void)addin_len;

    rv = CRYPTOKI_call(ctx, C_GenerateRandom(session, out, outlen));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_RANDOM, rv);
    return -1;
}

int pkcs11_rand_seed(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, int prediction_resistance, const unsigned char* ent, size_t ent_len, const unsigned char* addin, size_t addin_len)
{
    int rv;

    (void)prediction_resistance;
    (void)addin;
    (void)addin_len;

    rv = CRYPTOKI_call(ctx, C_SeedRandom(session, (unsigned char*)ent, ent_len));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_RANDOM, rv);
    return -1;
}
