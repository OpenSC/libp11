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

int pkcs11_digest_init(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE type)
{
    CK_MECHANISM mech;
    int rv;

    mech.mechanism = type;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    rv = CRYPTOKI_call(ctx, C_DigestInit(session, &mech));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DIGEST_INIT, rv);
    return -1;
}

#define BUFFER_SIZE 256
int pkcs11_digest_abort(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session)
{
    int rv;

    /* According to https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html
     * C_DigestInit() has to support pMechanism = NULL, but OpenCryptoki does not support, hence
     * C_DigestFinal() is being used. 
     */
    rv = CRYPTOKI_call(ctx, C_DigestInit(session, NULL));
    if (rv == CKR_OK)
    {
        return 0;
    }

    /* OpenCryptoki does not support C_DigestInit() with pMechanism = NULL, hence let's try also
     * C_DigestFinal(). 
     */

    CK_BYTE buffer[BUFFER_SIZE];
    CK_ULONG buffer_size = BUFFER_SIZE;
    rv = CRYPTOKI_call(ctx, C_DigestFinal(session, buffer, &buffer_size));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DIGEST_ABORT, rv);
    return -1;
}
#undef BUFFER_SIZE

int pkcs11_digest_update(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, const unsigned char* in, size_t inl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_DigestUpdate(session, (unsigned char*)in, inl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DIGEST_UPDATE, rv);
    return -1;
}

int pkcs11_digest_final(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t* outl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_DigestFinal(session, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DIGEST_FINAL, rv);
    return -1;
}

int pkcs11_digest(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, const unsigned char* in, size_t inl, unsigned char* out, size_t* outl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_Digest(session, (unsigned char*)in, inl, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DIGEST, rv);
    return -1;
}
