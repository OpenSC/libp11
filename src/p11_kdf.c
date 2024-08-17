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

void phex(unsigned char* p, size_t len);

int pkcs11_generate_secret_key(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_KEY_TYPE key_type, size_t keylen, unsigned char* key)
{
    CK_RV rv;
    CK_BBOOL false = FALSE;
    CK_BBOOL true = TRUE;

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    // CK_UTF8CHAR label[] = "libp11";

    CK_ATTRIBUTE attributes[] = {
    {CKA_CLASS, &class, sizeof(class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    {CKA_DERIVE, &true, sizeof(true)},
    {CKA_SENSITIVE, &false, sizeof(false)},
    {CKA_EXTRACTABLE, &true, sizeof(true)},
    // {CKA_TOKEN, &true, sizeof(true)},
    // {CKA_LABEL, label, sizeof(label) - 1},
    // {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VALUE_LEN, &keylen, sizeof(keylen)}};

    CK_ULONG attributes_count = sizeof(attributes) / sizeof(*attributes);

    CK_OBJECT_HANDLE key_handle;

    rv = CRYPTOKI_call(ctx, C_GenerateKey(session, mechanism, attributes, attributes_count, &key_handle));
    if (rv != CKR_OK)
    {
        goto err;
    }

    CK_ATTRIBUTE template[] = {
    {CKA_VALUE, key, keylen}};

    rv = CRYPTOKI_call(ctx, C_GetAttributeValue(session, key_handle, template, 1));
    if (rv != CKR_OK)
    {
        goto err;
    }

    phex(key, keylen);
    return 0;

err:
    CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_KEY, rv);
    return 1;
}

void phex(unsigned char* p, size_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }

    printf("\n");
}