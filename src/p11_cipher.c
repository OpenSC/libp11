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

int pkcs11_create_cipher_key_object(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR* key_object, CK_KEY_TYPE key_type, const unsigned char* key, size_t keylen)
{
    (void)ctx;
    CK_OBJECT_HANDLE_PTR obj;

    obj = malloc(sizeof(*obj));
    if (!obj)
    {
        goto err;
    }

    int rv;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_UTF8CHAR label[] = "libp11";
    CK_BBOOL true = CK_TRUE;

    CK_ATTRIBUTE attributes[] = {
    {CKA_CLASS, &class, sizeof(class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_LABEL, label, sizeof(label) - 1},
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VALUE, (unsigned char*)key, keylen}};

    CK_ULONG attributes_count = 6;

    rv = CRYPTOKI_call(ctx, C_CreateObject(session, attributes, attributes_count, obj));
    if (rv != CKR_OK)
    {
        goto err;
    }

    *key_object = obj;

    return 0;

err:
    CRYPTOKI_checkerr(CKR_F_PKCS11_CREATE_CIPHER_KEY_OBJECT, rv);
    return -1;
}

int pkcs11_destroy_cipher_key_object(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR* key_object)
{
    (void)ctx;
    int rv;

    rv = CRYPTOKI_call(ctx, C_DestroyObject(session, **key_object));
    if (rv != CKR_OK)
    {
        goto err;
    }

    free(*key_object);
    *key_object = NULL;

    return 0;

err:
    CRYPTOKI_checkerr(CKR_F_PKCS11_DESTROY_CIPHER_KEY_OBJECT, rv);
    return -1;
}

int pkcs11_decrypt_init(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_MECHANISM_PTR type, CK_OBJECT_HANDLE_PTR key_object, const unsigned char* iv, size_t ivlen)
{
    int rv;

    // TODO: handle iv & ivlen
    (void)iv;
    (void)ivlen;

    rv = CRYPTOKI_call(ctx, C_DecryptInit(session, type, *key_object));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DECRYPT_INIT, rv);
    return -1;
}

int pkcs11_decrypt_update(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t* outl, unsigned char* in, size_t inl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_DecryptUpdate(session, in, inl, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DECRYPT_UPDATE, rv);
    return -1;
}

int pkcs11_decrypt_final(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t* outl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_DecryptFinal(session, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_DECRYPT_FINAL, rv);
    return -1;
}

int pkcs11_encrypt_init(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, CK_MECHANISM_PTR type, CK_OBJECT_HANDLE_PTR key_object, const unsigned char* iv, size_t ivlen)
{
    int rv;

    // TODO: handle iv & ivlen
    (void)iv;
    (void)ivlen;

    rv = CRYPTOKI_call(ctx, C_EncryptInit(session, type, *key_object));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_ENCRYPT_INIT, rv);
    return -1;
}

int pkcs11_encrypt_update(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t* outl, const unsigned char* in, size_t inl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_EncryptUpdate(session, (unsigned char*)in, inl, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_ENCRYPT_UPDATE, rv);
    return -1;
}

int pkcs11_encrypt_final(PKCS11_CTX_private* ctx, CK_SESSION_HANDLE session, unsigned char* out, size_t* outl)
{
    int rv;

    rv = CRYPTOKI_call(ctx, C_EncryptFinal(session, out, outl));
    if (rv == CKR_OK)
    {
        return 0;
    }

    CRYPTOKI_checkerr(CKR_F_PKCS11_ENCRYPT_FINAL, rv);
    return -1;
}
