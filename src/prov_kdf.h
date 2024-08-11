#ifndef _PROV_KDF_H
#define _PROV_KDF_H

#include <openssl/types.h>

struct pkcs11_kdf_ctx_st {
    size_t keylen;
    CK_VOID_PTR key;

    size_t passlen;
    char* pass;

    size_t saltlen;
    char* salt;

    size_t secretlen;
    CK_VOID_PTR secret;

    int mode;
    int iter;
    const char* mdname;

    size_t param_size;

    CK_MECHANISM_TYPE type;
    CK_SESSION_HANDLE session;
    CK_MECHANISM_PTR mech;

    PROVIDER_CTX* provctx;
    PKCS11_SLOT* slot;

};

typedef struct pkcs11_kdf_ctx_st PKCS11_KDF_CTX;

const OSSL_ALGORITHM* p11_get_ops_kdf(void* provctx, int* no_store);

#endif
