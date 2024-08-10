#ifndef _PROV_STOREMGMT_H
#define _PROV_STOREMGMT_H

#include <openssl/types.h>

#include "pkcs11.h"
#include "prov_ctx.h"

/* copied from OpenSSL crypto/store/store_local.h */

struct ossl_store_info_st
{
    int type;

    union
    {
        void* data; /* used internally as generic pointer */

        struct
        {
            char* name;
            char* desc;
        } name; /* when type == OSSL_STORE_INFO_NAME */

        EVP_PKEY* params; /* when type == OSSL_STORE_INFO_PARAMS */
        EVP_PKEY* pubkey; /* when type == OSSL_STORE_INFO_PUBKEY */
        EVP_PKEY* pkey;   /* when type == OSSL_STORE_INFO_PKEY */
        X509* x509;       /* when type == OSSL_STORE_INFO_CERT */
        X509_CRL* crl;    /* when type == OSSL_STORE_INFO_CRL */
    } _;
};

struct ossl_load_result_data_st
{
    OSSL_STORE_INFO* v; /* To be filled in */
    void* ctx;          /* Type changed to restrict further dependencies */
};

/* end copy section */

const OSSL_ALGORITHM* p11_get_ops_storemgmt(void* provctx, int* no_store);

// -------------------------------------------------------------------------------------------------

typedef struct pkcs11_object_private PKCS11_OBJECT_private; /* Forward definition. See libp11-int.h */

enum P11_STORE_CTX_STATE
{
    P11_STORE_CTX_STATE_INITIAL = 0,
    P11_STORE_CTX_STATE_LOADING,
    P11_STORE_CTX_STATE_LOADED,
    P11_STORE_CTX_STATE_ERROR
};

struct p11_storectx_t
{
    PROVIDER_CTX* provctx;
    char* uri;
    char* label;
    int type;
    CK_OBJECT_HANDLE handle;
    enum P11_STORE_CTX_STATE state;
    PKCS11_OBJECT_private* object;

    EVP_PKEY* privkey;
    EVP_PKEY* pubkey;
    X509* cert;
};

typedef struct p11_storectx_t P11_STORE_CTX;

#endif
