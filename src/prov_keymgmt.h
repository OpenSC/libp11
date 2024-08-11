#ifndef _PROV_KEYMGMT_H
#define _PROV_KEYMGMT_H

#include <openssl/types.h>

#include "prov_ctx.h"

#ifndef RSA_MIN_MODULUS_BITS
#define RSA_MIN_MODULUS_BITS    512
#endif

struct p11_keymgmtctx
{
    PROVIDER_CTX* provctx;
    PKCS11_SLOT* slot;
    long algorithm;

    /* PKCS11 URI */
    char* uri;

    /* Parsed from PKCS11 URI */
    char* label;
    char* id;
    size_t id_len;

    size_t nbits;

    char* group_name;
    char* encoding;
    char* point_conversion;
};

typedef struct p11_keymgmtctx P11_KEYMGMT_CTX;

const OSSL_ALGORITHM* p11_get_ops_keymgmt(void* provctx, int* no_store);

#endif
