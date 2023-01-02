#ifndef _PROV_KDF_H
#define _PROV_KDF_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_kdf(void* provctx, int* no_store);

#endif
