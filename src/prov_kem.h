#ifndef _PROV_KEM_H
#define _PROV_KEM_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_kem(void* provctx, int* no_store);

#endif
