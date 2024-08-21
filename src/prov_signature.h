#ifndef _PROV_SIGNATURE_H
#define _PROV_SIGNATURE_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_signature(void* provctx, int* no_store);

#endif