#ifndef _PROV_ASYM_CIPHER_H
#define _PROV_ASYM_CIPHER_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_asym_cipher(void* provctx, int* no_store);

#endif
