#ifndef _PROV_MAC_H
#define _PROV_MAC_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_mac(void* provctx, int* no_store);

#endif
