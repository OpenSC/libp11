#ifndef _PROV_KEYEXCH_H
#define _PROV_KEYEXCH_H

#include <openssl/types.h>

const OSSL_ALGORITHM* p11_get_ops_keyexch(void* provctx, int* no_store);

#endif
