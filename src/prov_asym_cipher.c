#include <stdlib.h>

#include "prov_asym_cipher.h"
#include "prov_ctx.h"

const OSSL_ALGORITHM* p11_get_ops_asym_cipher(void* provctx, int* no_store)
{
    (void)no_store;

    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    return !ctx->b_asym_cipher_disabled ? NULL : NULL;
}