#include <stdlib.h>

#include "prov_ctx.h"
#include "prov_kem.h"

const OSSL_ALGORITHM* p11_get_ops_kem(void* provctx, int* no_store)
{
    (void)no_store;

    PROVIDER_CTX* ctx = provctx;

    ctx_log(ctx, 3, "%s\n", __FUNCTION__);

    // return !ctx->b_kem_disabled ? NULL : NULL;
    return NULL;
}