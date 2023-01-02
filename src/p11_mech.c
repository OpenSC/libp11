/*
 * Code build on definitions from OpenSSL 3 documentation.
 *
 * Copyright (c) 2022 Zoltan Patocs
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "libp11-int.h"
#include <openssl/buffer.h>

/*
 * Enumerate mechanisms of a slot
 */
int pkcs11_enumerate_slot_mechanisms(PKCS11_CTX_private* ctx,
                                     CK_SLOT_ID slotid,
                                     PKCS11_MECHANISM** mechp,
                                     unsigned long* mechcountp)
{
    CK_MECHANISM_TYPE *mechlist = NULL;
    PKCS11_MECHANISM *mechinfo = NULL;
    CK_ULONG mechcount;
    int rv;
    int i;

    /* Cache the slot's mechanism list. */
    rv = CRYPTOKI_call(ctx, C_GetMechanismList(slotid, NULL, &mechcount));
    if (rv != CKR_OK)
        goto err;

    mechlist = OPENSSL_malloc(mechcount * sizeof(*mechlist));
    if (!mechlist)
        goto err;

    rv = CRYPTOKI_call(ctx, C_GetMechanismList(slotid, mechlist, &mechcount));
    if (rv != CKR_OK)
        goto err;

    /* Cache the slot's mechanism info structure for each mechanism. */
    mechinfo = OPENSSL_malloc(mechcount * sizeof(*mechinfo));
    if (!mechinfo)
        goto err;

    for (i = 0; i < mechcount; i++)
    {
        mechinfo[i].type = mechlist[i];
        rv = CRYPTOKI_call(ctx, C_GetMechanismInfo(slotid, mechlist[i], &mechinfo[i].info));
        if (rv != CKR_OK)
            goto err;
    }

    OPENSSL_free(mechlist);

    *mechp = mechinfo;
    *mechcountp = mechcount;

    return 0;

err:

    if (mechinfo)
        OPENSSL_free(mechinfo);

    if (mechlist)
        OPENSSL_free(mechlist);

    CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_MECHANISMS, rv);
}

int pkcs11_enumerate_mechanisms(PKCS11_CTX_private* ctx,
                                PKCS11_SLOT* slots,
                                CK_ULONG nslots,
                                PKCS11_MECHANISM*** mechsp,
                                unsigned long** mechcountsp)
{
    PKCS11_MECHANISM** mechs = NULL;
    unsigned long* mechcounts = NULL;

    unsigned long i;
    int rv;

    mechs = OPENSSL_zalloc(nslots * sizeof(*mechs));
    if (!mechs)
        goto err;

    mechcounts = OPENSSL_zalloc(nslots * sizeof(*mechcounts));
    if (!mechcounts)
        goto err;

    for (i = 0; i < nslots; i++)
    {
        if (slots[i].token)
        {
            rv = pkcs11_enumerate_slot_mechanisms(ctx,
                                                  PKCS11_get_slotid_from_slot(&slots[i]),
                                                  &mechs[i],
                                                  &mechcounts[i]);
            if (rv)
                goto err;
        }
    }

    *mechsp = mechs;
    *mechcountsp = mechcounts;

    return 0;

err:

    if (mechs)
    {
        for (i = 0; i < nslots; i++)
        {
            if (mechs[i])
                OPENSSL_free(mechs[i]);
        }
        OPENSSL_free(mechs);
    }

    if (mechcounts)
        OPENSSL_free(mechcounts);

    return -1;
}
