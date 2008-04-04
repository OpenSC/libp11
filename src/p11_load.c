/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <config.h>
#include <string.h>
#include "libp11-int.h"

static void *handle = NULL;

/*
 * Create a new context
 */
PKCS11_CTX *PKCS11_CTX_new(void)
{
	PKCS11_CTX_private *priv;
	PKCS11_CTX *ctx;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	priv = PKCS11_NEW(PKCS11_CTX_private);
	ctx = PKCS11_NEW(PKCS11_CTX);
	ctx->_private = priv;

	return ctx;
}

/*
 * Load the shared library, and initialize it.
 */
int PKCS11_CTX_load(PKCS11_CTX * ctx, const char *name)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	CK_INFO ck_info;
	int rv;

	if (priv->libinfo != NULL) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_MODULE_LOADED_ERROR);
		return -1;
	}
	handle = C_LoadModule(name, &priv->method);
	if (!handle) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_LOAD_MODULE_ERROR);
		return -1;
	}

	/* Tell the PKCS11 to initialize itself */
	rv = priv->method->C_Initialize(NULL);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CTX_LOAD, rv);

	/* Get info on the library */
	rv = priv->method->C_GetInfo(&ck_info);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CTX_LOAD, rv);

	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);

	return 0;
}

/*
 * Unload the shared library
 */
void PKCS11_CTX_unload(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv;
	priv = PRIVCTX(ctx);

	/* Tell the PKCS11 library to shut down */
	priv->method->C_Finalize(NULL);

	/* Unload the module */
	C_UnloadModule(handle);
}

/*
 * Free a context
 */
void PKCS11_CTX_free(PKCS11_CTX * ctx)
{
	/* Do not remove the strings since OpenSSL strings may still be used by
	 * the application and we can't know

	ERR_free_strings();
	ERR_remove_state(0);
	*/
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);
}
