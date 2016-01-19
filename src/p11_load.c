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

#include "libp11-int.h"
#include <string.h>

static void *handle = NULL;

/*
 * Create a new context
 */
PKCS11_CTX *PKCS11_CTX_new(void)
{
	PKCS11_CTX_private *priv = NULL;
	PKCS11_CTX *ctx = NULL;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	priv = OPENSSL_malloc(sizeof(PKCS11_CTX_private));
	if (priv == NULL)
		goto fail;
	memset(priv, 0, sizeof(PKCS11_CTX_private));
	ctx = OPENSSL_malloc(sizeof(PKCS11_CTX));
	if (ctx == NULL)
		goto fail;
	memset(ctx, 0, sizeof(PKCS11_CTX));
	ctx->_private = priv;
	priv->forkid = _P11_get_forkid();
	priv->lockid = pkcs11_get_new_dynlockid();

	return ctx;
 fail:
	OPENSSL_free(priv);
	OPENSSL_free(ctx);
	return NULL;
}

/*
 * Set private init args for module
 */
void PKCS11_CTX_init_args(PKCS11_CTX * ctx, const char *init_args)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	/* Free previously duplicated string */
	if (priv->init_args) {
		OPENSSL_free(priv->init_args);
	}
	priv->init_args = init_args ? BUF_strdup(init_args) : NULL;
}

/*
 * Load the shared library, and initialize it.
 */
int PKCS11_CTX_load(PKCS11_CTX * ctx, const char *name)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS _args;
	CK_C_INITIALIZE_ARGS *args = NULL;
	CK_INFO ck_info;
	int rv;

	if (priv->libinfo != NULL) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_MODULE_LOADED_ERROR);
		return -1;
	}
	handle = C_LoadModule(name, &priv->method);
	if (handle == NULL) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_LOAD_MODULE_ERROR);
		return -1;
	}

	/* Tell the PKCS11 to initialize itself */
	if (priv->init_args != NULL) {
		memset(&_args, 0, sizeof(_args));
		args = &_args;
		/* Unconditionally say using OS locking primitives is OK */
		args->flags |= CKF_OS_LOCKING_OK;
		args->pReserved = priv->init_args;
	}
	rv = priv->method->C_Initialize(args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	/* Get info on the library */
	rv = priv->method->C_GetInfo(&ck_info);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CTX_LOAD, rv);

	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);

	return 0;
}

/*
 * Reinitialize (e.g., after a fork).
 */
int PKCS11_CTX_reload(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS _args;
	CK_C_INITIALIZE_ARGS *args = NULL;
	int rv;

	/* Tell the PKCS11 to initialize itself */
	if (priv->init_args != NULL) {
		memset(&_args, 0, sizeof(_args));
		args = &_args;
		args->pReserved = priv->init_args;
	}
	rv = priv->method->C_Initialize(args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	/* Reinitialize the PKCS11 internal slot table */
	return pkcs11_enumerate_slots(ctx, NULL, NULL);
}

/*
 * Unload the shared library
 */
void PKCS11_CTX_unload(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv;
	priv = PRIVCTX(ctx);

	/* Tell the PKCS11 library to shut down */
	if (priv->forkid == _P11_get_forkid())
		priv->method->C_Finalize(NULL);

	/* Unload the module */
	C_UnloadModule(handle);
}

/*
 * Free a context
 */
void PKCS11_CTX_free(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	/* Do not remove the strings since OpenSSL strings may still be used by
	 * the application and we can't know

	ERR_free_strings();
	ERR_remove_state(0);
	*/
	if (priv->init_args) {
		OPENSSL_free(priv->init_args);
	}
	pkcs11_destroy_dynlockid(priv->lockid);
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);
}

/* vim: set noexpandtab: */
