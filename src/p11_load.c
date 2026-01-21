/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
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

/* Global number of active PKCS11_CTX objects */
int pkcs11_global_data_refs = 0;

/*
 * Create a new context
 */
PKCS11_CTX *pkcs11_CTX_new(void)
{
	PKCS11_CTX_private *cpriv = NULL;
	PKCS11_CTX *ctx = NULL;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	cpriv = OPENSSL_malloc(sizeof(PKCS11_CTX_private));
	if (!cpriv)
		goto fail;
	memset(cpriv, 0, sizeof(PKCS11_CTX_private));
	ctx = OPENSSL_malloc(sizeof(PKCS11_CTX));
	if (!ctx)
		goto fail;
	memset(ctx, 0, sizeof(PKCS11_CTX));
	ctx->_private = cpriv;
	cpriv->forkid = get_forkid();
	pthread_mutex_init(&cpriv->fork_lock, 0);

	pkcs11_global_data_refs++;

	return ctx;
fail:
	OPENSSL_free(cpriv);
	OPENSSL_free(ctx);
	return NULL;
}

/*
 * Set private init args for module
 */
void pkcs11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	/* Free previously duplicated string */
	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	cpriv->init_args = init_args ? OPENSSL_strdup(init_args) : NULL;
}

/*
 * Tell the PKCS11 to initialize itself
 */
static int pkcs11_initialize(PKCS11_CTX_private *cpriv)
{
	CK_C_INITIALIZE_ARGS args;
	int rv;

	memset(&args, 0, sizeof(args));
	/* Unconditionally say using OS locking primitives is OK */
	args.flags |= CKF_OS_LOCKING_OK;
	args.pReserved = cpriv->init_args;
	rv = cpriv->method->C_Initialize(&args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		cpriv->initialized = 0;
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}
	cpriv->initialized = 1;
	return 0;
}

/*
 * Load the shared library, and initialize it.
 */
int pkcs11_CTX_load(PKCS11_CTX *ctx, const char *name)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_INFO ck_info;
	int rv;

	cpriv->handle = C_LoadModule(name, &cpriv->method);
	if (!cpriv->handle) {
		P11err(P11_F_PKCS11_CTX_LOAD, P11_R_LOAD_MODULE_ERROR);
		return -1;
	}

	if (pkcs11_initialize(cpriv)) {
		pkcs11_CTX_unload(ctx);
		return -1;
	}

	/* Get info on the library */
	memset(&ck_info, 0, sizeof(ck_info));
	rv = cpriv->method->C_GetInfo(&ck_info);
	if (rv) {
		pkcs11_CTX_unload(ctx);
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}
	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);
	cpriv->cryptoki_version.major = ck_info.cryptokiVersion.major;
	cpriv->cryptoki_version.minor = ck_info.cryptokiVersion.minor;

	return 0;
}

/*
 * Reinitialize (e.g., after a fork).
 */
int pkcs11_CTX_reload(PKCS11_CTX_private *cpriv)
{
	if (!cpriv->method) /* Module not loaded */
		return 0;

	return pkcs11_initialize(cpriv);
}

/*
 * Unload the shared library
 */
void pkcs11_CTX_unload(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	/* Tell the PKCS11 library to shut down */
	if (cpriv->method) {
		if (cpriv->initialized && cpriv->forkid == get_forkid())
			cpriv->method->C_Finalize(NULL);
		cpriv->method = NULL;
	}

	/* Unload the module */
	if (cpriv->handle) {
		C_UnloadModule(cpriv->handle);
		cpriv->handle = NULL;
	}
}

/*
 * Free a context
 */
void pkcs11_CTX_free(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	if (cpriv->handle) {
		OPENSSL_free(cpriv->handle);
	}
	pthread_mutex_destroy(&cpriv->fork_lock);
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);

	pkcs11_global_data_refs--;
#ifndef OPENSSL_NO_RSA
	pkcs11_rsa_method_free();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
#ifndef OPENSSL_NO_EC
	pkcs11_ec_key_method_free();
# if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x40000000L
	pkcs11_ed_key_method_free();
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x40000000L */
#endif /* OPENSSL_NO_EC */
#else /* OPENSSL_VERSION_NUMBER */
#ifndef OPENSSL_NO_ECDSA
	pkcs11_ecdsa_method_free();
#endif /* OPENSSL_NO_ECDSA */
#ifndef OPENSSL_NO_ECDH
	pkcs11_ecdh_method_free();
#endif /* OPENSSL_NO_ECDH */
#endif /* OPENSSL_VERSION_NUMBER */
}

/* vim: set noexpandtab: */
