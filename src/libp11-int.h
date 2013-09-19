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

#ifndef _LIBP11_INT_H
#define _LIBP11_INT_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define CRYPTOKI_EXPORTS
#include <pkcs11.h>

extern void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern CK_RV C_UnloadModule(void *module);

#include "libp11.h"

/* get private implementations of PKCS11 structures */

/*
 * PKCS11_CTX: context for a PKCS11 implementation
 */
typedef struct pkcs11_ctx_private {
	char *name;
	void *libinfo;
	CK_FUNCTION_LIST_PTR method;

	CK_SESSION_HANDLE session;
	char *init_args;
} PKCS11_CTX_private;
#define PRIVCTX(ctx)		((PKCS11_CTX_private *) (ctx->_private))

typedef struct pkcs11_slot_private {
	PKCS11_CTX *parent;
	unsigned char haveSession, loggedIn;
	CK_SLOT_ID id;
	CK_SESSION_HANDLE session;
} PKCS11_SLOT_private;
#define PRIVSLOT(slot)		((PKCS11_SLOT_private *) (slot->_private))
#define SLOT2CTX(slot)		(PRIVSLOT(slot)->parent)

typedef struct pkcs11_token_private {
	PKCS11_SLOT *parent;
	int nkeys, nprkeys;
	PKCS11_KEY *keys;
	int ncerts;
	PKCS11_CERT *certs;
} PKCS11_TOKEN_private;
#define PRIVTOKEN(token)	((PKCS11_TOKEN_private *) (token->_private))
#define TOKEN2SLOT(token)	(PRIVTOKEN(token)->parent)
#define TOKEN2CTX(token)	SLOT2CTX(TOKEN2SLOT(token))

typedef struct pkcs11_key_ops {
	int type;               /* EVP_PKEY_xxx */
	int (*get_public) (PKCS11_KEY *, EVP_PKEY *);
	int (*get_private) (PKCS11_KEY *, EVP_PKEY *);
} PKCS11_KEY_ops;

typedef struct pkcs11_key_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
	PKCS11_KEY_ops *ops;
} PKCS11_KEY_private;
#define PRIVKEY(key)		((PKCS11_KEY_private *) key->_private)
#define KEY2SLOT(key)		TOKEN2SLOT(KEY2TOKEN(key))
#define KEY2TOKEN(key)		(PRIVKEY(key)->parent)
#define KEY2CTX(key)		TOKEN2CTX(KEY2TOKEN(key))

typedef struct pkcs11_cert_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
} PKCS11_CERT_private;
#define PRIVCERT(cert)		((PKCS11_CERT_private *) cert->_private)
#define CERT2SLOT(cert)		TOKEN2SLOT(CERT2TOKEN(cert))
#define CERT2TOKEN(cert)	(PRIVCERT(cert)->parent)
#define CERT2CTX(cert)		TOKEN2CTX(CERT2TOKEN(cert))

/*
 * Mapping Cryptoki error codes to those used internally
 * by this code.
 * Right now, we just map them directly, and make sure
 * that the few genuine messages we use don't clash with
 * PKCS#11
 */
#define pkcs11_map_err(rv)	(rv)

/*
 * Internal functions
 */
#define CRYPTOKI_checkerr(f, rv) \
	do { if (rv) { \
		PKCS11err(f, pkcs11_map_err(rv)); \
		return -1; \
	} } while (0)
#define CRYPTOKI_call(ctx, func_and_args) \
	PRIVCTX(ctx)->method->func_and_args

/* Memory allocation */
#define PKCS11_NEW(type) \
	((type *) pkcs11_malloc(sizeof(type)))
#define PKCS11_DUP(s) \
	pkcs11_strdup((char *) s, sizeof(s))

extern void pkcs11_release_slot(PKCS11_CTX *, PKCS11_SLOT *slot);

extern void pkcs11_destroy_keys(PKCS11_TOKEN *);
extern void pkcs11_destroy_certs(PKCS11_TOKEN *);
extern void *pkcs11_malloc(size_t);
extern char *pkcs11_strdup(char *, size_t);

extern int pkcs11_getattr(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			  unsigned int, void *, size_t);
extern int pkcs11_getattr_s(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			    unsigned int, void *, size_t);
extern int pkcs11_getattr_var(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			      unsigned int, void *, size_t *);
extern int pkcs11_getattr_bn(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			     unsigned int, BIGNUM **);

#define key_getattr(key, t, p, s) \
	pkcs11_getattr(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

#define key_getattr_bn(key, t, bn) \
	pkcs11_getattr_bn(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (bn))

#define key_getattr_var(key, t, p, s) \
	pkcs11_getattr_var(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

typedef int (*pkcs11_i2d_fn) (void *, unsigned char **);
extern void pkcs11_addattr(CK_ATTRIBUTE_PTR, int, const void *, size_t);
extern void pkcs11_addattr_int(CK_ATTRIBUTE_PTR, int, unsigned long);
extern void pkcs11_addattr_bool(CK_ATTRIBUTE_PTR, int, int);
extern void pkcs11_addattr_s(CK_ATTRIBUTE_PTR, int, const char *);
extern void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR, int, const BIGNUM *);
extern void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR, int, pkcs11_i2d_fn, void *);
extern void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR, unsigned int);

extern void *memdup(const void *, size_t);

extern PKCS11_KEY_ops pkcs11_rsa_ops;
extern PKCS11_KEY_ops pkcs11_ec_ops;

#endif
