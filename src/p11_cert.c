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

/*
 * p11_cert.c - Handle certificates residing on a PKCS11 token
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
 */

#include "libp11-int.h"
#include <string.h>

static int pkcs11_find_certs(PKCS11_TOKEN *);
static int pkcs11_next_cert(PKCS11_CTX *, PKCS11_TOKEN *, CK_SESSION_HANDLE);
static int pkcs11_init_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o, PKCS11_CERT **);

/*
 * Enumerate all certs on the card
 */
int
PKCS11_enumerate_certs(PKCS11_TOKEN * token,
		PKCS11_CERT ** certp, unsigned int *countp)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	int rv;

	if (tpriv->ncerts < 0) {
		if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
			return -1;
		pkcs11_w_lock(cpriv->lockid);
		rv = pkcs11_find_certs(token);
		pkcs11_w_unlock(cpriv->lockid);
		if (rv < 0) {
			pkcs11_destroy_certs(token);
			return -1;
		}
	}
	if (certp)
		*certp = tpriv->certs;
	if (countp)
		*countp = tpriv->ncerts;
	return 0;
}

/*
 * Find certificate matching a key
 */
PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert;
	unsigned int n, count;

	kpriv = PRIVKEY(key);
	if (PKCS11_enumerate_certs(KEY2TOKEN(key), &cert, &count))
		return NULL;
	for (n = 0; n < count; n++, cert++) {
		cpriv = PRIVCERT(cert);
		if (cpriv->id_len == kpriv->id_len
				&& !memcmp(cpriv->id, kpriv->id, kpriv->id_len))
			return cert;
	}
	return NULL;
}

/*
 * Find all certs of a given type (public or private)
 */
static int pkcs11_find_certs(PKCS11_TOKEN * token)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS cert_search_class;
	CK_ATTRIBUTE cert_search_attrs[] = {
		{CKA_CLASS, &cert_search_class, sizeof(cert_search_class)},
	};
	int rv, res = -1;

	/* Make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	cert_search_class = CKO_CERTIFICATE;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(session, cert_search_attrs, 1));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_CERTS, rv);

	tpriv->ncerts = 0;
	do {
		res = pkcs11_next_cert(ctx, token, session);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_CERTS, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_cert(ctx, token, session, obj, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, PKCS11_CERT ** ret)
{
	PKCS11_TOKEN_private *tpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert, *tmp;
	char label[256];
	unsigned char *data;
	unsigned char id[256];
	CK_CERTIFICATE_TYPE cert_type;
	size_t size;

	(void)ctx;
	(void)session;

	size = sizeof(cert_type);
	if (pkcs11_getattr_var(token, obj, CKA_CERTIFICATE_TYPE, &cert_type, &size))
		return -1;

	/* Ignore any certs we don't understand */
	if (cert_type != CKC_X_509)
		return 0;

	tpriv = PRIVTOKEN(token);
	tmp = OPENSSL_realloc(tpriv->certs,
		(tpriv->ncerts + 1) * sizeof(PKCS11_CERT));
	if (tmp == NULL) {
		OPENSSL_free(tpriv->certs);
		tpriv->certs = NULL;
		return -1;
	}
	tpriv->certs = tmp;

	cert = tpriv->certs + tpriv->ncerts++;
	memset(cert, 0, sizeof(*cert));
	cpriv = OPENSSL_malloc(sizeof(PKCS11_CERT_private));
	if (cpriv == NULL)
		return -1;
	memset(cpriv, 0, sizeof(PKCS11_CERT_private));
	cert->_private = cpriv;
	cpriv->object = obj;
	cpriv->parent = token;

	if (!pkcs11_getattr_s(token, obj, CKA_LABEL, label, sizeof(label)))
		cert->label = BUF_strdup(label);
	size = 0;
	if (!pkcs11_getattr_var(token, obj, CKA_VALUE, NULL, &size) && size > 0) {
		data = OPENSSL_malloc(size);
		if (data) {
			if (!pkcs11_getattr_var(token, obj, CKA_VALUE, data, &size)) {
				const unsigned char *p = data;

				cert->x509 = d2i_X509(NULL, &p, (long) size);
			}
			OPENSSL_free(data);
		}
	}
	cert->id_len = sizeof(id);
	if (!pkcs11_getattr_var(token, obj, CKA_ID, id, &cert->id_len)) {
		cert->id = OPENSSL_malloc(cert->id_len);
		if (cert->id == NULL)
			return -1;
		memcpy(cert->id, id, cert->id_len);
	}

	/* Initialize internal information */
	cpriv->id_len = sizeof(cpriv->id);
	if (pkcs11_getattr_var(token, obj, CKA_ID, cpriv->id, &cpriv->id_len))
		cpriv->id_len = 0;

	if (ret)
		*ret = cert;
	return 0;
}

/*
 * Destroy all certs
 */
void pkcs11_destroy_certs(PKCS11_TOKEN * token)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	while (priv->ncerts > 0) {
		PKCS11_CERT *cert = &priv->certs[--(priv->ncerts)];

		if (cert->x509)
			X509_free(cert->x509);
		OPENSSL_free(cert->label);
		if (cert->id)
			OPENSSL_free(cert->id);
		if (cert->_private != NULL)
			OPENSSL_free(cert->_private);
	}
	if (priv->certs)
		OPENSSL_free(priv->certs);
	priv->certs = NULL;
	priv->ncerts = -1;
}

/*
 * Store certificate
 */
int
PKCS11_store_certificate(PKCS11_TOKEN * token, X509 * x509, char *label,
		unsigned char *id, size_t id_len, PKCS11_CERT ** ret_cert)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	CHECK_SLOT_FORK(slot);

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the template */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_CERTIFICATE);
	pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
	pkcs11_addattr_int(attrs + n++, CKA_CERTIFICATE_TYPE, CKC_X_509);
	pkcs11_addattr_obj(attrs + n++, CKA_VALUE, (pkcs11_i2d_fn) i2d_X509, x509);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_CERTIFICATE, rv);

	/* Gobble the key object */
	return pkcs11_init_cert(ctx, token, session, object, ret_cert);
}

/* vim: set noexpandtab: */
