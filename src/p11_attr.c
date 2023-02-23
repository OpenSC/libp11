/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2016 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
 * PKCS11 attribute querying.
 *
 * The number of layers we stack on top of each other here
 * is frightening.
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
 */

#include "libp11-int.h"
#include <assert.h>
#include <string.h>

/*
 * Query pkcs11 attributes
 */
int pkcs11_getattr_var(PKCS11_CTX_private *ctx, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
		CK_BYTE *value, size_t *size)
{
	CK_ATTRIBUTE templ;
	int rv;

	templ.type = type;
	templ.pValue = value;
	templ.ulValueLen = *size;
	rv = CRYPTOKI_call(ctx, C_GetAttributeValue(session, object, &templ, 1));
	CRYPTOKI_checkerr(CKR_F_PKCS11_GETATTR_INT, rv);
	*size = templ.ulValueLen;
	return 0;
}

int pkcs11_getattr_val(PKCS11_CTX_private *ctx, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
		void *value, size_t size)
{
	return pkcs11_getattr_var(ctx, session, object, type, value, &size);
}

int pkcs11_getattr_alloc(PKCS11_CTX_private *ctx, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
		CK_BYTE **value, size_t *size)
{
	CK_BYTE *data;
	size_t len = 0;

	if (pkcs11_getattr_var(ctx, session, object, type, NULL, &len))
		return -1;
	data = OPENSSL_malloc(len+1);
	if (!data) {
		CKRerr(CKR_F_PKCS11_GETATTR_ALLOC, CKR_HOST_MEMORY);
		return -1;
	}
	memset(data, 0, len+1); /* also null-terminate the allocated data */
	if (pkcs11_getattr_var(ctx, session, object, type, data, &len)) {
		OPENSSL_free(data);
		return -1;
	}
	if (value)
		*value = data;
	if (size)
		*size = len;
	return 0;
}

int pkcs11_getattr_bn(PKCS11_CTX_private *ctx, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type, BIGNUM **bn)
{
	CK_BYTE *binary;
	size_t size;

	size = 0;
	if (pkcs11_getattr_alloc(ctx, session, object, type, &binary, &size))
		return -1;
	/*
	 * @ALON: invalid object,
	 * not sure it will survive the ulValueLen->size_t and keep sign at all platforms
	 */
	if (size == (size_t)-1) {
		CKRerr(CKR_F_PKCS11_GETATTR_BN, CKR_ATTRIBUTE_TYPE_INVALID);
		OPENSSL_free(binary);
		return -1;
	}
	*bn = BN_bin2bn(binary, (int)size, *bn);
	OPENSSL_free(binary);
	return *bn ? 0 : -1;
}

/*
 * Add attributes to template
 */
unsigned int pkcs11_addattr(PKCS11_TEMPLATE *tmpl, int type, void *data, size_t size)
{
	unsigned int n = tmpl->nattr;
	CK_ATTRIBUTE_PTR ap;

	assert(tmpl->nattr < sizeof(tmpl->attrs)/sizeof(tmpl->attrs[0]));
	ap = &tmpl->attrs[tmpl->nattr++];
	ap->type = type;
	ap->pValue = data;
	ap->ulValueLen = size;
	return n;
}

void pkcs11_addattr_bool(PKCS11_TEMPLATE *tmpl, int type, int value)
{
	static CK_BBOOL _true = CK_TRUE;
	static CK_BBOOL _false = CK_FALSE;
	pkcs11_addattr(tmpl, type, value ? &_true : &_false, sizeof(CK_BBOOL));
}

void pkcs11_addattr_s(PKCS11_TEMPLATE *tmpl, int type, const char *s)
{
	pkcs11_addattr(tmpl, type, (void*) s, s ? strlen(s) : 0);
}

void pkcs11_addattr_bn(PKCS11_TEMPLATE *tmpl, int type, const BIGNUM *bn)
{
	int n = BN_num_bytes(bn);
	unsigned char *buf = OPENSSL_malloc(n);
	unsigned int i;

	if (buf && BN_bn2bin(bn, buf) == n) {
		i = pkcs11_addattr(tmpl, type, buf, n);
		tmpl->allocated |= 1<<i;
	}
}

void pkcs11_addattr_obj(PKCS11_TEMPLATE *tmpl, int type, pkcs11_i2d_fn enc, void *obj)
{
	unsigned char *buf, *p;
	unsigned int i;
	size_t n;

	n = enc(obj, NULL);
	buf = p = OPENSSL_malloc(n);
	if (n && p) {
		enc(obj, &p);
		i = pkcs11_addattr(tmpl, type, buf, n);
		tmpl->allocated |= 1<<i;
	}
}

void pkcs11_zap_attrs(PKCS11_TEMPLATE *tmpl)
{
	unsigned int i;

	if (!tmpl->allocated)
		return;
	for (i = 0; i < 32; i++) {
		if (tmpl->allocated & (1<<i))
			OPENSSL_free(tmpl->attrs[i].pValue);
	}
	tmpl->allocated = 0;
	tmpl->nattr = 0;
}

/* vim: set noexpandtab: */
