/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2016-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

static int pkcs11_find_certs(PKCS11_SLOT_private *, PKCS11_TEMPLATE *, CK_SESSION_HANDLE);
static int pkcs11_next_cert(PKCS11_CTX_private *, PKCS11_SLOT_private *, CK_SESSION_HANDLE);
static int pkcs11_init_cert(PKCS11_SLOT_private *token, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE o, PKCS11_CERT **);

/*
 * Enumerate all certs matching with cert_template on the card
 */
int pkcs11_enumerate_certs(PKCS11_SLOT_private *slot, const PKCS11_CERT *cert_template, PKCS11_CERT **certp, unsigned int *countp)
{
	CK_SESSION_HANDLE session;
	int rv;
	PKCS11_TEMPLATE tmpl = {0};
	CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
	pkcs11_addattr_var(&tmpl, CKA_CLASS, object_class);

	if (cert_template) {
		if (cert_template->id_len)
			pkcs11_addattr(&tmpl, CKA_ID, cert_template->id, cert_template->id_len);

		if (cert_template->label)
			pkcs11_addattr_s(&tmpl, CKA_LABEL, cert_template->label);
	}

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = pkcs11_find_certs(slot, &tmpl, session);
	pkcs11_put_session(slot, session);
	if (rv < 0) {
		pkcs11_destroy_certs(slot);
		return -1;
	}

	if (certp)
		*certp = slot->certs;
	if (countp)
		*countp = slot->ncerts;
	return 0;
}

/*
 * Find certificate matching a key
 */
PKCS11_CERT *pkcs11_find_certificate(PKCS11_OBJECT_private *key)
{
	PKCS11_OBJECT_private *cpriv;
	PKCS11_CERT *cert, cert_template = {0};
	unsigned int n, count;

	cert_template.id = key->id;
	cert_template.id_len = key->id_len;
	if (pkcs11_enumerate_certs(key->slot, &cert_template, &cert, &count))
		return NULL;
	for (n = 0; n < count; n++, cert++) {
		cpriv = PRIVCERT(cert);
		if (cpriv->id_len == key->id_len
				&& !memcmp(cpriv->id, key->id, key->id_len))
			return cert;
	}
	return NULL;
}

/*
 * Find all certs of a given type (public or private) and matching template
 */
static int pkcs11_find_certs(PKCS11_SLOT_private *slot, PKCS11_TEMPLATE *tmpl, CK_SESSION_HANDLE session)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(session, tmpl->attrs, tmpl->nattr));
	CRYPTOKI_checkerr(CKR_F_PKCS11_FIND_CERTS, rv);

	do {
		res = pkcs11_next_cert(ctx, slot, session);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_cert(PKCS11_CTX_private *ctx, PKCS11_SLOT_private *slot,
		CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_NEXT_CERT, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_cert(slot, session, obj, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_cert(PKCS11_SLOT_private *slot, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE object, PKCS11_CERT **ret)
{
	PKCS11_OBJECT_private *cpriv;
	PKCS11_CERT *cert, *tmp;
	int i;

	/* Prevent re-adding existing PKCS#11 object handles */
	/* TODO: Rewrite the O(n) algorithm as O(log n),
	 * or it may be too slow with a large number of certificates */
	for (i = 0; i < slot->ncerts; ++i) {
		if (PRIVCERT(&slot->certs[i])->object == object) {
			if (ret)
				*ret = &slot->certs[i];
			return 0;
		}
	}

	cpriv = pkcs11_object_from_handle(slot, session, object);
	if (!cpriv)
		return -1;

	/* Allocate memory */
	tmp = OPENSSL_realloc(slot->certs, (slot->ncerts + 1) * sizeof(PKCS11_CERT));
	if (!tmp) {
		pkcs11_object_free(cpriv);
		return -1;
	}
	slot->certs = tmp;
	cert = slot->certs + slot->ncerts++;
	memset(cert, 0, sizeof(PKCS11_CERT));

	/* Fill public properties */
	cert->id = cpriv->id;
	cert->id_len = cpriv->id_len;
	cert->label = cpriv->label;
	cert->x509 = cpriv->x509;
	cert->_private = cpriv;

	if (ret)
		*ret = cert;
	return 0;
}

/*
 * Destroy all certs
 */
void pkcs11_destroy_certs(PKCS11_SLOT_private *slot)
{
	while (slot->ncerts > 0) {
		PKCS11_CERT *cert = &slot->certs[--slot->ncerts];
		if (cert->_private)
			pkcs11_object_free(PRIVCERT(cert));
	}
	if (slot->certs)
		OPENSSL_free(slot->certs);
	slot->certs = NULL;
	slot->ncerts = 0;
}

/*
 * Store certificate
 */
int pkcs11_store_certificate(PKCS11_SLOT_private *slot, X509 *x509, char *label,
		unsigned char *id, size_t id_len, PKCS11_CERT **ret_cert)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	int rv, r = -1;
	int signature_nid;
	int evp_md_nid = NID_sha1;
	const EVP_MD *evp_md;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	PKCS11_TEMPLATE tmpl = {0};
	CK_OBJECT_CLASS class_certificate = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certificate_x509 = CKC_X_509;
	CK_MECHANISM_TYPE ckm_md;

	/* First, make sure we have a session */
	if (pkcs11_get_session(slot, 1, &session))
		return -1;

	/* Now build the template */
	pkcs11_addattr_var(&tmpl, CKA_CLASS, class_certificate);
	pkcs11_addattr_bool(&tmpl, CKA_TOKEN, TRUE);
	pkcs11_addattr_var(&tmpl, CKA_CERTIFICATE_TYPE, certificate_x509);
	pkcs11_addattr_obj(&tmpl, CKA_SUBJECT,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_subject_name(x509));
	pkcs11_addattr_obj(&tmpl, CKA_ISSUER,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_issuer_name(x509));

	/* Get digest algorithm from x509 certificate */
	/* CKA_NAME_HASH_ALGORITHM was added in Cryptoki 2.30;
	 * older versions of PKCS#11 modules should not touch
	 * this attribute or any other related attributes */
	if (ctx->cryptoki_version.major > 2 ||
		(ctx->cryptoki_version.major == 2 && ctx->cryptoki_version.minor >= 30)) {
		/* Get digest algorithm from x509 certificate */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
		signature_nid = X509_get_signature_nid(x509);
#else
		signature_nid = OBJ_obj2nid(x509->sig_alg->algorithm);
#endif
		OBJ_find_sigid_algs(signature_nid, &evp_md_nid, NULL);
		switch (evp_md_nid) {
		default:
			evp_md_nid = NID_sha1;
			/* fall through */
		case NID_sha1:
			ckm_md = CKM_SHA_1;
			break;
		case NID_sha224:
			ckm_md = CKM_SHA224;
			break;
		case NID_sha256:
			ckm_md = CKM_SHA256;
			break;
		case NID_sha512:
			ckm_md = CKM_SHA512;
			break;
		case NID_sha384:
			ckm_md = CKM_SHA384;
			break;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
		case NID_sha3_224:
			ckm_md = CKM_SHA3_224;
			break;
		case NID_sha3_256:
			ckm_md = CKM_SHA3_256;
			break;
		case NID_sha3_384:
			ckm_md = CKM_SHA3_384;
			break;
		case NID_sha3_512:
			ckm_md = CKM_SHA3_512;
			break;
#endif
		}

		evp_md = EVP_get_digestbynid(evp_md_nid);

		/* Set hash algorithm; default is SHA-1 */
		pkcs11_addattr_var(&tmpl, CKA_NAME_HASH_ALGORITHM, ckm_md);
		if (X509_pubkey_digest(x509, evp_md, md, &md_len))
			pkcs11_addattr(&tmpl, CKA_HASH_OF_SUBJECT_PUBLIC_KEY, md, md_len);
	}

	pkcs11_addattr_obj(&tmpl, CKA_VALUE, (pkcs11_i2d_fn)i2d_X509, x509);
	if (label)
		pkcs11_addattr_s(&tmpl, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(&tmpl, CKA_ID, id, id_len);

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, tmpl.attrs, tmpl.nattr, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(&tmpl);

	/* Gobble the key object */
	if (rv == CKR_OK) {
		r = pkcs11_init_cert(slot, session, object, ret_cert);
	}
	pkcs11_put_session(slot, session);

	CRYPTOKI_checkerr(CKR_F_PKCS11_STORE_CERTIFICATE, rv);
	return r;
}

/* vim: set noexpandtab: */
