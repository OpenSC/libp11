/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2011, 2013 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2014, 2016 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
 * This file implements the handling of EC keys stored on a
 * PKCS11 token
 */

#include "libp11-int.h"
#include <string.h>

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#include <openssl/bn.h>
#endif
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif

#ifndef OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
typedef int (*compute_key_fn)(unsigned char **, size_t *,
	const EC_POINT *, const EC_KEY *);
#else
typedef int (*compute_key_fn)(void *, size_t,
	const EC_POINT *, const EC_KEY *,
	void *(*)(const void *, size_t, void *, size_t *));
#endif
static compute_key_fn ossl_ecdh_compute_key;
static void (*ossl_ec_finish)(EC_KEY *);
static int (*ossl_ec_copy)(EC_KEY *, const EC_KEY *);

static int ec_ex_index = 0;

/********** Missing ECDSA_METHOD functions for OpenSSL < 1.1.0 */

typedef ECDSA_SIG *(*sign_sig_fn)(const unsigned char *, int,
	const BIGNUM *, const BIGNUM *, EC_KEY *);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* ecdsa_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdsa_method {
	char *name;
	sign_sig_fn ecdsa_do_sign;
	void (*ecdsa_sign_setup)();
	void (*ecdsa_do_verify)();
	int flags;
	char *app_data;
};

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

/* Define missing functions */

ECDSA_METHOD *ECDSA_METHOD_new(const ECDSA_METHOD *m)
{
	ECDSA_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDSA_METHOD));
	if (!out)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDSA_METHOD));
	else
		memset(out, 0, sizeof(ECDSA_METHOD));
	return out;
}

void ECDSA_METHOD_free(ECDSA_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDSA_METHOD_set_sign(ECDSA_METHOD *m, sign_sig_fn f)
{
	m->ecdsa_do_sign = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/********** Missing ECDH_METHOD functions for OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

/* ecdh_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdh_method {
	char *name;
	compute_key_fn compute_key;
	int flags;
	char *data;
};

/* Define missing functions */

ECDH_METHOD *ECDH_METHOD_new(const ECDH_METHOD *m)
{
	ECDH_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDH_METHOD));
	if (!out)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDH_METHOD));
	else
		memset(out, 0, sizeof(ECDH_METHOD));
	return out;
}

void ECDH_METHOD_free(ECDH_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDH_METHOD_get_compute_key(ECDH_METHOD *m, compute_key_fn *f)
{
	*f = m->compute_key;
}

void ECDH_METHOD_set_compute_key(ECDH_METHOD *m, compute_key_fn f)
{
	m->compute_key = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/********** Manage EC ex_data */

/* NOTE: ECDH also uses ECDSA ex_data and *not* ECDH ex_data */
static void alloc_ec_ex_index()
{
	if (ec_ex_index == 0) {
		while (ec_ex_index == 0) /* Workaround for OpenSSL RT3710 */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L && !defined(LIBRESSL_VERSION_NUMBER)
			ec_ex_index = EC_KEY_get_ex_new_index(0, "libp11 ec_key",
				NULL, NULL, NULL);
#else
			ec_ex_index = ECDSA_get_ex_new_index(0, "libp11 ecdsa",
				NULL, NULL, NULL);
#endif
		if (ec_ex_index < 0)
			ec_ex_index = 0; /* Fallback to app_data */
	}
}

#if 0
/* TODO: Free the indexes on unload */
static void free_ec_ex_index()
{
	if (ec_ex_index > 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
		/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_ex_index);
#endif
		ec_ex_index = 0;
	}
}
#endif

/********** EVP_PKEY retrieval */

/* Retrieve EC parameters from key into ec
 * return nonzero on error */
static int pkcs11_get_params(EC_KEY *ec, PKCS11_OBJECT_private *key, CK_SESSION_HANDLE session)
{
	CK_BYTE *params;
	size_t params_len = 0;
	const unsigned char *a;
	int rv;

	if (pkcs11_getattr_alloc(key->slot->ctx, session, key->object,
			CKA_EC_PARAMS, &params, &params_len))
		return -1;

	a = params;
	rv = d2i_ECParameters(&ec, &a, (long)params_len) == NULL;
	OPENSSL_free(params);
	return rv;
}

/* Retrieve EC point from x509 certificate into ec
 * return nonzero on error */
static int pkcs11_get_point_x509(EC_KEY *ec, X509 *x509)
{
	EVP_PKEY *pubkey = NULL;
	EC_KEY *pubkey_ec;
	const EC_POINT *point;
	int rv = -1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	pubkey = X509_get0_pubkey(x509);
#else
	pubkey = X509_get_pubkey(x509);
#endif
	if (!pubkey)
		goto error;
	pubkey_ec = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pubkey);
	if (!pubkey_ec)
		goto error;
	point = EC_KEY_get0_public_key(pubkey_ec);
	if (!point)
		goto error;
	if (EC_KEY_set_public_key(ec, point) == 0)
		goto error;
	rv = 0;
error:
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_free(pubkey);
#endif
	return rv;
}

/* Retrieve EC point from key into ec
 * return nonzero on error */
static int pkcs11_get_point(EC_KEY *ec, PKCS11_OBJECT_private *key, CK_SESSION_HANDLE session)
{
	CK_BYTE *point;
	size_t point_len = 0;
	const unsigned char *a;
	ASN1_OCTET_STRING *os;
	int rv = -1;

	if (!key)
		return -1;

	if (key->x509 && pkcs11_get_point_x509(ec, key->x509) == 0)
		return 0;

	if (pkcs11_getattr_alloc(key->slot->ctx, session, key->object,
			CKA_EC_POINT, &point, &point_len))
		return -1;

	/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
	a = point;
	os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)point_len);
	if (os) {
		a = os->data;
		rv = o2i_ECPublicKey(&ec, &a, os->length) == NULL;
		ASN1_STRING_free(os);
	}
	if (rv) { /* Workaround for broken PKCS#11 modules */
		a = point;
		rv = o2i_ECPublicKey(&ec, &a, (long)point_len) == NULL;
	}
	OPENSSL_free(point);
	return rv;
}

static int pkcs11_get_point_associated(EC_KEY *ec, PKCS11_OBJECT_private *key,
	CK_OBJECT_CLASS object_class, CK_SESSION_HANDLE session)
{
	int r;
	PKCS11_OBJECT_private *obj = pkcs11_object_from_object(key, session, object_class);

	if (!obj)
		return -1;
	r = pkcs11_get_point(ec, obj, session);
	pkcs11_object_free(obj);
	return r;
}

static EC_KEY *pkcs11_get_ec(PKCS11_OBJECT_private *key)
{
	PKCS11_SLOT_private *slot = key->slot;
	CK_SESSION_HANDLE session;
	EC_KEY *ec;
	int no_params, no_point;

	ec = EC_KEY_new();
	if (!ec)
		return NULL;

	/* For OpenSSL req we need at least the
	 * EC_KEY_get0_group(ec_key)) to return the group.
	 * Continue even if it fails, as the sign operation does not need
	 * it if the PKCS#11 module or the hardware can figure this out
	 */
	if (pkcs11_get_session(slot, 0, &session)) {
		EC_KEY_free(ec);
		return NULL;
	}
	no_params = pkcs11_get_params(ec, key, session);
	no_point = pkcs11_get_point(ec, key, session);
	if (no_point && key->object_class == CKO_PRIVATE_KEY) /* Retry with the public key */
		no_point = pkcs11_get_point_associated(ec, key, CKO_PUBLIC_KEY, session);
	if (no_point && key->object_class == CKO_PRIVATE_KEY) /* Retry with the certificate */
		no_point = pkcs11_get_point_associated(ec, key, CKO_CERTIFICATE, session);
	pkcs11_put_session(slot, session);

	if (key->object_class == CKO_PRIVATE_KEY && EC_KEY_get0_private_key(ec) == NULL) {
		BIGNUM *bn = BN_new();
		EC_KEY_set_private_key(ec, bn);
		BN_free(bn);
	}

	/* A public keys requires both the params and the point to be present */
	if (key->object_class == CKO_PUBLIC_KEY && (no_params || no_point)) {
		EC_KEY_free(ec);
		return NULL;
	}

	return ec;
}

PKCS11_OBJECT_private *pkcs11_get_ex_data_ec(const EC_KEY *ec)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	return EC_KEY_get_ex_data(ec, ec_ex_index);
#else
	return ECDSA_get_ex_data((EC_KEY *)ec, ec_ex_index);
#endif
}

static void pkcs11_set_ex_data_ec(EC_KEY *ec, PKCS11_OBJECT_private *key)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	EC_KEY_set_ex_data(ec, ec_ex_index, key);
#else
	ECDSA_set_ex_data(ec, ec_ex_index, key);
#endif
}

/*
 * Get EC key material and stash pointer in ex_data
 * Note we get called twice, once for private key, and once for public
 * We need to get the EC_PARAMS and EC_POINT into both,
 * as lib11 dates from RSA only where all the pub key components
 * were also part of the private key.  With EC the point
 * is not in the private key, and the params may or may not be.
 *
 */
static EVP_PKEY *pkcs11_get_evp_key_ec(PKCS11_OBJECT_private *key)
{
	EVP_PKEY *pk;
	EC_KEY *ec;

	ec = pkcs11_get_ec(key);
	if (!ec)
		return NULL;
	pk = EVP_PKEY_new();
	if (!pk) {
		EC_KEY_free(ec);
		return NULL;
	}

	if (key->object_class == CKO_PRIVATE_KEY) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
		ECDH_set_method(ec, PKCS11_get_ecdh_method());
#endif
		/* This creates a new EC_KEY object which requires its own key object reference */
		key = pkcs11_object_ref(key);
		pkcs11_set_ex_data_ec(ec, key);
	}
	/* TODO: Retrieve the ECDSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

	EVP_PKEY_set1_EC_KEY(pk, ec); /* Also increments the ec ref count */
	EC_KEY_free(ec); /* Drops our reference to it */

	return pk;
}

/********** ECDSA signing */

/* Signature size is the issue, will assume the caller has a big buffer! */
/* No padding or other stuff needed.  We can call PKCS11 from here */
static int pkcs11_ecdsa_sign(const unsigned char *msg, unsigned int msg_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_OBJECT_private *key)
{
	int rv;
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG ck_sigsize;

	ck_sigsize = *siglen;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = CRYPTOKI_call(ctx,
		C_SignInit(session, &mechanism, key->object));
	if (!rv && key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(session, (CK_BYTE *)msg, msg_len, sigret, &ck_sigsize));
	pkcs11_put_session(slot, session);

	if (rv) {
		CKRerr(CKR_F_PKCS11_ECDSA_SIGN, rv);
		return -1;
	}
	*siglen = ck_sigsize;

	return ck_sigsize;
}

static void pkcs11_ec_finish(EC_KEY *ec)
{
	PKCS11_OBJECT_private *key;

	key = pkcs11_get_ex_data_ec(ec);
	if (key) {
		pkcs11_set_ex_data_ec(ec, NULL);
		pkcs11_object_free(key);
	}
	if (ossl_ec_finish)
		ossl_ec_finish(ec);
}

/**
 * ECDSA signing method (replaces ossl_ecdsa_sign_sig)
 *
 *  @param  dgst     hash value to sign
 *  @param  dlen     length of the hash value
 *  @param  kinv     precomputed inverse k (from the sign_setup method)
 *  @param  rp       precomputed rp (from the sign_setup method)
 *  @param  ec       private EC signing key
 *  @return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
static ECDSA_SIG *pkcs11_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
		const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *ec)
{
	unsigned char sigret[512]; /* HACK for now */
	ECDSA_SIG *sig;
	PKCS11_OBJECT_private *key;
	unsigned int siglen;
	BIGNUM *r, *s, *order;

	(void)kinv; /* Precomputed values are not used for PKCS#11 */
	(void)rp; /* Precomputed values are not used for PKCS#11 */

	key = pkcs11_get_ex_data_ec(ec);
	if (check_object_fork(key) < 0) {
		sign_sig_fn orig_sign_sig;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
		const EC_KEY_METHOD *meth = EC_KEY_OpenSSL();
		EC_KEY_METHOD_get_sign((EC_KEY_METHOD *)meth,
			NULL, NULL, &orig_sign_sig);
#else
		const ECDSA_METHOD *meth = ECDSA_OpenSSL();
		orig_sign_sig = meth->ecdsa_do_sign;
#endif
		return orig_sign_sig(dgst, dlen, kinv, rp, ec);
	}

	/* Truncate digest if its byte size is longer than needed */
	order = BN_new();
	if (order) {
		const EC_GROUP *group = EC_KEY_get0_group(ec);
		if (group && EC_GROUP_get_order(group, order, NULL)) {
			int klen = BN_num_bits(order);
			if (klen < 8*dlen)
				dlen = (klen+7)/8;
		}
		BN_free(order);
	}

	siglen = sizeof sigret;
	if (pkcs11_ecdsa_sign(dgst, dlen, sigret, &siglen, key) <= 0)
		return NULL;

	r = BN_bin2bn(sigret, siglen/2, NULL);
	s = BN_bin2bn(sigret + siglen/2, siglen/2, NULL);
	sig = ECDSA_SIG_new();
	if (!sig)
		return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
	ECDSA_SIG_set0(sig, r, s);
#else
	BN_free(sig->r);
	sig->r = r;
	BN_free(sig->s);
	sig->s = s;
#endif
	return sig;
}

/********** ECDH key derivation */

static CK_ECDH1_DERIVE_PARAMS *pkcs11_ecdh_params_alloc(
		const EC_GROUP *group, const EC_POINT *point)
{
	CK_ECDH1_DERIVE_PARAMS *parms;
	size_t len;
	unsigned char *buf = NULL;

	if (!group || !point)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (len == 0)
		return NULL;
	buf = OPENSSL_malloc(len);
	if (!buf)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL);
	if (len == 0) {
		OPENSSL_free(buf);
		return NULL;
	}

	parms = OPENSSL_malloc(sizeof(CK_ECDH1_DERIVE_PARAMS));
	if (!parms) {
		OPENSSL_free(buf);
		return NULL;
	}
	parms->kdf = CKD_NULL;
	parms->pSharedData = NULL;
	parms->ulSharedDataLen = 0;
	parms->pPublicData = buf;
	parms->ulPublicDataLen = len;
	return parms;
}

static void pkcs11_ecdh_params_free(CK_ECDH1_DERIVE_PARAMS *parms)
{
	OPENSSL_free(parms->pPublicData);
	OPENSSL_free(parms);
}

/* initial code will only support what is needed for pkcs11_ec_ckey
 * i.e. CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE
 * and CK_EC_KDF_TYPE  supported by token
 * The secret key object is deleted
 *
 * In future CKM_ECMQV_DERIVE with CK_ECMQV_DERIVE_PARAMS
 * could also be supported, and the secret key object could be returned.
 */
static int pkcs11_ecdh_derive(unsigned char **out, size_t *outlen,
		const int key_len,
		const unsigned long ecdh_mechanism,
		const void *ec_params,
		void *outnewkey,
		PKCS11_OBJECT_private *key)
{
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	int rv;

	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_ULONG newkey_len = key_len;
	CK_OBJECT_HANDLE *tmpnewkey = (CK_OBJECT_HANDLE *)outnewkey;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &_false, sizeof(_false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_VALUE_LEN, &newkey_len, sizeof(newkey_len)},
		{CKA_SENSITIVE, &_false, sizeof(_false) },
		{CKA_EXTRACTABLE, &_true, sizeof(_true) },
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_DECRYPT, &_true, sizeof(_true)}
	};

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism  = ecdh_mechanism;
	mechanism.pParameter =  (void*)ec_params;
	switch (ecdh_mechanism) {
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
			mechanism.ulParameterLen  = sizeof(CK_ECDH1_DERIVE_PARAMS);
			break;
#if 0
		/* TODO */
		case CK_ECMQV_DERIVE_PARAMS:
			mechanism.ulParameterLen  = sizeof(CK_ECMQV_DERIVE_PARAMS);
			break;
#endif
		default:
			P11err(P11_F_PKCS11_ECDH_DERIVE, P11_R_NOT_SUPPORTED);
			return -1;
	}

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = CRYPTOKI_call(ctx, C_DeriveKey(session, &mechanism, key->object,
		newkey_template, sizeof(newkey_template)/sizeof(*newkey_template), &newkey));
	if (rv != CKR_OK)
		goto error;

	/* Return the value of the secret key and/or the object handle of the secret key */
	if (out && outlen) { /* pkcs11_ec_ckey only asks for the value */
		if (pkcs11_getattr_alloc(ctx, session, newkey, CKA_VALUE, out, outlen)) {
			CRYPTOKI_call(ctx, C_DestroyObject(session, newkey));
			goto error;
		}
	}
	if (tmpnewkey) /* For future use (not used by pkcs11_ec_ckey) */
		*tmpnewkey = newkey;
	else /* Destroy the temporary key */
		CRYPTOKI_call(ctx, C_DestroyObject(session, newkey));

	pkcs11_put_session(slot, session);

	return 0;
error:
	pkcs11_put_session(slot, session);
	CKRerr(CKR_F_PKCS11_ECDH_DERIVE, rv);
	return -1;
}

static int pkcs11_ecdh_compute_key(unsigned char **buf, size_t *buflen,
		const EC_POINT *peer_point, const EC_KEY *ecdh, PKCS11_OBJECT_private *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(ecdh);
	const int key_len = (EC_GROUP_get_degree(group) + 7) / 8;
	/* both peer and ecdh use same group parameters */
	CK_ECDH1_DERIVE_PARAMS *parms = pkcs11_ecdh_params_alloc(group, peer_point);
	int rv;

	if (!parms)
		return -1;
	rv = pkcs11_ecdh_derive(buf, buflen, key_len, CKM_ECDH1_DERIVE, parms, NULL, key);
	pkcs11_ecdh_params_free(parms);
	return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre4 and later
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @return 1 on success or 0 on error
 */
static int pkcs11_ec_ckey(unsigned char **out, size_t *outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh)
{
	PKCS11_OBJECT_private *key;
	unsigned char *buf = NULL;
	size_t buflen;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_object_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh);
	if (pkcs11_ecdh_compute_key(&buf, &buflen, peer_point, ecdh, key) < 0)
		return 0;
	*out = buf;
	*outlen = buflen;
	return 1;
}

/* Without this, the EC_KEY objects share the same PKCS11_OBJECT_private
 * object in ex_data and when one of them is freed, the following frees
 * result in crashes.
 * We need to increase the reference to the private object.
 */
static int pkcs11_ec_copy(EC_KEY *dest, const EC_KEY *src)
{
	PKCS11_OBJECT_private *srckey = NULL;
	PKCS11_OBJECT_private *destkey = NULL;

	srckey = pkcs11_get_ex_data_ec(src);
	destkey = pkcs11_object_ref(srckey);

	pkcs11_set_ex_data_ec(dest, destkey);

	if (ossl_ec_copy)
		ossl_ec_copy(dest, src);

	return 1;
}

#else

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre3 and earlier
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @param  KCF        key derivation function
 * @return the length of the derived key or -1 if an error occurred
 */
static int pkcs11_ec_ckey(void *out, size_t outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh,
		void *(*KDF)(const void *, size_t, void *, size_t *))
{
	PKCS11_OBJECT_private *key;
	unsigned char *buf = NULL;
	size_t buflen;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_object_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh, KDF);
	if (pkcs11_ecdh_compute_key(&buf, &buflen, peer_point, ecdh, key) < 0)
		return -1;
	if (KDF) {
		if (KDF(buf, buflen, out, &outlen) == NULL) {
			OPENSSL_free(buf);
			return -1;
		}
	} else {
		if (outlen > buflen)
			outlen = buflen;
		memcpy(out, buf, outlen);
	}
	OPENSSL_free(buf);
	return outlen;
}

#endif

/********** Set OpenSSL EC methods */

/*
 * Overload the default OpenSSL methods for ECDSA
 * If OpenSSL supports ECDSA_METHOD_new we will use it.
 * First introduced in 1.0.2, changed in 1.1-pre
 */

/* New way to allocate an ECDSA_METOD object */
/* OpenSSL 1.1 has single method  EC_KEY_METHOD for ECDSA and ECDH */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)

EC_KEY_METHOD *PKCS11_get_ec_key_method(void)
{
	static EC_KEY_METHOD *ops = NULL;
	int (*orig_init)(EC_KEY *);
	int (*orig_set_group)(EC_KEY *, const EC_GROUP *);
	int (*orig_set_private)(EC_KEY *, const BIGNUM *);
	int (*orig_set_public)(EC_KEY *, const EC_POINT *);
	int (*orig_sign)(int, const unsigned char *, int, unsigned char *,
		unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;

	alloc_ec_ex_index();
	if (!ops) {
		ops = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_OpenSSL());
		EC_KEY_METHOD_get_init(ops, &orig_init, &ossl_ec_finish, &ossl_ec_copy,
			&orig_set_group, &orig_set_private, &orig_set_public);
		EC_KEY_METHOD_set_init(ops, orig_init, pkcs11_ec_finish, pkcs11_ec_copy,
			orig_set_group, orig_set_private, orig_set_public);
		EC_KEY_METHOD_get_sign(ops, &orig_sign, NULL, NULL);
		EC_KEY_METHOD_set_sign(ops, orig_sign, NULL, pkcs11_ecdsa_sign_sig);
		EC_KEY_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		EC_KEY_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

/* define old way to keep old engines working without ECDSA */
void *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

void *PKCS11_get_ecdh_method(void)
{
	return NULL;
}

#else /* OPENSSL_VERSION_NUMBER */

/* define new way to keep new engines from crashing with older libp11 */
void *PKCS11_get_ec_key_method(void)
{
	return NULL;
}

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	static ECDSA_METHOD *ops = NULL;

	if (!ops) {
		alloc_ec_ex_index();
		ops = ECDSA_METHOD_new((ECDSA_METHOD *)ECDSA_OpenSSL());
		ECDSA_METHOD_set_sign(ops, pkcs11_ecdsa_sign_sig);
	}
	return ops;
}

ECDH_METHOD *PKCS11_get_ecdh_method(void)
{
	static ECDH_METHOD *ops = NULL;

	if (!ops) {
		alloc_ec_ex_index();
		ops = ECDH_METHOD_new((ECDH_METHOD *)ECDH_OpenSSL());
		ECDH_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		ECDH_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

#endif /* OPENSSL_VERSION_NUMBER */

PKCS11_OBJECT_ops pkcs11_ec_ops = {
	EVP_PKEY_EC,
	pkcs11_get_evp_key_ec,
};

#else /* OPENSSL_NO_EC */

/* if not built with EC or OpenSSL does not support ECDSA
 * add these routines so engine_pkcs11 can be built now and not
 * require further changes */
#warning "ECDSA support not built with libp11"

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

#endif /* OPENSSL_NO_EC */

/* TODO: remove this function in libp11 0.5.0 */
void PKCS11_ecdsa_method_free(void)
{
	/* no op */
}

/* vim: set noexpandtab: */
