/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2011, 2013 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2014, 2016 Douglas E. Engert <deengert@gmail.com>
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
 * This file implements the handling of EC keys stored on a
 * PKCS11 token
 */

#include "libp11-int.h"
#include <string.h>

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif

static int ec_ex_index = 0;

#ifndef OPENSSL_NO_EC

/********** Missing ECDSA_METHOD functions for OpenSSL < 1.0.2 */

#if OPENSSL_VERSION_NUMBER < 0x10002000L

/* ecdsa_method maintains unchanged layout between 0.9.8 and 1.0.1 */

typedef ECDSA_SIG *(*sign_fn)(const unsigned char *, int,
	const BIGNUM *, const BIGNUM *, EC_KEY *);
typedef int (*sign_setup_fn)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdsa_method {
	char *name;
	sign_fn sign;
	sign_setup_fn sign_setup;
	void (*verify)();
	int flags;
	char *data;
};

/* Define missing functions */

ECDSA_METHOD *ECDSA_METHOD_new(const ECDSA_METHOD *m)
{
	ECDSA_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDSA_METHOD));
	if (out == NULL)
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

void ECDSA_METHOD_set_sign(ECDSA_METHOD *m, sign_fn f)
{
	m->sign = f;
}

void ECDSA_METHOD_set_sign_setup(ECDSA_METHOD *m, sign_setup_fn f)
{
	m->sign_setup = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/********** Missing ECDH_METHOD functions for OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* ecdh_method maintains unchanged layout between 0.9.8 and 1.0.2 */

typedef int (*compute_key_fn)(void *, size_t, const EC_POINT *, const EC_KEY *,
	void *(*)(const void *, size_t, void *, size_t *));

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
	if (out == NULL)
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

void ECDH_METHOD_set_compute_key(ECDH_METHOD *m, compute_key_fn f)
{
	m->compute_key = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/********** ECDSA signature */

/* Signature size is the issue, will assume the caller has a big buffer! */
/* No padding or other stuff needed.  We can call PKCS11 from here */
int
pkcs11_ecdsa_sign(const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key)
{
	int rv;
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG ck_sigsize;

	ck_sigsize = *siglen;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	rv = CRYPTOKI_call(ctx, C_SignInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *) m, m_len, sigret, &ck_sigsize));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_EC_KEY_SIGN, pkcs11_map_err(rv));
		return -1;
	}
	*siglen = ck_sigsize;

	return ck_sigsize;
}

/********** EVP_PKEY retrieval */

/*
 * Get EC key material and stash pointer in ex_data
 * Note we get called twice, once for private key, and once for public
 * We need to get the EC_PARAMS and EC_POINT into both,
 * as lib11 dates from RSA only where all the pub key components
 * were also part of the private key.  With EC the point
 * is not in the private key, and the params may or may not be.
 *
 */
static EVP_PKEY *pkcs11_get_evp_key_ec(PKCS11_KEY * key)
{
	EVP_PKEY *pk;
	EC_KEY * ec = NULL;
	CK_RV ckrv;
	size_t ec_paramslen = 0;
	CK_BYTE * ec_params = NULL;
	size_t ec_pointlen = 0;
	CK_BYTE * ec_point = NULL;
	PKCS11_KEY * pubkey;
	ASN1_OCTET_STRING *os=NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return NULL;

	ec = EC_KEY_new();
	if (ec == NULL) {
		EVP_PKEY_free(pk);
		return NULL;
	}
	EVP_PKEY_set1_EC_KEY(pk, ec); /* Also increments the ec ref count */

	/* For Openssl req we need at least the
	 * EC_KEY_get0_group(ec_key)) to return the group.
	 * Even if it fails will continue as a sign only does not need
	 * need this if the pkcs11 or card can figure this out.
	 */

	if (key_getattr_var(key, CKA_EC_PARAMS, NULL, &ec_paramslen) == CKR_OK &&
			ec_paramslen > 0) {
		ec_params = OPENSSL_malloc(ec_paramslen);
		if (ec_params) {
			ckrv = key_getattr_var(key, CKA_EC_PARAMS, ec_params, &ec_paramslen);
			if (ckrv == CKR_OK) {
				const unsigned char * a = ec_params;
				/* convert to OpenSSL parmas */
				d2i_ECParameters(&ec, &a, (long) ec_paramslen);
			}
		}
	}

	/* Now get the ec_point */
	pubkey = key->isPrivate ? pkcs11_find_key_from_key(key) : key;
	if (pubkey) {
		ckrv = key_getattr_var(pubkey, CKA_EC_POINT, NULL, &ec_pointlen);
		if (ckrv == CKR_OK && ec_pointlen > 0) {
			ec_point = OPENSSL_malloc(ec_pointlen);
			if (ec_point) {
				ckrv = key_getattr_var(pubkey, CKA_EC_POINT, ec_point, &ec_pointlen);
				if (ckrv == CKR_OK) {
					/* PKCS#11 returns ASN1 octstring*/
					const unsigned char * a;
					/* we have asn1 octet string, need to strip off 04 len */

					a = ec_point;
					os = d2i_ASN1_OCTET_STRING(NULL, &a, (long) ec_pointlen);
					if (os) {
						a = os->data;
						o2i_ECPublicKey(&ec, &a, os->length);
					}
/* EC_KEY_print_fp(stderr, ec, 5); */
				}
			}
		}
	}

	/* If the key is not extractable, create a key object
	 * that will use the card's functions to sign & decrypt
	 */
	if (os)
		ASN1_STRING_free(os);
	if (ec_point)
		OPENSSL_free(ec_point);
	if (ec_params)
		OPENSSL_free(ec_params);

	if (key->isPrivate) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
		ECDH_set_method(ec, PKCS11_get_ecdh_method());
#endif
	}
	/* TODO: Retrieve the ECDSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EC_KEY_set_ex_data(ec, ec_ex_index, key);
#else
	ECDSA_set_ex_data(ec, ec_ex_index, key);
#endif
	EC_KEY_free(ec); /* drops our reference to it */
	return pk;
}

/* TODO Looks like this is never called */
static int pkcs11_ecdsa_sign_setup(EC_KEY *ec, BN_CTX *ctx_in,
	BIGNUM **kinvp, BIGNUM **rp) {

	if (*kinvp != NULL)
		BN_clear_free(*kinvp);
	*kinvp = BN_new();

	if (*rp != NULL)
		BN_clear_free(*rp);
	*rp = BN_new();
	return 1;
}

static ECDSA_SIG * pkcs11_ecdsa_do_sign(const unsigned char *dgst, int dlen,
			const BIGNUM *inv, const BIGNUM *r, EC_KEY * ec)
{
	unsigned char sigret[512]; /* HACK for now */
	ECDSA_SIG * sig = NULL;
	PKCS11_KEY * key = NULL;
	unsigned int siglen;
	int nLen = 48; /* HACK */
	int rv;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	key = (PKCS11_KEY *) EC_KEY_get_ex_data(ec, ec_ex_index);
#else
	key = (PKCS11_KEY *) ECDSA_get_ex_data(ec, ec_ex_index);
#endif
	if (key == NULL)
		return NULL;

	siglen = sizeof(sigret);

	rv = pkcs11_ecdsa_sign(dgst, dlen, sigret, &siglen, key);
	nLen = siglen / 2;
	if (rv > 0) {
		sig = ECDSA_SIG_new();
		if (sig) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/*
		 * OpenSSL 1.1 does not have a way to allocate r and s
		 * in ECDSA_SIG as it is now hidden.
		 * Will us dummy ASN1 so r and s are allocated then
		 * use ECDSA_SIG_get0 to get access to r and s
		 * can then update r annd s
		 */
			const unsigned char *a;
			unsigned char dasn1[8] =
				{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00};
			BIGNUM *r;
			BIGNUM *s;
			a = dasn1;
			d2i_ECDSA_SIG(&sig, &a, 8);
			ECDSA_SIG_get0(&r, &s, sig);
			BN_bin2bn(&sigret[0], nLen, r);
			BN_bin2bn(&sigret[nLen], nLen, s);
#else
			BN_bin2bn(&sigret[0], nLen, sig->r);
			BN_bin2bn(&sigret[nLen], nLen, sig->s);
#endif
		}
	}
	return sig;
}

/********** Key derivation */

/* initial code will only support what is needed for pkcs11_ec_ckey
 * i.e. CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE
 * and CK_EC_KDF_TYPE  supported by token
 * The secret key object is deleted
 *
 * In future CKM_ECMQV_DERIVE with CK_ECMQV_DERIVE_PARAMS
 * could also be supported, and the secret key object could be returned.
 */
static int pkcs11_ecdh_derive_internal(unsigned char **out, size_t *outlen,
		const unsigned long ecdh_mechanism,
		const void * ec_params,
		void *outnewkey,
		PKCS11_KEY * key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_TOKEN *token = KEY2TOKEN(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;
	int ret = -1;
	unsigned char * buf = NULL;
	size_t buflen;

	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE * tmpnewkey = (CK_OBJECT_HANDLE *)outnewkey;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)}
	};

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism  = ecdh_mechanism;
	mechanism.pParameter =  (void*)ec_params;
	switch (ecdh_mechanism) {
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
			mechanism.ulParameterLen  = sizeof(CK_ECDH1_DERIVE_PARAMS);
			break;
//		case CK_ECMQV_DERIVE_PARAMS:
//			mechanism.ulParameterLen  = sizeof(CK_ECMQV_DERIVE_PARAMS);
//			break;
		default:
			PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY, PKCS11_NOT_SUPPORTED);
			goto err;
	}

	rv = CRYPTOKI_call(ctx, C_DeriveKey(spriv->session, &mechanism, kpriv->object, newkey_template, 5, &newkey));
	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY, pkcs11_map_err(rv));
		goto err;
	}

	/* Return the value of the secret key and/or the object handle of the secret key */

	/* pkcs11_ec_ckey only asks for the value */

	if (out && outlen) {
		/* get size of secret key value */
		if (!pkcs11_getattr_var(token, newkey, CKA_VALUE, NULL, &buflen)
			&& buflen > 0) {
			buf = OPENSSL_malloc(buflen);
			if (buf == NULL) {
				PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY,
					pkcs11_map_err(CKR_HOST_MEMORY));
				goto err;
			}
		} else {
			PKCS11err(PKCS11_F_PKCS11_EC_KEY_COMPUTE_KEY,
				pkcs11_map_err(CKR_ATTRIBUTE_VALUE_INVALID));
			goto err;
		}

		pkcs11_getattr_var(token, newkey, CKA_VALUE, buf, &buflen);
		*out = buf;
		*outlen = buflen;
		buf = NULL;
	}

	/* not used by pkcs11_ec_ckey for future use */
	if (tmpnewkey) {
		*tmpnewkey = newkey;
		newkey = CK_INVALID_HANDLE;
	}

	ret = 1;
err:
	if (buf)
		OPENSSL_free(buf);
	if (newkey != CK_INVALID_HANDLE && spriv->session != CK_INVALID_HANDLE)
		CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));

	return ret;
}

/* Our version of the ossl_ecdh_compute_key replaced in the EC_KEY_METHOD */
static int pkcs11_ec_ckey(void *out,
		size_t outlen,
		const EC_POINT *ecpointpeer,
		const EC_KEY *ecdh,
		void *(*KDF) (const void *in,
			size_t inlen,
			void *out,
			size_t *outlen))
{
	int ret = -1;
	size_t buflen;
	unsigned char *buf = NULL;
	size_t peerbuflen;
	unsigned char *peerbuf = NULL;
	const EC_GROUP *ecgroup = NULL;
	CK_ECDH1_DERIVE_PARAMS ecdh_parms;
	PKCS11_KEY * key = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	key = (PKCS11_KEY *) EC_KEY_get_ex_data(ecdh, ec_ex_index);
#else
	key = (PKCS11_KEY *) ECDSA_get_ex_data((EC_KEY *)ecdh, ec_ex_index);
#endif

	if (key == NULL) {
		ret = -1;
		goto err;
	}

	/* both peer and ecdh use same group parameters */
	ecgroup = EC_KEY_get0_group(ecdh);
	buflen = (EC_GROUP_get_degree(ecgroup) + 7) / 8;

	peerbuflen = 2*buflen + 1;
	peerbuf = OPENSSL_malloc(peerbuflen);
	if (peerbuf == NULL) {
		ret = -1;
		goto err;
	}

	ecdh_parms.kdf = CKD_NULL;
	ecdh_parms.ulSharedDataLen = 0;
	ecdh_parms.pSharedData = NULL;
	ecdh_parms.ulPublicDataLen = peerbuflen;
	ret = EC_POINT_point2oct(ecgroup,
			ecpointpeer,
			POINT_CONVERSION_UNCOMPRESSED,
			peerbuf, peerbuflen,NULL);
	ecdh_parms.ulPublicDataLen = peerbuflen;
	ecdh_parms.pPublicData = peerbuf;

	ret = pkcs11_ecdh_derive_internal(&buf, &buflen, CKM_ECDH1_DERIVE,
		(const void *)&ecdh_parms, NULL, key);

	if (KDF != 0) {
		if (KDF(buf, buflen, out, &outlen) == NULL) {
			ret = -1;
			goto err;
		}
		ret = outlen;
	} else {
		if (outlen > buflen)
			outlen = buflen;
		memcpy(out, buf, outlen);
		ret = outlen;
	}
err:
	OPENSSL_free(buf);
	return (ret);
}

/********** OpenSSL EC methods */

static void alloc_ec_ex_index()
{
	if (ec_ex_index == 0) {
		while (ec_ex_index == 0) /* Workaround for OpenSSL RT3710 */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
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

/*
 * Overload the default OpenSSL methods for ECDSA
 * If OpenSSL supports ECDSA_METHOD_new we will use it.
 * First introduced in 1.0.2, changed in 1.1-pre
 */

/* New way to allocate an ECDSA_METOD object */
/* OpenSSL 1.1 has single method  EC_KEY_METHOD for ECDSA and ECDH */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

EC_KEY_METHOD *PKCS11_get_ec_key_method(void)
{
	static EC_KEY_METHOD *ops = NULL;

	int (*orig_sign)(int type, const unsigned char *dgst,
		int dlen, unsigned char *sig,
		unsigned int *siglen,
		const BIGNUM *kinv, const BIGNUM *r,
		EC_KEY *eckey) = NULL;
	int (*orig_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
		BIGNUM **kinvp, BIGNUM **rp) = NULL;
	ECDSA_SIG *(*orig_sign_sig)(const unsigned char *dgst,
		int dgst_len,
		const BIGNUM *in_kinv,
		const BIGNUM *in_r,
		EC_KEY *eckey) = NULL;

	alloc_ec_ex_index();
	if (ops == NULL) {
		ops = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_OpenSSL());

		EC_KEY_METHOD_get_sign(ops, &orig_sign,
			&orig_sign_setup, &orig_sign_sig);

		EC_KEY_METHOD_set_sign(ops, orig_sign,
			pkcs11_ecdsa_sign_setup,
			pkcs11_ecdsa_do_sign);

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

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDSA_METHOD_new((ECDSA_METHOD *)ECDSA_OpenSSL());
		ECDSA_METHOD_set_sign(ops, pkcs11_ecdsa_do_sign);
		ECDSA_METHOD_set_sign_setup(ops, pkcs11_ecdsa_sign_setup);
	}
	return ops;
}

ECDH_METHOD *PKCS11_get_ecdh_method(void)
{
	static ECDH_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDH_METHOD_new((ECDH_METHOD *)ECDH_OpenSSL());
		ECDH_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

#endif /* OPENSSL_VERSION_NUMBER */

PKCS11_KEY_ops pkcs11_ec_ops_s = {
	EVP_PKEY_EC,
	pkcs11_get_evp_key_ec
};
PKCS11_KEY_ops *pkcs11_ec_ops = {&pkcs11_ec_ops_s};

#else /* OPENSSL_NO_EC */

PKCS11_KEY_ops *pkcs11_ec_ops = {NULL};

/* if not built with EC or OpenSSL does not support ECDSA
 * add these routines so engine_pkcs11 can be built now and not
 * require further changes */
#warning "ECDSA support not built with libp11"

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

void PKCS11_ecdsa_method_free(void)
{
	/* no op, as it is static in the old code */
}

#endif /* OPENSSL_NO_EC */

/* vim: set noexpandtab: */
