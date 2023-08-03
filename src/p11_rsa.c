/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2016-2017 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
 * This file implements the handling of RSA keys stored on a
 * PKCS11 token
 */

#include "libp11-int.h"
#include <string.h>
#include <openssl/rsa.h>

static int rsa_ex_index = 0;

static RSA *pkcs11_rsa(PKCS11_OBJECT_private *key)
{
	EVP_PKEY *evp_key = pkcs11_get_key(key, key->object_class);
	RSA *rsa;
	if (!evp_key)
		return NULL;
	rsa = (RSA *)EVP_PKEY_get0_RSA(evp_key);
	/* Danger: this assumes evp_key returned above has at least reference
	 * count of 2. Which is true in current code as long as key->object_class
	 * is used for the object_class. */
	EVP_PKEY_free(evp_key);
	return rsa;
}

/* PKCS#1 v1.5 RSA signature */
/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_OBJECT_private *key)
{
	RSA *rsa = pkcs11_rsa(key);
	if (!rsa)
		return -1;
	return RSA_sign(type, m, m_len, sigret, siglen, rsa);
}

/* Setup PKCS#11 mechanisms for encryption/decryption */
static int pkcs11_mechanism(CK_MECHANISM *mechanism, const int padding)
{
	memset(mechanism, 0, sizeof(CK_MECHANISM));
	switch (padding) {
	case RSA_PKCS1_PADDING:
		mechanism->mechanism = CKM_RSA_PKCS;
		break;
	case RSA_PKCS1_OAEP_PADDING:
		mechanism->mechanism = CKM_RSA_PKCS_OAEP;
		break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		break;
	case RSA_X931_PADDING:
		mechanism->mechanism = CKM_RSA_X9_31;
		break;
	default:
		P11err(P11_F_PKCS11_MECHANISM, P11_R_UNSUPPORTED_PADDING_TYPE);
		return -1;
	}
	return 0;
}

static void
pkcs11_oaep_param(CK_MECHANISM *mechanism, CK_RSA_PKCS_OAEP_PARAMS *oaep_params)
{
	/* Openssl API for RSA_private_decrypt() allows to use
	 * RSA_PKCS1_OAEP_PADDING nly with SHA_1 hash and and MGF1_SHA1 mask
	 * gen function.  It is not possible to use RFC8017 "Label" or
	 * PKCS#11 "source data" respectively.
	 * https://www.openssl.org/docs/man3.0/man3/RSA_private_decrypt.html */

	mechanism->pParameter = oaep_params;
	mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
	oaep_params->mgf = CKG_MGF1_SHA1;
	oaep_params->hashAlg = CKM_SHA_1;
	oaep_params->source = 0;
	oaep_params->pSourceData = NULL;
	oaep_params->ulSourceDataLen = 0;
}
/* RSA private key encryption (also invoked by OpenSSL for signing) */
/* OpenSSL assumes that the output buffer is always big enough */
int pkcs11_private_encrypt(int flen,
		const unsigned char *from, unsigned char *to,
		PKCS11_OBJECT_private *key, int padding)
{
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_MECHANISM mechanism;
	CK_ULONG size;
	CK_SESSION_HANDLE session;
	int rv;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	size = pkcs11_get_key_size(key);

	if (pkcs11_mechanism(&mechanism, padding) < 0)
		return -1;

	if (mechanism.mechanism == CKM_RSA_PKCS_OAEP)
		pkcs11_oaep_param(&mechanism, &oaep_params);

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	/* Try signing first, as applications are more likely to use it */
	rv = CRYPTOKI_call(ctx,
		C_SignInit(session, &mechanism, key->object));
	if (!rv && key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(session, (CK_BYTE *)from, flen, to, &size));
	if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
		/* OpenSSL may use it for encryption rather than signing */
		rv = CRYPTOKI_call(ctx,
			C_EncryptInit(session, &mechanism, key->object));
		if (!rv && key->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key, session);
		if (!rv)
			rv = CRYPTOKI_call(ctx,
				C_Encrypt(session, (CK_BYTE *)from, flen, to, &size));
	}
	pkcs11_put_session(slot, session);

	if (rv) {
		CKRerr(CKR_F_PKCS11_PRIVATE_ENCRYPT, rv);
		return -1;
	}

	return size;
}

/* RSA private key decryption */
int pkcs11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_OBJECT_private *key, int padding)
{
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG size = flen;
	CK_RV rv;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	if (pkcs11_mechanism(&mechanism, padding) < 0)
		return -1;

	if (mechanism.mechanism == CKM_RSA_PKCS_OAEP)
		pkcs11_oaep_param(&mechanism, &oaep_params);

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = CRYPTOKI_call(ctx,
		C_DecryptInit(session, &mechanism, key->object));
	if (!rv && key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Decrypt(session, (CK_BYTE *)from, size,
				(CK_BYTE_PTR)to, &size));
	pkcs11_put_session(slot, session);

	if (rv) {
		CKRerr(CKR_F_PKCS11_PRIVATE_DECRYPT, rv);
		return -1;
	}

	return size;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_OBJECT_private *key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	P11err(P11_F_PKCS11_VERIFY, P11_R_NOT_SUPPORTED);
	return -1;
}

/*
 * Get RSA key material
 */
static RSA *pkcs11_get_rsa(PKCS11_OBJECT_private *key)
{
	CK_OBJECT_CLASS class_public_key = CKO_PUBLIC_KEY;
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	PKCS11_OBJECT_private *pubkey;
	PKCS11_TEMPLATE tmpl = {0};
	CK_OBJECT_HANDLE object = key->object;
	CK_SESSION_HANDLE session;
	RSA *rsa;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	if (pkcs11_get_session(slot, 0, &session))
		return NULL;

	/* Retrieve the modulus */
	if (pkcs11_getattr_bn(ctx, session, object, CKA_MODULUS, &rsa_n))
		goto failure;

	/* Retrieve the public exponent */
	if (!pkcs11_getattr_bn(ctx, session, object, CKA_PUBLIC_EXPONENT, &rsa_e)) {
		if (!BN_is_zero(rsa_e)) /* A valid public exponent */
			goto success;
		BN_clear_free(rsa_e);
		rsa_e = NULL;
	}

	/* The public exponent was not found in the private key:
	 * retrieve it from the corresponding public key */
	pkcs11_addattr_var(&tmpl, CKA_CLASS, class_public_key);
	pkcs11_addattr_bn(&tmpl, CKA_MODULUS, rsa_n);
	pubkey = pkcs11_object_from_template(slot, session, &tmpl);
	if (pubkey && !pkcs11_getattr_bn(ctx, session, pubkey->object,
			CKA_PUBLIC_EXPONENT, &rsa_e)) {
		pkcs11_object_free(pubkey);
		goto success;
	}
	pkcs11_object_free(pubkey);

	/* Last resort: use the most common default */
	rsa_e = BN_new();
	if (rsa_e && BN_set_word(rsa_e, RSA_F4))
		goto success;

failure:
	pkcs11_put_session(slot, session);
	if (rsa_n)
		BN_clear_free(rsa_n);
	if (rsa_e)
		BN_clear_free(rsa_e);
	return NULL;

success:
	pkcs11_put_session(slot, session);
	rsa = RSA_new();
	if (!rsa)
		goto failure;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
	RSA_set0_key(rsa, rsa_n, rsa_e, NULL);
#else
	rsa->n = rsa_n;
	rsa->e = rsa_e;
#endif
	return rsa;
}

PKCS11_OBJECT_private *pkcs11_get_ex_data_rsa(const RSA *rsa)
{
	return RSA_get_ex_data(rsa, rsa_ex_index);
}

static void pkcs11_set_ex_data_rsa(RSA *rsa, PKCS11_OBJECT_private *key)
{
	RSA_set_ex_data(rsa, rsa_ex_index, key);
}

/*
 * Build an EVP_PKEY object
 */
static EVP_PKEY *pkcs11_get_evp_key_rsa(PKCS11_OBJECT_private *key)
{
	EVP_PKEY *pk;
	RSA *rsa;

	rsa = pkcs11_get_rsa(key);
	if (!rsa)
		return NULL;
	pk = EVP_PKEY_new();
	if (!pk) {
		RSA_free(rsa);
		return NULL;
	}
	if (key->object_class == CKO_PRIVATE_KEY) {
		RSA_set_method(rsa, PKCS11_get_rsa_method());
#if OPENSSL_VERSION_NUMBER >= 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
		RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
#else
		rsa->flags |= RSA_FLAG_EXT_PKEY;
#endif
	}
	/* TODO: Retrieve the RSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

#if OPENSSL_VERSION_NUMBER < 0x01010000L
	/* RSA_FLAG_SIGN_VER is no longer needed since OpenSSL 1.1 */
	rsa->flags |= RSA_FLAG_SIGN_VER;
#endif
	pkcs11_set_ex_data_rsa(rsa, key);

	EVP_PKEY_set1_RSA(pk, rsa); /* Also increments the rsa ref count */
	RSA_free(rsa); /* Drops our reference to it */
	return pk;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_get_key_modulus(PKCS11_OBJECT_private *key, BIGNUM **bn)
{
	RSA *rsa = pkcs11_rsa(key);
	const BIGNUM *rsa_n;

	if (!rsa)
		return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
	RSA_get0_key(rsa, &rsa_n, NULL, NULL);
#else
	rsa_n=rsa->n;
#endif
	*bn = BN_dup(rsa_n);
	return *bn == NULL ? 0 : 1;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_get_key_exponent(PKCS11_OBJECT_private *key, BIGNUM **bn)
{
	RSA *rsa = pkcs11_rsa(key);
	const BIGNUM *rsa_e;

	if (!rsa)
		return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
	RSA_get0_key(rsa, NULL, &rsa_e, NULL);
#else
	rsa_e=rsa->e;
#endif
	*bn = BN_dup(rsa_e);
	return *bn == NULL ? 0 : 1;
}

/* TODO: make this function static in libp11 0.5.0 */
int pkcs11_get_key_size(PKCS11_OBJECT_private *key)
{
	RSA *rsa = pkcs11_rsa(key);
	if (!rsa)
		return 0;
	return RSA_size(rsa);
}

#if ( ( defined (OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100005L ) || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3020199L ) )

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
		(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_enc;
}

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
		(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_dec;
}

static int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa)
{
    return meth->finish;
}

#endif

static int pkcs11_rsa_priv_dec_method(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_rsa(rsa);
	int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	if (check_object_fork(key) < 0) {
		priv_dec = RSA_meth_get_priv_dec(RSA_get_default_method());
		return priv_dec(flen, from, to, rsa, padding);
	}
	return pkcs11_private_decrypt(flen, from, to, key, padding);
}

static int pkcs11_rsa_priv_enc_method(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_rsa(rsa);
	int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	if (check_object_fork(key) < 0) {
		priv_enc = RSA_meth_get_priv_enc(RSA_get_default_method());
		return priv_enc(flen, from, to, rsa, padding);
	}
	return pkcs11_private_encrypt(flen, from, to, key, padding);
}

static int pkcs11_rsa_free_method(RSA *rsa)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_rsa(rsa);
	if (key) {
		pkcs11_set_ex_data_rsa(rsa, NULL);
		pkcs11_object_free(key);
	}
	int (*orig_rsa_free_method)(RSA *rsa) =
		RSA_meth_get_finish(RSA_get_default_method());
	if (orig_rsa_free_method) {
		return orig_rsa_free_method(rsa);
	}
	return 1;
}

static void alloc_rsa_ex_index()
{
	if (rsa_ex_index == 0) {
		while (rsa_ex_index == 0) /* Workaround for OpenSSL RT3710 */
			rsa_ex_index = RSA_get_ex_new_index(0, "libp11 rsa",
				NULL, NULL, NULL);
		if (rsa_ex_index < 0)
			rsa_ex_index = 0; /* Fallback to app_data */
	}
}

static void free_rsa_ex_index()
{
	/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
#if OPENSSL_VERSION_NUMBER >= 0x10100001L && !defined(LIBRESSL_VERSION_NUMBER)
	if (rsa_ex_index > 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_ex_index);
		rsa_ex_index = 0;
	}
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2080000L )

static RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)
{
	RSA_METHOD *ret = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (!ret)
		return NULL;
	memcpy(ret, meth, sizeof(RSA_METHOD));
	ret->name = OPENSSL_strdup(meth->name);
	if (!ret->name) {
		OPENSSL_free(ret);
		return NULL;
	}
	return ret;
}

static int RSA_meth_set1_name(RSA_METHOD *meth, const char *name)
{
	char *tmp = OPENSSL_strdup(name);
	if (!tmp)
		return 0;
	OPENSSL_free((char *)meth->name);
	meth->name = tmp;
	return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3000000L )

static int RSA_meth_set_flags(RSA_METHOD *meth, int flags)
{
	meth->flags = flags;
	return 1;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100005L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2080000L )

static int RSA_meth_set_priv_enc(RSA_METHOD *meth,
		int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_enc = priv_enc;
	return 1;
}

static int RSA_meth_set_priv_dec(RSA_METHOD *meth,
		int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_dec = priv_dec;
	return 1;
}

static int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish)(RSA *rsa))
{
	meth->finish = finish;
	return 1;
}

#endif

/*
 * Overload the default OpenSSL methods for RSA
 */
RSA_METHOD *PKCS11_get_rsa_method(void)
{
	static RSA_METHOD *ops = NULL;

	if (!ops) {
		alloc_rsa_ex_index();
		ops = RSA_meth_dup(RSA_get_default_method());
		if (!ops)
			return NULL;
		RSA_meth_set1_name(ops, "libp11 RSA method");
		RSA_meth_set_flags(ops, 0);
		RSA_meth_set_priv_enc(ops, pkcs11_rsa_priv_enc_method);
		RSA_meth_set_priv_dec(ops, pkcs11_rsa_priv_dec_method);
		RSA_meth_set_finish(ops, pkcs11_rsa_free_method);
	}
	return ops;
}

/* This function is *not* currently exported */
void PKCS11_rsa_method_free(void)
{
	free_rsa_ex_index();
}

PKCS11_OBJECT_ops pkcs11_rsa_ops = {
	EVP_PKEY_RSA,
	pkcs11_get_evp_key_rsa,
};

/* vim: set noexpandtab: */
