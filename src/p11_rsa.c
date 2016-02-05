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
 * This file implements the handling of RSA keys stored on a
 * PKCS11 token
 */

#include "libp11-int.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static int rsa_ex_index = 0;

int
pkcs11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key)
{
	int rv, ssl = ((type == NID_md5_sha1) ? 1 : 0);
	unsigned char *encoded = NULL;
	int sigsize;

	sigsize = pkcs11_get_key_size(key);

	if (ssl) {
		if ((m_len != 36) /* SHA1 + MD5 */ ||
				((m_len + RSA_PKCS1_PADDING_SIZE) > (unsigned)sigsize)) {
			return 0; /* the size is wrong */
		}
	} else {
		ASN1_TYPE parameter = { V_ASN1_NULL, { NULL } };
 		ASN1_STRING digest = { m_len, V_ASN1_OCTET_STRING, (unsigned char *)m, 0 };
		X509_ALGOR algor = { NULL, &parameter };
		X509_SIG digest_info = { &algor, &digest };
		int size;
		/* Fetch the OID of the algorithm used */
		if ((algor.algorithm = OBJ_nid2obj(type)) &&
				(algor.algorithm) &&
				/* Get the size of the encoded DigestInfo */
				(size = i2d_X509_SIG(&digest_info, NULL)) &&
				/* Check that size is compatible with PKCS#11 padding */
				(size + RSA_PKCS1_PADDING_SIZE <= sigsize) &&
				(encoded = OPENSSL_malloc(sigsize))) {
			unsigned char *tmp = encoded;
			/* Actually do the encoding */
			i2d_X509_SIG(&digest_info,&tmp);
			m = encoded;
			m_len = size;
		} else {
			return 0;
		}
	}

	rv = pkcs11_private_encrypt(m_len, m, sigret, key, RSA_PKCS1_PADDING);

	if (rv <= 0)
		rv = 0;
	else {
		*siglen = rv;
		rv = 1;
	}

	if (encoded != NULL)  /* NULL on SSL case */
		OPENSSL_free(encoded);

	return rv;
}

int
pkcs11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY * key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;
	int sigsize;
	CK_ULONG ck_sigsize;

	sigsize = pkcs11_get_key_size(key);
	ck_sigsize = sigsize;

	memset(&mechanism, 0, sizeof(mechanism));

	switch (padding) {
		case RSA_NO_PADDING:
			mechanism.mechanism = CKM_RSA_X_509;
			break;
		case RSA_PKCS1_PADDING:
			if ((flen + RSA_PKCS1_PADDING_SIZE) > sigsize) {
				return -1; /* the size is wrong */
			}
			mechanism.mechanism = CKM_RSA_PKCS;
			break;
		default:
			printf("pkcs11 engine: only RSA_NO_PADDING or RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	/* API is somewhat fishy here. *siglen is 0 on entry (cleared
	 * by OpenSSL). The library assumes that the memory passed
	 * by the caller is always big enough */
	rv = CRYPTOKI_call(ctx, C_SignInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *) from, flen, to, &ck_sigsize));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, pkcs11_map_err(rv));
		return -1;
	}

	if ((unsigned)sigsize != ck_sigsize)
		return -1;

	return sigsize;
}

int
pkcs11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY * key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG size = flen;
	CK_RV rv;

	if (padding != RSA_PKCS1_PADDING) {
			printf("pkcs11 engine: only RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	pkcs11_w_lock(PRIVSLOT(slot)->lockid);
	rv = CRYPTOKI_call(ctx, C_DecryptInit(spriv->session, &mechanism, kpriv->object)) ||
		CRYPTOKI_call(ctx,
			C_Decrypt(spriv->session, (CK_BYTE *) from, (CK_ULONG)flen,
				(CK_BYTE_PTR)to, &size));
	pkcs11_w_unlock(PRIVSLOT(slot)->lockid);

	if (rv)
		PKCS11err(PKCS11_F_PKCS11_RSA_DECRYPT, pkcs11_map_err(rv));

	return rv ? 0 : size;
}

int
pkcs11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_KEY * key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
	return -1;
}

/*
 * Get RSA key material
 */
static RSA *pkcs11_get_rsa(PKCS11_KEY * key)
{
	RSA *rsa;
	PKCS11_KEY *keys = NULL;
	unsigned int i, count = 0;

	rsa = RSA_new();
	if (rsa == NULL)
		return NULL;

	/* Retrieve the modulus and the public exponent */
	if (key_getattr_bn(key, CKA_MODULUS, &rsa->n) ||
			key_getattr_bn(key, CKA_PUBLIC_EXPONENT, &rsa->e)) {
		RSA_free(rsa);
		return NULL;
	}
	if(!BN_is_zero(rsa->e)) /* The public exponent was retrieved */
		return rsa;
	BN_clear_free(rsa->e);
	/* In case someone modifies this function to execute RSA_free()
	 * before a valid BN value is assigned to rsa->e */
	rsa->e = NULL;

	/* The public exponent was not found in the private key:
	 * retrieve it from the corresponding public key */
	if (!PKCS11_enumerate_public_keys(KEY2TOKEN(key), &keys, &count)) {
		for(i = 0; i < count; i++) {
			BIGNUM *pubmod;

			if (key_getattr_bn(&keys[i], CKA_MODULUS, &pubmod))
				continue; /* Failed to retrieve the modulus */
			if (BN_cmp(rsa->n, pubmod) == 0) { /* The key was found */
				BN_clear_free(pubmod);
				if (key_getattr_bn(&keys[i], CKA_PUBLIC_EXPONENT, &rsa->e))
					continue; /* Failed to retrieve the public exponent */
				return rsa;
			} else {
				BN_clear_free(pubmod);
			}
		}
	}

	/* Last resort: use the most common default */
	rsa->e = BN_new();
	if(rsa->e && BN_set_word(rsa->e, RSA_F4))
		return rsa;

	RSA_free(rsa);
	return NULL;
}

/*
 * Build an EVP_PKEY object
 */
static EVP_PKEY *pkcs11_get_evp_key_rsa(PKCS11_KEY * key)
{
	EVP_PKEY *pk;
	RSA *rsa;

	rsa = pkcs11_get_rsa(key);
	if (rsa == NULL)
		return NULL;
	pk = EVP_PKEY_new();
	if (pk == NULL) {
		RSA_free(rsa);
		return NULL;
	}
	EVP_PKEY_set1_RSA(pk, rsa); /* Also increments the rsa ref count */

	if (key->isPrivate)
		RSA_set_method(rsa, PKCS11_get_rsa_method());
	/* TODO: Retrieve the RSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

#if OPENSSL_VERSION_NUMBER < 0x01010000L
	/* RSA_FLAG_SIGN_VER no longer  in OpenSSL 1.1 */
	rsa->flags |= RSA_FLAG_SIGN_VER;
#endif
	RSA_set_ex_data(rsa, rsa_ex_index, key);
	RSA_free(rsa); /* Drops our reference to it */
	return pk;
}

int pkcs11_get_key_modulus(PKCS11_KEY * key, BIGNUM **bn)
{
	if (pkcs11_getattr_bn(KEY2TOKEN(key), PRIVKEY(key)->object,
			CKA_MODULUS, bn))
		return 0;
	return 1;
}

int pkcs11_get_key_exponent(PKCS11_KEY * key, BIGNUM **bn)
{
	if (pkcs11_getattr_bn(KEY2TOKEN(key), PRIVKEY(key)->object,
			CKA_PUBLIC_EXPONENT, bn))
		return 0;
	return 1;
}

int pkcs11_get_key_size(PKCS11_KEY * key)
{
	BIGNUM *n = NULL;
	int numbytes = 0;
	if (key_getattr_bn(key, CKA_MODULUS, &n))
		return 0;
	numbytes = BN_num_bytes(n);
	BN_clear_free(n);
	return numbytes;
}

static int pkcs11_rsa_decrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA * rsa, int padding)
{
	return pkcs11_private_decrypt(flen, from, to,
		(PKCS11_KEY *) RSA_get_ex_data(rsa, rsa_ex_index), padding);
}

static int pkcs11_rsa_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA * rsa, int padding)
{
	return pkcs11_private_encrypt(flen, from, to,
		(PKCS11_KEY *) RSA_get_ex_data(rsa, rsa_ex_index), padding);
}

static int pkcs11_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const RSA * rsa)
{
	return pkcs11_sign(type, m, m_len, sigret, siglen,
		(PKCS11_KEY *) RSA_get_ex_data(rsa, rsa_ex_index));
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
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	if (rsa_ex_index > 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_ex_index);
		rsa_ex_index = 0;
	}
#endif
}

/*
 * Overload the default OpenSSL methods for RSA
 */
RSA_METHOD *PKCS11_get_rsa_method(void)
{
	static RSA_METHOD ops;

	alloc_rsa_ex_index();
	if (!ops.rsa_priv_enc) {
		ops = *RSA_get_default_method();
		ops.rsa_priv_enc = pkcs11_rsa_encrypt;
		ops.rsa_priv_dec = pkcs11_rsa_decrypt;
		ops.rsa_sign = pkcs11_rsa_sign;
	}
	return &ops;
}

/* This function is *not* currently exported */
void PKCS11_rsa_method_free(void)
{
	free_rsa_ex_index();
}

PKCS11_KEY_ops pkcs11_rsa_ops = {
	EVP_PKEY_RSA,
	pkcs11_get_evp_key_rsa
};

/* vim: set noexpandtab: */
