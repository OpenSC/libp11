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
 * This file implements the handling of RSA keys stored on a
 * PKCS11 token
 */

#include <config.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "libp11-int.h"

static int pkcs11_get_rsa_public(PKCS11_KEY *, EVP_PKEY *);
static int pkcs11_get_rsa_private(PKCS11_KEY *, EVP_PKEY *);


/*
 * Get RSA key material
 */
static int pkcs11_get_rsa_private(PKCS11_KEY * key, EVP_PKEY * pk)
{
	CK_BBOOL sensitive, extractable;
	RSA *rsa;

	if (!(rsa = EVP_PKEY_get1_RSA(pk))) {
		ERR_clear_error();	/* the above flags an error */
		rsa = RSA_new();
		EVP_PKEY_set1_RSA(pk, rsa);
	}

	if (key_getattr(key, CKA_SENSITIVE, &sensitive, sizeof(sensitive))
	    || key_getattr(key, CKA_EXTRACTABLE, &extractable, sizeof(extractable))) {
		RSA_free(rsa);
		return -1;
	}

	if (key_getattr_bn(key, CKA_MODULUS, &rsa->n) ||
	    key_getattr_bn(key, CKA_PUBLIC_EXPONENT, &rsa->e)) {
		RSA_free(rsa);
		return -1;
	}

	/* If the key is not extractable, create a key object
	 * that will use the card's functions to sign & decrypt */
	if (sensitive || !extractable) {
		RSA_set_method(rsa, PKCS11_get_rsa_method());
		rsa->flags |= RSA_FLAG_SIGN_VER;
		RSA_set_app_data(rsa, key);

		RSA_free(rsa);
		return 0;
	}

	/* TBD - extract RSA private key. */
	/* In the mean time let's use the card anyway */
	RSA_set_method(rsa, PKCS11_get_rsa_method());
	rsa->flags |= RSA_FLAG_SIGN_VER;
	RSA_set_app_data(rsa, key);

	RSA_free(rsa);

	return 0;
	/*
	PKCS11err(PKCS11_F_PKCS11_GET_KEY, PKCS11_NOT_SUPPORTED);
	return -1;
	*/
}

static int pkcs11_get_rsa_public(PKCS11_KEY * key, EVP_PKEY * pk)
{
	/* TBD */
	return 0;
/*	return pkcs11_get_rsa_private(key,pk);*/
}


static int pkcs11_rsa_decrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA * rsa, int padding)
{

	return PKCS11_private_decrypt(	flen, from, to, (PKCS11_KEY *) RSA_get_app_data(rsa), padding);
}

static int pkcs11_rsa_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA * rsa, int padding)
{
	return PKCS11_private_encrypt(flen,from,to,(PKCS11_KEY *) RSA_get_app_data(rsa), padding);
}

static int pkcs11_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const RSA * rsa)
{
	
	return PKCS11_sign(type,m,m_len,sigret,siglen,(PKCS11_KEY *) RSA_get_app_data(rsa));
}
/* Lousy hack alert. If RSA_verify detects that the key has the
 * RSA_FLAG_SIGN_VER flags set, it will assume that verification
 * is implemented externally as well.
 * We work around this by temporarily cleaning the flag, and
 * calling RSA_verify once more.
 */
static int
pkcs11_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
		  unsigned char *signature, unsigned int siglen, const RSA * rsa)
{
	RSA *r = (RSA *) rsa;	/* Ugly hack to get rid of compiler warning */
	int res;

	if (r->flags & RSA_FLAG_SIGN_VER) {
		r->flags &= ~RSA_FLAG_SIGN_VER;
		res = RSA_verify(type, m, m_len, signature, siglen, r);
		r->flags |= RSA_FLAG_SIGN_VER;
	} else {
		PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
		res = 0;
	}
	return res;
}

/*
 * Overload the default OpenSSL methods for RSA
 */
RSA_METHOD *PKCS11_get_rsa_method(void)
{
	static RSA_METHOD ops;

	if (!ops.rsa_priv_enc) {
		ops = *RSA_get_default_method();
		ops.rsa_priv_enc = pkcs11_rsa_encrypt;
		ops.rsa_priv_dec = pkcs11_rsa_decrypt;
		ops.rsa_sign = pkcs11_rsa_sign;
		ops.rsa_verify = pkcs11_rsa_verify;
	}
	return &ops;
}

PKCS11_KEY_ops pkcs11_rsa_ops = {
	EVP_PKEY_RSA,
	pkcs11_get_rsa_public,
	pkcs11_get_rsa_private
};
