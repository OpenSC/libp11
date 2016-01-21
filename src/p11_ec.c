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
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>

#define LIBP11_BUILD_WITHOUT_ECDSA
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#undef LIBP11_BUILD_WITHOUT_ECDSA
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#endif

#if defined(BUILD_WITH_ECS_LOCL_H)
	#error  "BUILD_WITH_ECS_LOCL_H is no longer supported"
#endif

#if !defined(LIBP11_BUILD_WITHOUT_ECDSA)


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static EC_KEY_METHOD *ops = NULL;
static int ec_key_ex_index = 0;
#else
static ECDSA_METHOD *ops = NULL;
static int ecdsa_ex_index = 0;
#endif

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
	pubkey = key->isPrivate ? PKCS11_find_key_from_key(key) : key;
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

	if (sensitive || !extractable) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
#endif
	} else if (key->isPrivate) {
		/* TODO: Extract the ECDSA private key */
		/* In the meantime lets use the card anyway */
		/* TODO we should do this early after EC_KEY_new */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
	/* TODO: Retrieve the ECDSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
	EC_KEY_set_ex_data(ec,ec_key_ex_index, key);
#else
	ECDSA_set_ex_data(ec, ecdsa_ex_index, key);
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
	key = (PKCS11_KEY *) EC_KEY_get_ex_data(ec, ec_key_ex_index);
#else
	key = (PKCS11_KEY *) ECDSA_get_ex_data(ec, ecdsa_ex_index);
#endif
	if (key == NULL)
		return NULL;

	siglen = sizeof(sigret);

	rv = PKCS11_ecdsa_sign(dgst, dlen, sigret, &siglen, key);
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

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
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
	const EC_POINT *ecpoint = NULL;
	CK_ECDH1_DERIVE_PARAMS ecdh_parms;
	PKCS11_KEY * key = NULL;

	key = (PKCS11_KEY *) EC_KEY_get_ex_data(ecdh, ec_key_ex_index);

	if (key == NULL) {
	    ret -1;
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
			ret -1;
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
#endif


#if OPENSSL_VERSION_NUMBER >= 0x10100002L
static void alloc_ec_key_ex_index() {
	if (ec_key_ex_index == 0) {
		while (ec_key_ex_index == 0) /* Workaround for OpenSSL RT3710 */
			ec_key_ex_index = EC_KEY_get_ex_new_index(0, "libp11 ec_key",
				NULL, NULL, NULL);
		if (ec_key_ex_index < 0)
			ec_key_ex_index = 0; /* Fallback to app_data */
	}
}
#else
static void alloc_ecdsa_ex_index() {
	if (ecdsa_ex_index == 0) {
		while (ecdsa_ex_index == 0) /* Workaround for OpenSSL RT3710 */
			ecdsa_ex_index = ECDSA_get_ex_new_index(0, "libp11 ecdsa",
				NULL, NULL, NULL);
		if (ecdsa_ex_index < 0)
			ecdsa_ex_index = 0; /* Fallback to app_data */
	}
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
static void free_ec_key_ex_index() {
	/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
	if (ec_key_ex_index > 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_key_ex_index);
		ec_key_ex_index = 0;
	}
}
#else
static void free_ecdsa_ex_index() {
	/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
	if (ecdsa_ex_index > 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_ECDSA, ecdsa_ex_index);
		ecdsa_ex_index = 0;
	}
#endif
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

	alloc_ec_key_ex_index();
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

void PKCS11_EC_KEY_METHOD_free(void)
{
	if (ops) {
		EC_KEY_METHOD_free(ops);
		ops = NULL;
	}
	free_ec_key_ex_index();
}

#else /* OPENSSL_VERSION_NUMBER >= 0x1000200fL */
ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{

	if (ops == NULL) {
		alloc_ecdsa_ex_index();
		ops = ECDSA_METHOD_new((ECDSA_METHOD *)ECDSA_OpenSSL());
		ECDSA_METHOD_set_sign(ops, pkcs11_ecdsa_do_sign);
		ECDSA_METHOD_set_sign_setup(ops, pkcs11_ecdsa_sign_setup);
	}
	return ops;
}

void PKCS11_ecdsa_method_free(void)
{
	/* It is static in the old method */
	free_ecdsa_ex_index();
	if (ops) {
		ECDSA_METHOD_free(ops);
		ops = NULL;
	}
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x1000200fL */

PKCS11_KEY_ops pkcs11_ec_ops_s = {
	EVP_PKEY_EC,
	pkcs11_get_evp_key_ec
};
PKCS11_KEY_ops *pkcs11_ec_ops = {&pkcs11_ec_ops_s};

#else /* LIBP11_BUILD_WITHOUT_ECDSA */

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

#endif /* LIBP11_BUILD_WITHOUT_ECDSA */

/* vim: set noexpandtab: */
