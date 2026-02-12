/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * This file implements the handling of EdDSA keys stored on a PKCS11 token.
 * Inside EVP_PKEY, Ed25519/Ed448 keys are stored in an ECX_KEY structure.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "libp11-int.h"
#include <string.h>

#if !defined(OPENSSL_NO_EC) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/ec.h>
#include <openssl/bn.h>

#if OPENSSL_VERSION_NUMBER < 0x40000000L
static EVP_PKEY_METHOD *pkcs11_ed25519_method = NULL;
static EVP_PKEY_METHOD *pkcs11_ed448_method = NULL;
static const EVP_PKEY_METHOD *orig_ed25519_method = NULL;
static const EVP_PKEY_METHOD *orig_ed448_method = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

int (*orig_ed25519_digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);

int (*orig_ed448_digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);

#if OPENSSL_VERSION_NUMBER < 0x40000000L

/* PKCS#11 sign implementation for Ed25519 / Ed448 */
static int pkcs11_eddsa_sign(unsigned char *sigret, unsigned int *siglen,
	const unsigned char *tbs, unsigned int tbslen, PKCS11_OBJECT_private *key)
{
	int rv;
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG ck_siglen = (CK_ULONG)(*siglen);
	CK_ULONG ck_tbslen = (CK_ULONG)tbslen;

	/* PureEdDSA, no prehash */
	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_EDDSA;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = CRYPTOKI_call(ctx,
		C_SignInit(session, &mechanism, key->object));
	if (!rv && key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(session, (CK_BYTE_PTR)tbs, ck_tbslen, sigret, &ck_siglen));
	pkcs11_put_session(slot, session);

	if (rv) {
		CKRerr(CKR_F_PKCS11_EDDSA_SIGN, rv);
		return -1;
	}
	*siglen = (unsigned int)ck_siglen;
	return (int)ck_siglen;
}

/*
 * EVP_PKEY method sign wrapper for EdDSA.
 * This function is invoked internally by EVP_PKEY_sign().
 * If the key belongs to PKCS#11, perform signing via pkcs11_eddsa_sign().
 */
static int pkcs11_eddsa_pmeth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	int rv;
	unsigned int tmp_len;

	if (*siglen > UINT_MAX)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!pkey)
		return 0;

	key = pkcs11_get_ex_data_pkey(pkey);
	if (!key)
		return 0;

	tmp_len = (unsigned int)*siglen;
	rv = pkcs11_eddsa_sign(sig, &tmp_len, tbs, (unsigned int)tbslen, key);
	if (rv < 0)
		return 0;

	*siglen = tmp_len;
	return 1;
}

/*
 * Custom EVP_PKEY_METHOD digestsign implementation for EdDSA (Ed25519/Ed448)
 *
 * This function supports the two-step signing process used by EVP_DigestSign*():
 *   1. Query the required signature length (sig == NULL).
 *   2. Perform the actual signing when a buffer is provided (sig != NULL).
 *
 * If the key is managed by PKCS#11, the signing is performed via pkcs11_eddsa_sign().
 * Otherwise, the call is delegated to the original OpenSSL Ed25519/Ed448 implementation.
 */
static int pkcs11_eddsa_pmeth_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	unsigned int tmp_len;
	int rv;

	pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));
	if (!pkey)
		return -1;

	key = pkcs11_get_ex_data_pkey(pkey);
	if (!key)
		return -1;

	/* Step 1: caller asks for signature length only */
	if (sig == NULL) {
		if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519)
			*siglen = 64; /* fixed size for Ed25519 */
		else if (EVP_PKEY_id(pkey) == EVP_PKEY_ED448)
			*siglen = 114; /* fixed size for Ed448 */
		else
			return -1;
		/* success: report the expected signature length only,
		 * no signing is performed in this call */
		return 1;
	}

	/* Step 2: actual signing */
	tmp_len = (unsigned int)*siglen;
	rv = pkcs11_eddsa_sign(sig, &tmp_len, tbs, (unsigned int)tbslen, key);
	if (rv < 0)
		return -1;

	*siglen = tmp_len;
	return 1;
}

static int pkcs11_pkey_ed25519_digestsign(EVP_MD_CTX *ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_eddsa_pmeth_digestsign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		/* assume a foreign key */
		ret = (*orig_ed25519_digestsign)(ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static int pkcs11_pkey_ed448_digestsign(EVP_MD_CTX *ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_eddsa_pmeth_digestsign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_ed448_digestsign)(ctx, sig, siglen, tbs, tbslen);
	return ret;
}

/*
 * For Ed25519/Ed448, no digest algorithm can be set.
 * The only valid value here is NULL (PureEdDSA).
 * OpenSSL calls this during DigestSignInit() to check whether the digest is acceptable.
 */
static int pkcs11_eddsa_pmeth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	(void)ctx;
	(void)p1;
	switch (type) {
	case EVP_PKEY_CTRL_MD:
		if (p2 == NULL)
			return 1; /* Accept NULL digest */
		return 0; /* Reject if caller tries to set a digest */
	default:
		return -2; /* command not supported */
	}
}

/* Global initialize ED25519 EVP_PKEY_METHOD */
static int pkcs11_ed25519_method_new(void)
{
	int orig_id, orig_flags;

	if (pkcs11_ed25519_method)
		return 1; /* EVP_PKEY_ED25519 method already initialized */

	orig_ed25519_method = EVP_PKEY_meth_find(EVP_PKEY_ED25519);
	if (!orig_ed25519_method)
		return 0;

	EVP_PKEY_meth_get0_info(&orig_id, &orig_flags, orig_ed25519_method);
	if (orig_id != EVP_PKEY_ED25519 || !(orig_flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM))
		return 0;

	/* The digestsign() method is used to generate a signature in a one-shot mode */
	EVP_PKEY_meth_get_digestsign(orig_ed25519_method, &orig_ed25519_digestsign);
	if (!orig_ed25519_digestsign)
		return 0;

	/* Don't assume any digest related defaults */
	pkcs11_ed25519_method = EVP_PKEY_meth_new(EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (!pkcs11_ed25519_method)
		return 0;

	/* Duplicate the original method */
	EVP_PKEY_meth_copy(pkcs11_ed25519_method, orig_ed25519_method);

	/* Override selected ED25519 method callbacks with PKCS#11 implementations */
	EVP_PKEY_meth_set_sign(pkcs11_ed25519_method, NULL, pkcs11_eddsa_pmeth_sign);
	EVP_PKEY_meth_set_digestsign(pkcs11_ed25519_method, pkcs11_pkey_ed25519_digestsign);
	EVP_PKEY_meth_set_ctrl(pkcs11_ed25519_method, pkcs11_eddsa_pmeth_ctrl, NULL);

	/* Register the method globally */
	if (!EVP_PKEY_meth_add0(pkcs11_ed25519_method)) {
		EVP_PKEY_meth_free(pkcs11_ed25519_method);
		pkcs11_ed25519_method = NULL;
		return 0;
	}
	return 1;
}

/* Global initialize ED448 EVP_PKEY_METHOD */
static int pkcs11_ed448_method_new(void)
{
	int orig_id, orig_flags;

	if (pkcs11_ed448_method)
		return 1; /* EVP_PKEY_ED448 method already initialized */

	orig_ed448_method = EVP_PKEY_meth_find(EVP_PKEY_ED448);
	if (!orig_ed448_method)
		return 0;

	EVP_PKEY_meth_get0_info(&orig_id, &orig_flags, orig_ed448_method);
	if (orig_id != EVP_PKEY_ED448 || !(orig_flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM))
		return 0;

	/* The digestsign() method is used to generate a signature in a one-shot mode */
	EVP_PKEY_meth_get_digestsign(orig_ed448_method, &orig_ed448_digestsign);
	if (!orig_ed448_digestsign)
		return 0;

	/* Don't assume any digest related defaults */
	pkcs11_ed448_method = EVP_PKEY_meth_new(EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM);
	if (!pkcs11_ed448_method)
		return 0;

	/* Duplicate the original method */
	EVP_PKEY_meth_copy(pkcs11_ed448_method, orig_ed448_method);

	/* Override selected ED448 method callbacks with PKCS#11 implementations */
	EVP_PKEY_meth_set_sign(pkcs11_ed448_method, NULL, pkcs11_eddsa_pmeth_sign);
	EVP_PKEY_meth_set_digestsign(pkcs11_ed448_method, pkcs11_pkey_ed448_digestsign);
	EVP_PKEY_meth_set_ctrl(pkcs11_ed448_method, pkcs11_eddsa_pmeth_ctrl, NULL);

	/* Register the method globally */
	if (!EVP_PKEY_meth_add0(pkcs11_ed448_method)) {
		EVP_PKEY_meth_free(pkcs11_ed448_method);
		pkcs11_ed448_method = NULL;
		return 0;
	}
	return 1;
}

void pkcs11_ed25519_method_free(void)
{
	if (pkcs11_ed25519_method) {
		free_pkey_ex_index();
		/* Remove an EVP_PKEY_METHOD object added by EVP_PKEY_meth_add0() */
		EVP_PKEY_meth_remove(pkcs11_ed25519_method);
		EVP_PKEY_meth_free(pkcs11_ed25519_method);
		pkcs11_ed25519_method = NULL;
	}
}

void pkcs11_ed448_method_free(void)
{
	if (pkcs11_ed448_method) {
		free_pkey_ex_index();
		EVP_PKEY_meth_remove(pkcs11_ed448_method);
		EVP_PKEY_meth_free(pkcs11_ed448_method);
		pkcs11_ed448_method = NULL;
	}
}

void pkcs11_ed_key_method_free(void)
{
	if (pkcs11_global_data_refs == 0) {
		pkcs11_ed25519_method_free();
		pkcs11_ed448_method_free();
	}
}

#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

/*
 * Retrieve the raw public key (EdDSA) from a PKCS#11 object.
 * The buffer `*raw` is allocated and must be freed by the caller
 * using OPENSSL_free().
 */
static int pkcs11_get_raw_public_key(PKCS11_OBJECT_private *key,
	unsigned char **raw, size_t *rawlen)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	PKCS11_SLOT_private *slot = key->slot;
	PKCS11_CTX_private *ctx = slot->ctx;
	PKCS11_OBJECT_private *pubkey;

	*raw = NULL;
	*rawlen = 0;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_EDDSA;

	memset(&attr, 0, sizeof(attr));

	/* CKA_EC_POINT: DER-encoding of the b-bit public key value
	 * in little endian order as defined in RFC 8032 */
	attr.type = CKA_EC_POINT;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	if (key->object_class == CKO_PRIVATE_KEY)
		pubkey = pkcs11_object_from_object(key, session, CKO_PUBLIC_KEY);
	else
		pubkey = key;

	rv = CRYPTOKI_call(ctx, C_GetAttributeValue(session, pubkey->object, &attr, 1));
	if (rv != CKR_OK)
		return -1;

	if (attr.ulValueLen <= 0 || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return -1;

	*raw = OPENSSL_malloc(attr.ulValueLen);
	if (!*raw)
		return -1;

	attr.pValue = *raw;

	rv = CRYPTOKI_call(ctx, C_GetAttributeValue(session, pubkey->object, &attr, 1));

	if (key->object_class == CKO_PRIVATE_KEY)
		pkcs11_object_free(pubkey);

	if (rv != CKR_OK) {
		OPENSSL_free(*raw);
		*raw = NULL;
		return -1;
	}
	*rawlen = attr.ulValueLen;

	/* For EdDSA (RFC8032) the CKA_EC_POINT attribute may be encoded
	 * as a DER OCTET STRING. In such a case, the ASN.1 header needs
	 * to be stripped, leaving only the raw key bytes. */
	if (*rawlen > 2 && (*raw)[0] == 0x04) {
		/* simple OCTET STRING parser */
		size_t len = (*raw)[1];
		if (len + 2 == *rawlen) {
			memmove(*raw, *raw + 2, len);
			*rawlen = len;
		}
	}
	return 0;
}

static EVP_PKEY *pkcs11_get_evp_key_ed25519(PKCS11_OBJECT_private *key)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *raw = NULL;
	size_t rawlen = 0;

	/* Retrieve the public key in raw format from PKCS#11 */
	if (pkcs11_get_raw_public_key(key, &raw, &rawlen) < 0)
		return NULL;

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, rawlen);
	OPENSSL_free(raw);

	if (!pkey)
		return NULL;

	if (key->object_class == CKO_PRIVATE_KEY) {
#if OPENSSL_VERSION_NUMBER < 0x40000000L
		/* global initialize ED25519 EVP_PKEY_METHOD */
		if (!pkcs11_ed25519_method_new()) {
			EVP_PKEY_free(pkey);
			return NULL;
		}
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

		/* creates a new EVP_PKEY object which requires its own key object reference */
		key = pkcs11_object_ref(key);

#if OPENSSL_VERSION_NUMBER < 0x40000000L
		alloc_pkey_ex_index();
		pkcs11_set_ex_data_pkey(pkey, key);
		atexit(pkcs11_ed25519_method_free);
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */
	}
	return pkey;
}

static EVP_PKEY *pkcs11_get_evp_key_ed448(PKCS11_OBJECT_private *key)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *raw = NULL;
	size_t rawlen = 0;

	/* Retrieve the public key in raw format from PKCS#11 */
	if (pkcs11_get_raw_public_key(key, &raw, &rawlen) < 0)
		return NULL;

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, raw, rawlen);
	OPENSSL_free(raw);

	if (!pkey)
		return NULL;

	if (key->object_class == CKO_PRIVATE_KEY) {
#if OPENSSL_VERSION_NUMBER < 0x40000000L
		/* global initialize ED448 EVP_PKEY_METHOD */
		if (!pkcs11_ed448_method_new()) {
			EVP_PKEY_free(pkey);
			return NULL;
		}
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

		/* create a new EVP_PKEY object which requires its own key object reference */
		key = pkcs11_object_ref(key);

#if OPENSSL_VERSION_NUMBER < 0x40000000L
		alloc_pkey_ex_index();
		pkcs11_set_ex_data_pkey(pkey, key);
		atexit(pkcs11_ed448_method_free);
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */
	}
	return pkey;
}


PKCS11_OBJECT_ops pkcs11_ed25519_ops = {
	EVP_PKEY_ED25519,
	pkcs11_get_evp_key_ed25519,
};

PKCS11_OBJECT_ops pkcs11_ed448_ops = {
	EVP_PKEY_ED448,
	pkcs11_get_evp_key_ed448,
};

#else /* !defined(OPENSSL_NO_EC) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* if not built with EC or OpenSSL does not support EdDSA
 * add these routines so engine_pkcs11 can be built now and not
 * require further changes */
#warning "EdDSA support not built with libp11"

#endif /* !defined(OPENSSL_NO_EC) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
