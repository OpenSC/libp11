/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * This file implements the handling of SLH-DSA keys stored on a PKCS11 token.
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

#if !defined(OPENSSL_NO_SLH_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L

#define SLH_DSA_128_PUB_BYTES 32
#define SLH_DSA_192_PUB_BYTES 48
#define SLH_DSA_256_PUB_BYTES 64

/*
 * Extract raw SLH-DSA public key bytes from a CKO_PUBLIC_KEY object using CKA_VALUE.
 * Returns 1 on success, 0 on failure.
 */
static int extract_pub_from_public_key_obj(PKCS11_CTX_private *ctx,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
	size_t expected_len, unsigned char **raw, size_t *rawlen)
{
	unsigned char *value = NULL;
	size_t value_len = 0;

	if (ctx == NULL || raw == NULL || rawlen == NULL ||
		obj == CK_INVALID_HANDLE || expected_len == 0)
		return 0;

	*raw = NULL;
	*rawlen = 0;

	if (pkcs11_getattr_alloc(ctx, session, obj, CKA_VALUE, &value, &value_len)) {
		pkcs11_log(ctx, LOG_DEBUG,
			"Missing CKA_VALUE attribute on SLH-DSA public key\n");
		return 0;
	}

	if (value_len != expected_len) {
		pkcs11_log(ctx, LOG_DEBUG,
			"Unexpected SLH-DSA public key size: got %lu, expected %lu\n",
			(unsigned long)value_len, (unsigned long)expected_len);
		OPENSSL_free(value);
		return 0;
	}

	*raw = value;
	*rawlen = value_len;
	return 1;
}

/*
 * Extract raw SLH-DSA public key bytes from a CKO_CERTIFICATE object.
 * The certificate is read from CKA_VALUE (DER-encoded X.509) and
 * the public key is obtained via X.509 parsing.
 * Returns 1 on success, 0 on failure.
 */
static int extract_pub_from_cert_obj(PKCS11_CTX_private *ctx,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
	size_t expected_len, const char *algname,
	unsigned char **raw, size_t *rawlen)
{
	const unsigned char *p;
	unsigned char *der = NULL;
	unsigned char *buf = NULL;
	size_t derlen = 0;
	size_t len = 0;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	int ok = 0;

	if (ctx == NULL || raw == NULL || rawlen == NULL ||
		obj == CK_INVALID_HANDLE || expected_len == 0 || algname == NULL)
		return 0;

	*raw = NULL;
	*rawlen = 0;

	if (pkcs11_getattr_alloc(ctx, session, obj, CKA_VALUE, &der, &derlen))
		return 0;

	if (derlen == 0 || derlen > LONG_MAX)
		goto end;

	p = der;
	cert = d2i_X509(NULL, &p, (long)derlen);
	if (cert == NULL || p != der + derlen)
		goto end;

	pkey = X509_get_pubkey(cert);
	if (pkey == NULL)
		goto end;

	if (!EVP_PKEY_is_a(pkey, algname))
		goto end;

	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) != 1)
		goto end;

	if (len != expected_len)
		goto end;

	buf = OPENSSL_malloc(len);
	if (buf == NULL)
		goto end;

	if (EVP_PKEY_get_raw_public_key(pkey, buf, &len) != 1)
		goto end;

	if (len != expected_len)
		goto end;

	*raw = buf;
	*rawlen = len;
	buf = NULL;
	ok = 1;

end:
	OPENSSL_free(buf);
	OPENSSL_free(der);
	EVP_PKEY_free(pkey);
	X509_free(cert);
	return ok;
}

/*
 * Select an object that can provide public key material.
 *
 * For a private key object, try to locate a matching CKO_PUBLIC_KEY
 * (same CKA_ID). If not found, fall back to CKO_CERTIFICATE.
 *
 * On success, returns a PKCS11_OBJECT_private pointer.
 * If a new object is returned, *needs_free is set to 1 and the caller
 * must free it with pkcs11_object_free().
 *
 * Returns NULL on failure.
 */
static PKCS11_OBJECT_private *pkcs11_choose_public_source(PKCS11_OBJECT_private *key,
	CK_SESSION_HANDLE session, int *needs_free)
{
	PKCS11_OBJECT_private *obj;

	*needs_free = 0;

	if (key->object_class != CKO_PRIVATE_KEY)
		return key;

	obj = pkcs11_object_from_object(key, session, CKO_PUBLIC_KEY);
	if (obj != NULL && obj->object != CK_INVALID_HANDLE) {
		*needs_free = 1;
		return obj;
	}
	if (obj != NULL)
		pkcs11_object_free(obj);

	obj = pkcs11_object_from_object(key, session, CKO_CERTIFICATE);
	if (obj != NULL && obj->object != CK_INVALID_HANDLE) {
		*needs_free = 1;
		return obj;
	}
	if (obj != NULL)
		pkcs11_object_free(obj);

	return NULL;
}

/*
 * Retrieve raw SLH-DSA public key bytes.
 *
 * Preference order:
 *   1. CKO_PUBLIC_KEY  -> CKA_VALUE
 *   2. CKO_CERTIFICATE -> CKA_VALUE (DER) + X.509 parsing
 *
 * The returned buffer is allocated with OPENSSL_malloc()
 * and must be freed by the caller.
 *
 * Returns 0 on success, -1 on failure.
 */
static int pkcs11_get_raw_public_key(PKCS11_OBJECT_private *key,
	size_t expected_len, const char *algname,
	unsigned char **raw, size_t *rawlen)
{
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	PKCS11_OBJECT_private *obj = NULL;
	int obj_needs_free = 0, ok = 0;

	if (key == NULL || key->slot == NULL || raw == NULL || rawlen == NULL)
		return -1;

	*raw = NULL;
	*rawlen = 0;
	slot = key->slot;
	ctx = slot->ctx;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	obj = pkcs11_choose_public_source(key, session, &obj_needs_free);
	if (obj == NULL || obj->object == CK_INVALID_HANDLE)
		goto end;

	switch (obj->object_class) {
	case CKO_PUBLIC_KEY:
		ok = extract_pub_from_public_key_obj(ctx, session, obj->object,
			expected_len, raw, rawlen);
		break;
	case CKO_CERTIFICATE:
		ok = extract_pub_from_cert_obj(ctx, session, obj->object,
			expected_len, algname, raw, rawlen);
		break;
	default:
		ok = 0;
		break;
	}

end:
	pkcs11_put_session(slot, session);

	if (!ok) {
		OPENSSL_free(*raw);
		*raw = NULL;
		*rawlen = 0;
	}
	if (obj_needs_free && obj != NULL)
		pkcs11_object_free(obj);

	return ok ? 0 : -1;
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa(PKCS11_OBJECT_private *key,
	size_t publen, const char *algname)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *raw = NULL;
	size_t rawlen = 0;

	/* Retrieve the public key in raw format from PKCS#11 */
	if (pkcs11_get_raw_public_key(key, publen, algname, &raw, &rawlen) < 0)
		return NULL;

	/* Build a EVP_PKEY from the raw public key, used only as software public key */
	pkey = EVP_PKEY_new_raw_public_key_ex(NULL, algname, NULL, raw, rawlen);
	OPENSSL_free(raw);
	return pkey;
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_128s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_128_PUB_BYTES,
		"SLH-DSA-SHA2-128s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_128f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_128_PUB_BYTES,
		"SLH-DSA-SHA2-128f");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_192s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_192_PUB_BYTES,
		"SLH-DSA-SHA2-192s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_192f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_192_PUB_BYTES,
		"SLH-DSA-SHA2-192f");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_256s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_256_PUB_BYTES,
		"SLH-DSA-SHA2-256s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_sha2_256f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_256_PUB_BYTES,
		"SLH-DSA-SHA2-256f");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_128s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_128_PUB_BYTES,
		"SLH-DSA-SHAKE-128s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_128f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_128_PUB_BYTES,
		"SLH-DSA-SHAKE-128f");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_192s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_192_PUB_BYTES,
		"SLH-DSA-SHAKE-192s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_192f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_192_PUB_BYTES,
		"SLH-DSA-SHAKE-192f");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_256s(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_256_PUB_BYTES,
		"SLH-DSA-SHAKE-256s");
}

static EVP_PKEY *pkcs11_get_evp_key_slhdsa_shake_256f(PKCS11_OBJECT_private *key)
{
	return pkcs11_get_evp_key_slhdsa(key, SLH_DSA_256_PUB_BYTES,
		"SLH-DSA-SHAKE-256f");
}


PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_128s_ops = {
	EVP_PKEY_SLH_DSA_SHA2_128S,
	pkcs11_get_evp_key_slhdsa_sha2_128s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_128f_ops = {
	EVP_PKEY_SLH_DSA_SHA2_128F,
	pkcs11_get_evp_key_slhdsa_sha2_128f,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_192s_ops = {
	EVP_PKEY_SLH_DSA_SHA2_192S,
	pkcs11_get_evp_key_slhdsa_sha2_192s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_192f_ops = {
	EVP_PKEY_SLH_DSA_SHA2_192F,
	pkcs11_get_evp_key_slhdsa_sha2_192f,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_256s_ops = {
	EVP_PKEY_SLH_DSA_SHA2_256S,
	pkcs11_get_evp_key_slhdsa_sha2_256s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_sha2_256f_ops = {
	EVP_PKEY_SLH_DSA_SHA2_256F,
	pkcs11_get_evp_key_slhdsa_sha2_256f,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_128s_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_128S,
	pkcs11_get_evp_key_slhdsa_shake_128s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_128f_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_128F,
	pkcs11_get_evp_key_slhdsa_shake_128f,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_192s_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_192S,
	pkcs11_get_evp_key_slhdsa_shake_192s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_192f_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_192F,
	pkcs11_get_evp_key_slhdsa_shake_192f,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_256s_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_256S,
	pkcs11_get_evp_key_slhdsa_shake_256s,
};

PKCS11_OBJECT_ops pkcs11_slhdsa_shake_256f_ops = {
	EVP_PKEY_SLH_DSA_SHAKE_256F,
	pkcs11_get_evp_key_slhdsa_shake_256f,
};


#else /* !defined(OPENSSL_NO_SLH_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L */
/*
 * SLH-DSA support is not available:
 * - either OpenSSL was built without SLH-DSA support, or
 * - OpenSSL version is older than 3.5.
 */
#warning "SLH-DSA support not built with libp11"

#endif /* !defined(OPENSSL_NO_SLH_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* vim: set noexpandtab: */
