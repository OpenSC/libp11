/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * Common handling of algorithms using raw public key representations:
 * Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM, SLH-DSA and Falcon.
 *
 * Public key material is retrieved from a matching public key object or
 * certificate and used to construct an OpenSSL EVP_PKEY.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "libp11-int.h"

#include <limits.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define FALCON_512_PUB_LEN   897
#define FALCON_1024_PUB_LEN 1793

#ifndef OPENSSL_NO_ECX
#define ED25519_PUB_LEN 32
#define ED448_PUB_LEN   57
#define X25519_PUB_LEN  32
#define X448_PUB_LEN    56
#endif /* OPENSSL_NO_ECX */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
#define ML_DSA_44_PUB_LEN 1312
#define ML_DSA_65_PUB_LEN 1952
#define ML_DSA_87_PUB_LEN 2592
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_ML_KEM
#define ML_KEM_512_PUB_LEN   800
#define ML_KEM_768_PUB_LEN  1184
#define ML_KEM_1024_PUB_LEN 1568
#endif /* OPENSSL_NO_ML_KEM */

#ifndef OPENSSL_NO_SLH_DSA
#define SLH_DSA_128_PUB_LEN 32
#define SLH_DSA_192_PUB_LEN 48
#define SLH_DSA_256_PUB_LEN 64
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

typedef enum {
	P11_RAW_FROM_VALUE,
	P11_RAW_FROM_EC_POINT
} P11_RAW_SOURCE;

typedef struct {
	int type;
	const char *name;
	size_t public_len;
	P11_RAW_SOURCE public_source;
} P11_RAW_ALGORITHM;


/*
 * CKA_EC_POINT is normally a DER OCTET STRING, but some modules return its
 * contents directly. Accept both representations.
 * Returns 1 on success, 0 on error.
 */
static int strip_der_octet_string_alloc(const unsigned char *in, size_t inlen,
	unsigned char **out, size_t *outlen)
{
	const unsigned char *p = in;
	unsigned char *buf;
	ASN1_OCTET_STRING *os = NULL;

	if (out == NULL || outlen == NULL || in == NULL || inlen == 0)
		return 0;

	*out = NULL;
	*outlen = 0;

	if (inlen <= LONG_MAX) {
		/* Discard ASN.1 errors when the input is valid raw data */
		ERR_set_mark();

		/* For EdDSA (RFC8032) the CKA_EC_POINT attribute may be
		* encoded as a DER OCTET STRING */
		os = d2i_ASN1_OCTET_STRING(NULL, &p, (long)inlen);
		if (os != NULL && p == in + inlen) {
			const unsigned char *data = ASN1_STRING_get0_data(os);
			int len = ASN1_STRING_length(os);

			if (len <= 0 || data == NULL) {
				ASN1_OCTET_STRING_free(os);
				ERR_pop_to_mark();
				return 0;
			}

			buf = OPENSSL_memdup(data, (size_t)len);
			ASN1_OCTET_STRING_free(os);
			ERR_pop_to_mark();
			if (buf == NULL)
				return 0;

			*out = buf;
			*outlen = (size_t)len;
			return 1;
		}
		ASN1_OCTET_STRING_free(os);
		ERR_pop_to_mark();
	}

	/* Not DER OCTET STRING -> copy as-is */
	buf = OPENSSL_memdup(in, inlen);
	if (buf == NULL)
		return 0;

	*out = buf;
	*outlen = inlen;
	return 1;
}

/*
 * Extract raw public key bytes from a CKO_PUBLIC_KEY object using
 * the attribute configured for the algorithm.
 * Returns 1 on success, 0 on failure.
 */
static int extract_pub_from_public_key_obj(PKCS11_CTX_private *ctx,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
	const P11_RAW_ALGORITHM *alg, unsigned char **raw, size_t *rawlen)
{
	CK_ATTRIBUTE_TYPE attr;
	const char *attr_name;
	unsigned char *value = NULL;
	unsigned char *decoded = NULL;
	size_t value_len = 0;
	size_t decoded_len = 0;
	int ok = 0;

	if (ctx == NULL || alg == NULL || raw == NULL || rawlen == NULL ||
			object == CK_INVALID_HANDLE || alg->public_len == 0)
		return 0;

	*raw = NULL;
	*rawlen = 0;

	if (alg->public_source == P11_RAW_FROM_EC_POINT) {
		attr = CKA_EC_POINT;
		attr_name = "CKA_EC_POINT";
	} else {
		attr = CKA_VALUE;
		attr_name = "CKA_VALUE";
	}

	if (pkcs11_getattr_alloc(ctx, session, object, attr, &value, &value_len)) {
		pkcs11_log(ctx, LOG_DEBUG,
			"Missing %s attribute on %s public key\n",
			attr_name, alg->name);
		return 0;
	}

	if (alg->public_source == P11_RAW_FROM_EC_POINT) {
		if (!strip_der_octet_string_alloc(value, value_len,
				&decoded, &decoded_len))
			goto end;
	} else {
		decoded = value;
		decoded_len = value_len;
		value = NULL;
	}

	if (decoded_len != alg->public_len) {
		pkcs11_log(ctx, LOG_DEBUG,
			"Unexpected %s public key size: got %lu, expected %lu\n",
			alg->name, (unsigned long)decoded_len,
			(unsigned long)alg->public_len);
		goto end;
	}

	*raw = decoded;
	*rawlen = decoded_len;
	decoded = NULL;
	ok = 1;

end:
	OPENSSL_free(decoded);
	OPENSSL_free(value);
	return ok;
}

/*
 * Extract raw public key bytes from a CKO_CERTIFICATE object.
 * The certificate is read from CKA_VALUE (DER-encoded X.509) and
 * the public key is obtained via X.509 parsing.
 * Returns 1 on success, 0 on failure.
 */
static int extract_pub_from_cert_obj(PKCS11_CTX_private *ctx,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
	const P11_RAW_ALGORITHM *alg, unsigned char **raw, size_t *rawlen)
{
	const unsigned char *p;
	unsigned char *der = NULL;
	unsigned char *buf = NULL;
	size_t derlen = 0;
	size_t len = 0;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	int ok = 0;

	if (ctx == NULL || alg == NULL || raw == NULL || rawlen == NULL ||
			object == CK_INVALID_HANDLE || alg->public_len == 0)
		return 0;

	*raw = NULL;
	*rawlen = 0;

	if (pkcs11_getattr_alloc(ctx, session, object, CKA_VALUE, &der, &derlen))
		return 0;

	if (derlen == 0 || derlen > LONG_MAX)
		goto end;

	p = der;
	cert = d2i_X509(NULL, &p, (long)derlen);
	if (cert == NULL || p != der + derlen)
		goto end;

	pkey = X509_get_pubkey(cert);
	if (pkey == NULL || !EVP_PKEY_is_a(pkey, alg->name))
		goto end;

	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) != 1 ||
			len != alg->public_len)
		goto end;

	buf = OPENSSL_malloc(len);
	if (buf == NULL)
		goto end;

	if (EVP_PKEY_get_raw_public_key(pkey, buf, &len) != 1 ||
			len != alg->public_len)
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
	PKCS11_OBJECT_private *object;

	if (key == NULL || needs_free == NULL)
		return NULL;

	*needs_free = 0;

	if (key->object_class != CKO_PRIVATE_KEY)
		return key;

	object = pkcs11_object_from_object(key, session, CKO_PUBLIC_KEY);
	if (object != NULL && object->object != CK_INVALID_HANDLE) {
		*needs_free = 1;
		return object;
	}
	pkcs11_object_free(object);

	object = pkcs11_object_from_object(key, session, CKO_CERTIFICATE);
	if (object != NULL && object->object != CK_INVALID_HANDLE) {
		*needs_free = 1;
		return object;
	}
	pkcs11_object_free(object);

	return NULL;
}

/*
 * Retrieve raw public key bytes.
 *
 * For a private key, prefer a matching CKO_PUBLIC_KEY object and fall back
 * to a matching CKO_CERTIFICATE. Public-key material is read from the
 * algorithm-specific attribute or extracted from the certificate.
 *
 * The returned buffer is allocated with OPENSSL_malloc() and must be freed
 * by the caller.
 *
 * Returns 0 on success, -1 on failure.
 */
static int get_raw_public_key(PKCS11_OBJECT_private *key,
	const P11_RAW_ALGORITHM *alg, unsigned char **raw, size_t *rawlen)
{
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	PKCS11_OBJECT_private *obj = NULL;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int object_needs_free = 0;
	int ok = 0;

	if (key == NULL || key->slot == NULL || alg == NULL ||
			raw == NULL || rawlen == NULL)
		return -1;

	*raw = NULL;
	*rawlen = 0;
	slot = key->slot;
	ctx = slot->ctx;
	if (ctx == NULL)
		return -1;

	if (pkcs11_session_pool_acquire(slot, 0, &session))
		return -1;

	obj = pkcs11_choose_public_source(key, session, &object_needs_free);
	if (obj == NULL || obj->object == CK_INVALID_HANDLE)
		goto end;

	switch (obj->object_class) {
	case CKO_PUBLIC_KEY:
		ok = extract_pub_from_public_key_obj(ctx, session, obj->object,
			alg, raw, rawlen);
		break;
	case CKO_CERTIFICATE:
		ok = extract_pub_from_cert_obj(ctx, session, obj->object,
			alg, raw, rawlen);
		break;
	default:
		break;
	}

end:
	if (object_needs_free)
		pkcs11_object_free(obj);
	pkcs11_session_pool_release(slot, session);

	if (!ok) {
		OPENSSL_free(*raw);
		*raw = NULL;
		*rawlen = 0;
		return -1;
	}
	return 0;
}

/* Create an EVP_PKEY from raw public key material. */
static EVP_PKEY *pkcs11_get_evp_raw_key(PKCS11_OBJECT_private *key,
	const P11_RAW_ALGORITHM *alg)
{
	EVP_PKEY *pkey;
	const char *properties = NULL;
	unsigned char *raw = NULL;
	size_t rawlen = 0;

	if (get_raw_public_key(key, alg, &raw, &rawlen) < 0)
		return NULL;

	/* Falcon KEYMGMT is provided by pkcs11prov. Other algorithms use
	 * the default OpenSSL provider selection. */
	if (alg->type == EVP_PKEY_FALCON512 || alg->type == EVP_PKEY_FALCON1024)
		properties = "provider=pkcs11prov";

	/* Create a public-only EVP_PKEY using the selected KEYMGMT. */
	pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg->name, properties,
		raw, rawlen);
	OPENSSL_free(raw);
	if (pkey == NULL)
		return NULL;

#ifdef LIBP11_HAVE_ECX_METHODS
	if (!pkcs11_ecx_method_enable(key, alg->type)) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
#endif /* LIBP11_HAVE_ECX_METHODS */
	return pkey;
}

#define DEFINE_RAW_OBJECT_OPS(symbol, pkey_type, alg_name, pub_len, source) \
	static const P11_RAW_ALGORITHM symbol##_algorithm = { \
		pkey_type, alg_name, pub_len, source \
	}; \
	static EVP_PKEY *pkcs11_get_evp_key_##symbol(PKCS11_OBJECT_private *key) \
	{ \
		return pkcs11_get_evp_raw_key(key, &symbol##_algorithm); \
	} \
	PKCS11_OBJECT_ops pkcs11_##symbol##_ops = { \
		pkey_type, pkcs11_get_evp_key_##symbol \
	}

/* Falcon is implemented by pkcs11prov rather than the OpenSSL default provider. */
DEFINE_RAW_OBJECT_OPS(falcon512, EVP_PKEY_FALCON512, "FALCON-512",
	FALCON_512_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(falcon1024, EVP_PKEY_FALCON1024, "FALCON-1024",
	FALCON_1024_PUB_LEN, P11_RAW_FROM_VALUE);

#ifndef OPENSSL_NO_ECX
DEFINE_RAW_OBJECT_OPS(ed25519, EVP_PKEY_ED25519, "ED25519",
	ED25519_PUB_LEN, P11_RAW_FROM_EC_POINT);
DEFINE_RAW_OBJECT_OPS(ed448, EVP_PKEY_ED448, "ED448",
	ED448_PUB_LEN, P11_RAW_FROM_EC_POINT);
DEFINE_RAW_OBJECT_OPS(x25519, EVP_PKEY_X25519, "X25519",
	X25519_PUB_LEN, P11_RAW_FROM_EC_POINT);
DEFINE_RAW_OBJECT_OPS(x448, EVP_PKEY_X448, "X448",
	X448_PUB_LEN, P11_RAW_FROM_EC_POINT);
#endif /* OPENSSL_NO_ECX */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
DEFINE_RAW_OBJECT_OPS(mldsa44, EVP_PKEY_ML_DSA_44, "ML-DSA-44",
	ML_DSA_44_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(mldsa65, EVP_PKEY_ML_DSA_65, "ML-DSA-65",
	ML_DSA_65_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(mldsa87, EVP_PKEY_ML_DSA_87, "ML-DSA-87",
	ML_DSA_87_PUB_LEN, P11_RAW_FROM_VALUE);
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_ML_KEM
DEFINE_RAW_OBJECT_OPS(mlkem512, EVP_PKEY_ML_KEM_512, "ML-KEM-512",
	ML_KEM_512_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(mlkem768, EVP_PKEY_ML_KEM_768, "ML-KEM-768",
	ML_KEM_768_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(mlkem1024, EVP_PKEY_ML_KEM_1024, "ML-KEM-1024",
	ML_KEM_1024_PUB_LEN, P11_RAW_FROM_VALUE);
#endif /* OPENSSL_NO_ML_KEM */

#ifndef OPENSSL_NO_SLH_DSA
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_128s, EVP_PKEY_SLH_DSA_SHA2_128S,
	"SLH-DSA-SHA2-128s", SLH_DSA_128_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_128f, EVP_PKEY_SLH_DSA_SHA2_128F,
	"SLH-DSA-SHA2-128f", SLH_DSA_128_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_192s, EVP_PKEY_SLH_DSA_SHA2_192S,
	"SLH-DSA-SHA2-192s", SLH_DSA_192_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_192f, EVP_PKEY_SLH_DSA_SHA2_192F,
	"SLH-DSA-SHA2-192f", SLH_DSA_192_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_256s, EVP_PKEY_SLH_DSA_SHA2_256S,
	"SLH-DSA-SHA2-256s", SLH_DSA_256_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_sha2_256f, EVP_PKEY_SLH_DSA_SHA2_256F,
	"SLH-DSA-SHA2-256f", SLH_DSA_256_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_128s, EVP_PKEY_SLH_DSA_SHAKE_128S,
	"SLH-DSA-SHAKE-128s", SLH_DSA_128_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_128f, EVP_PKEY_SLH_DSA_SHAKE_128F,
	"SLH-DSA-SHAKE-128f", SLH_DSA_128_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_192s, EVP_PKEY_SLH_DSA_SHAKE_192S,
	"SLH-DSA-SHAKE-192s", SLH_DSA_192_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_192f, EVP_PKEY_SLH_DSA_SHAKE_192F,
	"SLH-DSA-SHAKE-192f", SLH_DSA_192_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_256s, EVP_PKEY_SLH_DSA_SHAKE_256S,
	"SLH-DSA-SHAKE-256s", SLH_DSA_256_PUB_LEN, P11_RAW_FROM_VALUE);
DEFINE_RAW_OBJECT_OPS(slhdsa_shake_256f, EVP_PKEY_SLH_DSA_SHAKE_256F,
	"SLH-DSA-SHAKE-256f", SLH_DSA_256_PUB_LEN, P11_RAW_FROM_VALUE);
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

#undef DEFINE_RAW_OBJECT_OPS
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
