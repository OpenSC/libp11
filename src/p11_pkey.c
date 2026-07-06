/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2017 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2017-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
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

#include "libp11-int.h"
#include <string.h>

#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif
#ifndef RSA_PSS_SALTLEN_AUTO
#define RSA_PSS_SALTLEN_AUTO -2
#endif
#ifndef RSA_PSS_SALTLEN_MAX
#define RSA_PSS_SALTLEN_MAX -3
#endif
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4
#endif

#if OPENSSL_VERSION_NUMBER < 0x40000000L
# ifndef OPENSSL_NO_EC
static int (*orig_pkey_ec_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_ec_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
# endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int (*orig_pkey_ed25519_digestsign)(EVP_MD_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
static int (*orig_pkey_ed448_digestsign)(EVP_MD_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

typedef struct {
	int nbits;
	BIGNUM *pub_exp;
	int gentmp[2];
	int pad_mode;
	const EVP_MD *md;
	const EVP_MD *mgf1md;
	int saltlen;
	unsigned char *tbuf;
} RSA_PKEY_CTX;

#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3000100L )

static int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (!rctx)
		return -1;
	*pmd = rctx->md;
	return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3010000L )

static int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (!rctx)
		return -1;
	*pmd = rctx->md;
	return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L

static int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (!rctx)
		return -1;
	*pmd = rctx->mgf1md;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *padding)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (!rctx)
		return -1;
	*padding = rctx->pad_mode;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (!rctx)
		return -1;
	*saltlen = rctx->saltlen;
	return 1;
}

static void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)
{
	memcpy((int *)dst + 2, (int *)src + 2, 25 * sizeof(void (*)()));
}

#endif

static int pkcs11_params_pss(CK_RSA_PKCS_PSS_PARAMS *pss_params, EVP_PKEY *pkey,
	int salt_len, const char *mdname, const char *mgf1_mdname,
	PKCS11_CTX_private *pctx)
{
	const EVP_MD *sig_md = NULL;
	const EVP_MD *mgf1_md = NULL;
	int digest_salt, max_salt;

	sig_md = EVP_get_digestbyname(mdname);
	if (sig_md == NULL)
		return -1;

	/* mgf1 default = signature digest */
	if (mgf1_mdname == NULL)
		mgf1_mdname = mdname;

	mgf1_md = EVP_get_digestbyname(mgf1_mdname);
	if (mgf1_md == NULL)
		return -1;

	digest_salt = EVP_MD_size(sig_md);
	max_salt = EVP_PKEY_size(pkey) - digest_salt - 2;

	if (((EVP_PKEY_bits(pkey) - 1) & 0x7) == 0)
		max_salt--;

	if (digest_salt < 0 || max_salt < 0)
		return -1;

	switch (salt_len) {
	case RSA_PSS_SALTLEN_DIGEST: /* -1 */
		/* sets the salt length to the digest length */
		salt_len = digest_salt;
		break;
	case RSA_PSS_SALTLEN_AUTO: /* -2 */
		/* for signing: it has the same meaning as RSA_PSS_SALTLEN_MAX */
	case RSA_PSS_SALTLEN_MAX:  /* -3 */
		/* sets the salt length to the maximum permissible value */
		salt_len = max_salt;
		break;
	case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX: /* -4 */
		/* for signing: use min(max_salt, digest_len) per FIPS 186-4 */
		salt_len = max_salt < digest_salt ? max_salt : digest_salt;
		break;
	default:
		if (salt_len < 0)
			return -1;
		break;
	}

	pkcs11_log(pctx, LOG_DEBUG, "salt_len=%d sig_md=%s mgf1_md=%s\n",
		salt_len, EVP_MD_name(sig_md), EVP_MD_name(mgf1_md));

	/* fill the CK_RSA_PKCS_PSS_PARAMS structure */
	memset(pss_params, 0, sizeof(CK_RSA_PKCS_PSS_PARAMS));
	pss_params->hashAlg = pkcs11_md2ckm(sig_md);
	pss_params->mgf = pkcs11_md2ckg(mgf1_md);
	if (!pss_params->hashAlg || !pss_params->mgf)
		return -1;

	pss_params->sLen = (CK_ULONG)salt_len;
	return 0;
}

static int pkcs11_oaep_param(CK_RSA_PKCS_OAEP_PARAMS *oaep_params,
	const char *oaep_mdname, const char *mgf1_mdname,
	unsigned char *oaep_label, size_t oaep_labellen,
	PKCS11_CTX_private *pctx)
{
	const EVP_MD *oaep_md = NULL;
	const EVP_MD *mgf1_md = NULL;

	if (oaep_mdname == NULL)
		oaep_mdname = "SHA1";

	oaep_md = EVP_get_digestbyname(oaep_mdname);
	if (oaep_md == NULL)
		return -1;

	/* mgf1 default = signature digest */
	if (mgf1_mdname == NULL)
		mgf1_mdname = oaep_mdname;

	mgf1_md = EVP_get_digestbyname(mgf1_mdname);
	if (mgf1_md == NULL)
		return -1;

	if (oaep_labellen > (size_t)((CK_ULONG)-1))
		return -1;

	pkcs11_log(pctx, LOG_DEBUG, "oaep_md=%s mgf1_md=%s oaep_labellen=%lu\n",
		EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md), oaep_labellen);

	/* fill the CK_RSA_PKCS_OAEP_PARAMS structure */
	memset(oaep_params, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
	oaep_params->hashAlg = pkcs11_md2ckm(oaep_md); /* CKM_SHA_1 */
	oaep_params->mgf = pkcs11_md2ckg(mgf1_md); /* CKG_MGF1_SHA1 */
	if (!oaep_params->hashAlg || !oaep_params->mgf)
		return -1;

	oaep_params->source = CKZ_DATA_SPECIFIED;
	oaep_params->pSourceData = oaep_label;
	oaep_params->ulSourceDataLen = (CK_ULONG)oaep_labellen;
	return 0;
}

/* Setup PKCS#11 RSA mechanism for signing. */
static int pkcs11_set_rsa_sign_mechanism(CK_MECHANISM *mechanism,
	CK_RSA_PKCS_PSS_PARAMS *pss_params,
	PKCS11_CTX_private *pctx, EVP_PKEY *pkey,
	const int padding, const int salt_len,
	const char *mdname, const char *mgf1_mdname)
{
	if (mechanism == NULL)
		return -1;

	memset(mechanism, 0, sizeof(CK_MECHANISM));

	switch (padding) {
	case RSA_PKCS1_PADDING:
		mechanism->mechanism = CKM_RSA_PKCS;
		break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		break;
	case RSA_X931_PADDING:
		/* RSA_X931_PADDING uses the legacy ANSI X9.31 signature format.
		 * This deprecated mode is not supported by SoftHSM or YubiKey
		 * PKCS#11 modules (no CKM_RSA_X9_31 support). */
		mechanism->mechanism = CKM_RSA_X9_31;
		break;
	case RSA_PKCS1_PSS_PADDING:
		if (pkcs11_params_pss(pss_params, pkey, salt_len, mdname,
			mgf1_mdname, pctx) != 0)
			return -1;
		mechanism->mechanism = CKM_RSA_PKCS_PSS;
		mechanism->pParameter = pss_params;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
		break;
	default:
		pkcs11_log(pctx, LOG_DEBUG, "%s:%d unsupported RSA signing padding: %d\n",
			__FILE__, __LINE__, padding);
		return -1;
	}

	return 0;
}

/* Setup PKCS#11 RSA mechanism for decryption. */
static int pkcs11_set_rsa_decrypt_mechanism(CK_MECHANISM *mechanism,
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params,
	PKCS11_CTX_private *pctx, const int padding,
	const char *mdname, const char *mgf1_mdname,
	unsigned char *oaep_label, size_t oaep_labellen)
{
	if (mechanism == NULL)
		return -1;

	memset(mechanism, 0, sizeof(CK_MECHANISM));

	switch (padding) {
	case RSA_PKCS1_PADDING:
		mechanism->mechanism = CKM_RSA_PKCS;
		break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		break;
	case RSA_PKCS1_OAEP_PADDING:
		if (pkcs11_oaep_param(oaep_params, mdname, mgf1_mdname,
			oaep_label, oaep_labellen, pctx) != 0)
			return -1;
		mechanism->mechanism = CKM_RSA_PKCS_OAEP;
		mechanism->pParameter = oaep_params;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		break;
	default:
		pkcs11_log(pctx, LOG_DEBUG, "%s:%d unsupported RSA decryption padding: %d\n",
			__FILE__, __LINE__, padding);
		return -1;
	}

	return 0;
}

const char *pkcs11_mechanism_name(CK_MECHANISM *mechanism)
{
	switch (mechanism->mechanism) {
	case CKM_RSA_PKCS:
		return "CKM_RSA_PKCS";
	case CKM_RSA_PKCS_PSS:
		return "CKM_RSA_PKCS_PSS";
	case CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP";
	case CKM_RSA_X_509:
		return "CKM_RSA_X_509";
	case CKM_RSA_X9_31:
		return "CKM_RSA_X9_31";
	case CKM_ECDSA:
		return "CKM_ECDSA";
	case CKM_EDDSA:
		return "CKM_EDDSA";
	case CKM_ML_DSA:
		return "CKM_ML_DSA";
	case CKM_SLH_DSA:
		return "CKM_SLH_DSA";
	case CKM_FALCON:
		return "CKM_FALCON";
	case CKM_PQC_FALCON:
		return "CKM_PQC_FALCON";
	case CKM_ECDH1_DERIVE:
		return "CKM_ECDH1_DERIVE";
	case CKM_ECDH1_COFACTOR_DERIVE:
		return "CKM_ECDH1_COFACTOR_DERIVE";
	default:
		return "UNKNOWN_MECHANISM";
	}
}

/*
 * Execute a PKCS#11 signing operation using the specified mechanism.
 *
 * If the token reports CKR_KEY_FUNCTION_NOT_PERMITTED the function
 * attempts a fallback using C_Encrypt(), as some tokens implement
 * RSA private-key operations through the encryption interface.
 *
 * Returns: CKR_OK on success or PKCS#11 error code on failure
 */
static int pkcs11_sign_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	int rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_siglen;
	CK_ULONG ck_tbslen;

	if (key == NULL || mechanism == NULL || siglen == NULL || tbs == NULL)
		return CKR_ARGUMENTS_BAD;

	slot = key->slot;
	if (slot == NULL)
		return CKR_GENERAL_ERROR;

	ctx = slot->ctx;
	if (ctx == NULL)
		return CKR_GENERAL_ERROR;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_sign_with_mechanism() "
		"%s sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__,
		pkcs11_mechanism_name(mechanism), sig, *siglen, tbs, tbslen);
#endif

	ck_siglen = (CK_ULONG)*siglen;
	ck_tbslen = (CK_ULONG)tbslen;

	if (pkcs11_get_session(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	rv = CRYPTOKI_call(ctx, C_SignInit(session, mechanism, key->object));
	if (rv == CKR_OK && key->always_authenticate == CK_TRUE) {
		rv = pkcs11_authenticate(key, session);
		if (rv != CKR_OK)
			goto end;
	}
	if (rv == CKR_OK)
		rv = CRYPTOKI_call(ctx,
			C_Sign(session, (CK_BYTE_PTR)tbs, ck_tbslen, sig, &ck_siglen));
	if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
		/* OpenSSL may use it for encryption rather than signing */
		rv = CRYPTOKI_call(ctx,
			C_EncryptInit(session, mechanism, key->object));
		if (rv == CKR_OK && key->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key, session);
		if (rv == CKR_OK)
			rv = CRYPTOKI_call(ctx,
				C_Encrypt(session, (CK_BYTE_PTR)tbs, ck_tbslen, sig, &ck_siglen));
		if (rv != CKR_OK) {
			pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Encrypt rv=%d\n",
				__FILE__, __LINE__, rv);
			goto end;
		}
	}
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Sign rv=%d\n",
			__FILE__, __LINE__, rv);
		goto end;
	}

	*siglen = (size_t)ck_siglen;

end:
	pkcs11_put_session(slot, session);
	return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Execute a PKCS#11 verify operation using the specified mechanism.
 *
 * Returns: CKR_OK on success or PKCS#11 error code on failure
 */
static int pkcs11_verify_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	int rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_siglen;
	CK_ULONG ck_tbslen;

	if (key == NULL || mechanism == NULL || sig == NULL || tbs == NULL)
		return CKR_ARGUMENTS_BAD;

	slot = key->slot;
	if (slot == NULL)
		return CKR_GENERAL_ERROR;

	ctx = slot->ctx;
	if (ctx == NULL)
		return CKR_GENERAL_ERROR;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_verify_with_mechanism() "
		"%s sig=%p siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__,
		pkcs11_mechanism_name(mechanism), sig, siglen, tbs, tbslen);
#endif

	ck_siglen = (CK_ULONG)siglen;
	ck_tbslen = (CK_ULONG)tbslen;

	if (pkcs11_get_session(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	rv = CRYPTOKI_call(ctx,
		C_VerifyInit(session, mechanism, key->object));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_VerifyInit rv=%d\n",
			__FILE__, __LINE__, rv);
		goto end;
	}

	rv = CRYPTOKI_call(ctx,
		C_Verify(session,
			(CK_BYTE_PTR)tbs, ck_tbslen,
			(CK_BYTE_PTR)sig, ck_siglen));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Verify rv=%d\n",
			__FILE__, __LINE__, rv);
		goto end;
	}

end:
	pkcs11_put_session(slot, session);
	return rv;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/*
 * Execute a PKCS#11 decryption operation using the specified mechanism.
 * Returns: CKR_OK on success or PKCS#11 error code on failure.
 */
static int pkcs11_decrypt_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	int rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_outlen;
	CK_ULONG ck_inlen;

	if (key == NULL || mechanism == NULL || outlen == NULL || in == NULL)
		return CKR_ARGUMENTS_BAD;

	slot = key->slot;
	if (slot == NULL)
		return CKR_GENERAL_ERROR;

	ctx = slot->ctx;
	if (ctx == NULL)
		return CKR_GENERAL_ERROR;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_decrypt_with_mechanism() "
		"%s out=%p *outlen=%lu in=%p inlen=%lu\n",
		__FILE__, __LINE__,
		pkcs11_mechanism_name(mechanism), out, *outlen, in, inlen);
#endif

	ck_outlen = (CK_ULONG)*outlen;
	ck_inlen = (CK_ULONG)inlen;

	if (pkcs11_get_session(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	rv = CRYPTOKI_call(ctx, C_DecryptInit(session, mechanism, key->object));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_DecryptInit rv=%d\n",
			__FILE__, __LINE__, rv);
		goto end;
	}

	if (key->always_authenticate == CK_TRUE) {
		rv = pkcs11_authenticate(key, session);
		if (rv != CKR_OK)
			goto end;
	}

	rv = CRYPTOKI_call(ctx,
		C_Decrypt(session, (CK_BYTE_PTR)in, ck_inlen, out, &ck_outlen));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Decrypt rv=%d\n",
			__FILE__, __LINE__, rv);
		goto end;
	}

	*outlen = (size_t)ck_outlen;

end:
	pkcs11_put_session(slot, session);
	return rv;
}

#ifndef OPENSSL_NO_EC
/*
 * Execute a PKCS#11 derive operation using the specified mechanism.
 * Returns: CKR_OK on success or PKCS#11/vendor defined error code on failure.
 */
static CK_RV pkcs11_derive_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism, unsigned char *secret, size_t *secretlen)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_BBOOL ck_false = CK_FALSE;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ULONG newkey_len = 0;
	unsigned char *value = NULL;
	size_t len, value_len_alloc = 0;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &ck_false, sizeof(ck_false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_VALUE_LEN, &newkey_len, sizeof(newkey_len)},
		{CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
		{CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
		{CKA_DERIVE, &ck_true, sizeof(ck_true)},
	};

	if (key == NULL || mechanism == NULL || secret == NULL ||
			secretlen == NULL || *secretlen == 0)
		return CKR_ARGUMENTS_BAD;

	if (*secretlen > (size_t)(CK_ULONG)-1)
		return CKR_ARGUMENTS_BAD;

	slot = key->slot;
	if (slot == NULL)
		return CKR_GENERAL_ERROR;

	ctx = slot->ctx;
	if (ctx == NULL)
		return CKR_GENERAL_ERROR;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_derive_with_mechanism() "
		"%s secret=%p *secretlen=%lu\n",
		__FILE__, __LINE__,
		pkcs11_mechanism_name(mechanism), secret, (unsigned long)*secretlen);
#endif

	if (pkcs11_get_session(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	if (key->always_authenticate == CK_TRUE) {
		rv = pkcs11_authenticate(key, session);
		if (rv != CKR_OK)
			goto end;
	}

	len = *secretlen;
	newkey_len = (CK_ULONG)len;

	rv = CRYPTOKI_call(ctx, C_DeriveKey(session, mechanism, key->object,
		newkey_template, sizeof(newkey_template)/sizeof(*newkey_template),
		&newkey));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_DeriveKey rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
		goto end;
	}

	if (pkcs11_getattr_alloc(ctx, session, newkey, CKA_VALUE,
			&value, &value_len_alloc)) {
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	if (value_len_alloc > len) {
		*secretlen = value_len_alloc;
		rv = CKR_BUFFER_TOO_SMALL;
		goto end;
	}

	memcpy(secret, value, value_len_alloc);
	*secretlen = value_len_alloc;
	rv = CKR_OK;

end:
	if (newkey != CK_INVALID_HANDLE)
		CRYPTOKI_call(ctx, C_DestroyObject(session, newkey));

	OPENSSL_clear_free(value, value_len_alloc);
	pkcs11_put_session(slot, session);
	return rv;
}

/* DER-encode data as an ASN.1 OCTET STRING. */
static unsigned char *der_encode_octet_string(const unsigned char *data,
	size_t data_len, size_t *der_len)
{
	ASN1_OCTET_STRING *os = NULL;
	unsigned char *der = NULL, *p;
	int len;

	if (data == NULL || data_len == 0 || der_len == NULL)
		return NULL;

	if (data_len > INT_MAX)
		return NULL;

	os = ASN1_OCTET_STRING_new();
	if (os == NULL)
		return NULL;

	if (!ASN1_OCTET_STRING_set(os, data, (int)data_len))
		goto err;

	len = i2d_ASN1_OCTET_STRING(os, NULL);
	if (len <= 0)
		goto err;

	der = OPENSSL_malloc((size_t)len);
	if (der == NULL)
		goto err;

	p = der;
	if (i2d_ASN1_OCTET_STRING(os, &p) != len)
		goto err;

	*der_len = (size_t)len;
	ASN1_OCTET_STRING_free(os);
	return der;

err:
	OPENSSL_free(der);
	ASN1_OCTET_STRING_free(os);
	return NULL;
}
#endif /* OPENSSL_NO_EC */

/* Build ASN.1 DigestInfo for PKCS#1 v1.5 signing. */
static int pkcs11_build_digestinfo(const char *mdname,
	const unsigned char *dgst, size_t dgstlen,
	unsigned char **out, size_t *outlen)
{
	const EVP_MD *md;
	X509_SIG *x509_sig = NULL;
	X509_ALGOR *alg = NULL;
	ASN1_OCTET_STRING *digest = NULL;
	unsigned char *p;
	int len;

	if (mdname == NULL || dgst == NULL || out == NULL || outlen == NULL)
		return 0;

	*out = NULL;
	*outlen = 0;

	md = EVP_get_digestbyname(mdname);
	if (md == NULL)
		return 0;

	if (EVP_MD_size(md) <= 0 || dgstlen != (size_t)EVP_MD_size(md))
		return 0;

	x509_sig = X509_SIG_new();
	if (x509_sig == NULL)
		return 0;

	X509_SIG_getm(x509_sig, &alg, &digest);

	if (!X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_type(md)), V_ASN1_NULL, NULL))
		goto err;

	if (!ASN1_OCTET_STRING_set(digest, dgst, (int)dgstlen))
		goto err;

	len = i2d_X509_SIG(x509_sig, NULL);
	if (len <= 0)
		goto err;

	*out = OPENSSL_malloc((size_t)len);
	if (*out == NULL)
		goto err;

	p = *out;
	len = i2d_X509_SIG(x509_sig, &p);
	if (len <= 0)
		goto err;

	*outlen = (size_t)len;
	X509_SIG_free(x509_sig);
	return 1;

err:
	OPENSSL_free(*out);
	*out = NULL;
	*outlen = 0;
	X509_SIG_free(x509_sig);
	return 0;
}

/* Build digest || X9.31 hash ID for RSA_X931_PADDING signing. */
static int pkcs11_build_x931_digest(const char *mdname,
	const unsigned char *dgst, size_t dgstlen,
	unsigned char **out, size_t *outlen)
{
	const EVP_MD *md;
	int md_size;
	int hash_id;

	if (mdname == NULL || dgst == NULL || out == NULL || outlen == NULL)
		return 0;

	*out = NULL;
	*outlen = 0;

	md = EVP_get_digestbyname(mdname);
	if (md == NULL)
		return 0;

	md_size = EVP_MD_size(md);
	if (md_size <= 0 || dgstlen != (size_t)md_size)
		return 0;

	hash_id = RSA_X931_hash_id(EVP_MD_type(md));
	if (hash_id == -1)
		return 0;

	*out = OPENSSL_malloc(dgstlen + 1);
	if (*out == NULL)
		return 0;

	memcpy(*out, dgst, dgstlen);
	(*out)[dgstlen] = (unsigned char)hash_id;
	*outlen = dgstlen + 1;

	return 1;
}

/*
 * Sign input data with an RSA private key using a PKCS#11 token.
 *
 * For RSA_PKCS1_PADDING, if mdname is set, the input must be the message
 * digest and is wrapped in an ASN.1 DigestInfo structure before signing with
 * CKM_RSA_PKCS. If mdname is not set, the input is signed directly.
 *
 * For RSA_PKCS1_PSS_PADDING, the input must be the message digest. The digest
 * algorithm, MGF1 digest and salt length are passed separately in
 * CK_RSA_PKCS_PSS_PARAMS.
 *
 * For RSA_X931_PADDING, if mdname is set, append the X9.31 hash
 * identifier to the digest before passing it to CKM_RSA_X9_31.
 * If mdname is not set, the input is expected to contain the hash ID.
 *
 * For RSA_NO_PADDING, the input is passed to the token unchanged.
 *
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_rsa_sign(PKCS11_OBJECT_private *key, EVP_PKEY *pkey,
	const char *mdname, const int pad_mode,
	const int salt_len, const char *mgf1_mdname,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_RSA_PKCS_PSS_PARAMS pss_params;
	const unsigned char *sign_tbs = tbs;
	size_t sign_tbslen = tbslen;
	unsigned char *encoded = NULL;
	size_t encoded_len = 0;
	int ret = -1;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	slot = key->slot;
	if (slot == NULL)
		return -1;

	ctx = slot->ctx;
	if (ctx == NULL)
		return -1;

	if (pkcs11_set_rsa_sign_mechanism(&mechanism, &pss_params, ctx, pkey,
		pad_mode, salt_len, mdname, mgf1_mdname) < 0)
		return -1;

	switch (pad_mode) {
	case RSA_PKCS1_PADDING:
		if (mdname != NULL) {
			/* Build ASN.1 DigestInfo for PKCS#1 v1.5 signing */
			if (!pkcs11_build_digestinfo(mdname,
				tbs, tbslen, &encoded, &encoded_len))
				goto end;

			sign_tbs = encoded;
			sign_tbslen = encoded_len;
		}
		break;
	case RSA_X931_PADDING:
		if (mdname != NULL) {
			/* Append X9.31 hash identifier to the digest */
			if (!pkcs11_build_x931_digest(mdname,
				tbs, tbslen, &encoded, &encoded_len))
				goto end;

			sign_tbs = encoded;
			sign_tbslen = encoded_len;
		}
		break;
	default:
		break;
	}

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		sign_tbs, sign_tbslen) != CKR_OK)
		goto end;

	ret = 1;

end:
	OPENSSL_free(encoded);
	return ret;
}

#ifndef OPENSSL_NO_EC
/*
 * Sign data via PKCS#11 (CKM_ECDSA) and convert raw r||s output
 * into an OpenSSL ECDSA_SIG structure. Returns NULL on failure.
 */
ECDSA_SIG *pkcs11_ec_sign_raw(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;
	ECDSA_SIG *ecdsa = NULL;
	BIGNUM *r = NULL, *s = NULL;
	size_t tmp_len;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return NULL;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return NULL;

	tmp_len = *siglen;
	if (tmp_len == 0 || tmp_len % 2 != 0 || tmp_len / 2 > INT_MAX)
		return NULL;

	r = BN_bin2bn(sig, (int)(tmp_len / 2), NULL);
	s = BN_bin2bn(sig + tmp_len / 2, (int)(tmp_len / 2), NULL);
	if (r == NULL || s == NULL)
		goto error;

	ecdsa = ECDSA_SIG_new();
	if (ecdsa == NULL)
		goto error;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL)
	if (ECDSA_SIG_set0(ecdsa, r, s) != 1)
		goto error;
#else
	BN_free(ecdsa->r);
	ecdsa->r = r;
	BN_free(ecdsa->s);
	ecdsa->s = s;
#endif
	/* Ownership of r and s has been transferred to ecdsa */
	r = NULL;
	s = NULL;
	return ecdsa;
error:
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(ecdsa);
	return NULL;
}

/*
 * Sign digest input with EC private key via PKCS#11 and encode signature as DER.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_ec_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	ECDSA_SIG *ecdsa;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	ecdsa = pkcs11_ec_sign_raw(key, sig, siglen, tbs, tbslen);
	if (!ecdsa)
		return -1;

	*siglen = i2d_ECDSA_SIG(ecdsa, &sig);
	ECDSA_SIG_free(ecdsa);
	return (*siglen > 0) ? 1 : -1;
}
#endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Sign message input with EdDSA private key via PKCS#11 mechanism.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_eddsa_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_EDDSA;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
/*
 * Sign message input with ML-DSA private key via PKCS#11 mechanism.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_mldsa_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ML_DSA;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_SLH_DSA
/*
 * Sign message input with SLH-DSA private key via PKCS#11 mechanism.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_slhdsa_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_SLH_DSA;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Sign message input with PQC FALCON private key via PKCS#11 mechanism.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_falcon_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	/* Luna Token documents Falcon signing with CKM_PQC_FALCON.
	 * TODO: Verify CKM_FALCON compatibility. */
	mechanism.mechanism = CKM_PQC_FALCON;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
}

/*
 * Verify message input with PQC FALCON public key via PKCS#11 mechanism.
 * Returns 1 on success or -1 on failure.
 */
int pkcs11_evp_pkey_falcon_verify(PKCS11_OBJECT_private *key,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || sig == NULL || tbs == NULL)
		return -1;

	if (siglen == 0 || tbslen == 0)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_PQC_FALCON;

	if (pkcs11_verify_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/*
 * Decrypt RSA input via PKCS#11 using configured padding and OAEP parameters.
 * EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an encoding parameter
 * (OAEP label).
 */
int pkcs11_evp_pkey_rsa_decrypt(PKCS11_OBJECT_private *key,
	const char *mdname, const int pad_mode,
	const char *mgf1_mdname, unsigned char *oaep_label, size_t oaep_labellen,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	CK_MECHANISM mechanism;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	int rv;

	if (key == NULL || outlen == NULL || in == NULL)
		return -1;

	slot = key->slot;
	if (slot == NULL)
		return -1;

	ctx = slot->ctx;
	if (ctx == NULL)
		return -1;

	if (oaep_labellen > 0)
		pkcs11_log(ctx, LOG_WARNING, "OAEP label may not be supported by PKCS#11 token\n");

	if (pkcs11_set_rsa_decrypt_mechanism(&mechanism, &oaep_params, ctx,
		pad_mode, mdname, mgf1_mdname, oaep_label, oaep_labellen) < 0)
		return -1;

	rv = pkcs11_decrypt_with_mechanism(key, &mechanism, out, outlen,
		in, inlen);
	if (rv != CKR_OK)
		return -1;

	return (int)*outlen;
}

#ifndef OPENSSL_NO_EC
/*
 * Derive an ECDH shared secret.  Raw uncompressed peer EC points are tried
 * first, with a fallback to the DER OCTET STRING form used by CKA_EC_POINT.
 */
extern int pkcs11_evp_pkey_ecdh_derive(PKCS11_OBJECT_private *key,
	const unsigned char *peer_pub, size_t peer_pub_len,
	int cofactor_mode, unsigned char *secret, size_t *secretlen)
{
	CK_MECHANISM mechanism;
	CK_ECDH1_DERIVE_PARAMS derive_params;
	unsigned char *der_pub = NULL;
	size_t der_pub_len = 0;
	size_t saved_secretlen = 0;
	CK_RV rv;

	if (key == NULL || peer_pub == NULL || peer_pub_len == 0 || secretlen == NULL)
		return -1;

	if (peer_pub_len > (size_t)(CK_ULONG)-1)
		return -1;

	memset(&derive_params, 0, sizeof(derive_params));
	derive_params.kdf = CKD_NULL;
	derive_params.pSharedData = NULL_PTR;
	derive_params.ulSharedDataLen = 0;
	derive_params.pPublicData = (CK_BYTE_PTR)peer_pub;
	derive_params.ulPublicDataLen = (CK_ULONG)peer_pub_len;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = cofactor_mode == 1
			? CKM_ECDH1_COFACTOR_DERIVE : CKM_ECDH1_DERIVE;

	/* Both ECDH variants use CK_ECDH1_DERIVE_PARAMS.
	 * The mechanism type selects plain vs cofactor ECDH; the token
	 * obtains the cofactor from the EC domain parameters. */
	mechanism.pParameter = &derive_params;
	mechanism.ulParameterLen = sizeof(derive_params);

	saved_secretlen = *secretlen;
	rv = pkcs11_derive_with_mechanism(key, &mechanism, secret, secretlen);
	if (rv == CKR_OK)
		return 1;

	/*
	 * SoftHSM accepts raw uncompressed EC points in pPublicData, while
	 * some tokens such as Luna expect the DER OCTET STRING form used by
	 * CKA_EC_POINT. Try raw first and fall back to DER-wrapped form on
	 * CKR_ECC_POINT_INVALID.
	 */
	if (rv != CKR_ECC_POINT_INVALID || peer_pub[0] != POINT_CONVERSION_UNCOMPRESSED)
		return -1;

	der_pub = der_encode_octet_string(peer_pub, peer_pub_len, &der_pub_len);
	if (der_pub == NULL || der_pub_len > (size_t)(CK_ULONG)-1) {
		OPENSSL_free(der_pub);
		return -1;
	}

	*secretlen = saved_secretlen;
	derive_params.pPublicData = der_pub;
	derive_params.ulPublicDataLen = (CK_ULONG)der_pub_len;

	rv = pkcs11_derive_with_mechanism(key, &mechanism, secret, secretlen);

	OPENSSL_clear_free(der_pub, der_pub_len);

	if (rv != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Derive an X25519/X448 shared secret using CKM_ECDH1_DERIVE and a raw
 * RFC 7748 peer public key.
 * TODO: Test this path once a token/module advertising
 * EC_MONTGOMERY derive support is available.
 */
extern int pkcs11_evp_pkey_xdh_derive(PKCS11_OBJECT_private *key,
	const unsigned char *peer_pub, size_t peer_pub_len,
	unsigned char *secret, size_t *secretlen)
{
	CK_MECHANISM mechanism;
	CK_ECDH1_DERIVE_PARAMS derive_params;
	CK_RV rv;

	if (key == NULL || peer_pub == NULL || peer_pub_len == 0 || secretlen == NULL)
		return -1;

	if (peer_pub_len > (size_t)(CK_ULONG)-1)
		return -1;

	memset(&derive_params, 0, sizeof(derive_params));
	derive_params.kdf = CKD_NULL;
	derive_params.pSharedData = NULL_PTR;
	derive_params.ulSharedDataLen = 0;
	derive_params.pPublicData = (CK_BYTE_PTR)peer_pub;
	derive_params.ulPublicDataLen = (CK_ULONG)peer_pub_len;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDH1_DERIVE;
	mechanism.pParameter = &derive_params;
	mechanism.ulParameterLen = sizeof(derive_params);

	/* X25519/X448 use CKM_ECDH1_DERIVE with raw RFC 7748 public keys
	 * on tokens that support EC_MONTGOMERY derive. */
	rv = pkcs11_derive_with_mechanism(key, &mechanism, secret, secretlen);
	if (rv != CKR_OK)
		return -1;

	return 1;
}
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER < 0x40000000L
#ifndef OPENSSL_NO_EC

static int pkcs11_try_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	PKCS11_OBJECT_private *key;
	PKCS11_SLOT_private *slot;
	CK_SESSION_HANDLE session;
	const EVP_MD *sig_md;

	if (!evp_pkey_ctx)
		return -1;

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;

	if (tbslen < (size_t)EVP_MD_size(sig_md))
		return -1;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (!pkey)
		return -1;

	eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
	if (!eckey)
		return -1;

	if (!sig) {
		*siglen = (size_t)ECDSA_size(eckey);
		return 1; /* length query */
	}

	if (*siglen < (size_t)ECDSA_size(eckey))
		return -1; /* buffer too small */

	key = pkcs11_get_ex_data_ec(eckey);
	if (check_object_fork(key) < 0)
		return -1;

	slot = key->slot;
	if (!slot)
		return -1;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	pkcs11_put_session(slot, session);

	return pkcs11_evp_pkey_ec_sign(key, sig, siglen, tbs, tbslen);
}
#endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
/* PKCS#11 sign implementation for Ed25519 / Ed448 */
static int pkcs11_eddsa_sign(unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen, PKCS11_OBJECT_private *key)
{
	PKCS11_SLOT_private *slot;
	CK_SESSION_HANDLE session;

	slot = key->slot;
	if (!slot)
		return -1;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	pkcs11_put_session(slot, session);

	return pkcs11_evp_pkey_eddsa_sign(key, sig, siglen, tbs, tbslen);
}

/*
 * EVP_PKEY method sign wrapper for EdDSA.
 * This function is invoked internally by EVP_PKEY_sign().
 * If the key belongs to PKCS#11, perform signing via pkcs11_eddsa_sign().
 */
static int pkcs11_eddsa_pmeth_sign(EVP_PKEY_CTX *evp_pkey_ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	int rv;

	if (!evp_pkey_ctx)
		return -1;

	if (*siglen > UINT_MAX)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (!pkey)
		return -1;

	key = pkcs11_get_ex_data_pkey(pkey);
	if (!key)
		return -1;

	if (check_object_fork(key) < 0)
		return -1;

	rv = pkcs11_eddsa_sign(sig, siglen, tbs, tbslen, key);
	if (rv < 0)
		return -1;

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
	rv = pkcs11_eddsa_sign(sig, siglen, tbs, tbslen, key);
	if (rv < 0)
		return 1;

	return 1;
}

static int pkcs11_pkey_ed25519_digestsign(EVP_MD_CTX *ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_eddsa_pmeth_digestsign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_ed25519_digestsign)(ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static int pkcs11_pkey_ed448_digestsign(EVP_MD_CTX *ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_eddsa_pmeth_digestsign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_ed448_digestsign)(ctx, sig, siglen, tbs, tbslen);
	return ret;
}

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
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#ifndef OPENSSL_NO_EC
static int pkcs11_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_try_pkey_ec_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_ec_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_ec(void)
{
	EVP_PKEY_METHOD *new_meth;
#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_METHOD *orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_EC);
#else
	const EVP_PKEY_METHOD *orig_meth = EVP_PKEY_meth_find(EVP_PKEY_EC);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER) */

	EVP_PKEY_meth_get_sign(orig_meth,
		&orig_pkey_ec_sign_init, &orig_pkey_ec_sign);

	new_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);

	EVP_PKEY_meth_copy(new_meth, orig_meth);

	EVP_PKEY_meth_set_sign(new_meth,
		orig_pkey_ec_sign_init, pkcs11_pkey_ec_sign);

	return new_meth;
}
#endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
static EVP_PKEY_METHOD *pkcs11_pkey_method_ed25519(void)
{
	EVP_PKEY_METHOD *new_meth;
#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_METHOD *orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_ED25519);
#else
	const EVP_PKEY_METHOD *orig_meth = EVP_PKEY_meth_find(EVP_PKEY_ED25519);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER) */

	/* The digestsign() method is used to generate a signature in a one-shot mode */
	EVP_PKEY_meth_get_digestsign(orig_meth, &orig_pkey_ed25519_digestsign);
	
	/* Don't assume any digest related defaults */
	new_meth = EVP_PKEY_meth_new(EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM);

	/* Duplicate the original method */
	EVP_PKEY_meth_copy(new_meth, orig_meth);

	/* Override selected ED25519 method callbacks with PKCS#11 implementations */
	EVP_PKEY_meth_set_sign(new_meth, NULL, pkcs11_eddsa_pmeth_sign);
	EVP_PKEY_meth_set_digestsign(new_meth, pkcs11_pkey_ed25519_digestsign);
	EVP_PKEY_meth_set_ctrl(new_meth, pkcs11_eddsa_pmeth_ctrl, NULL);

	return new_meth;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_ed448(void)
{
	EVP_PKEY_METHOD *new_meth;
#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_METHOD *orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_ED448);
#else
	const EVP_PKEY_METHOD *orig_meth = EVP_PKEY_meth_find(EVP_PKEY_ED448);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER) */

	/* The digestsign() method is used to generate a signature in a one-shot mode */
	EVP_PKEY_meth_get_digestsign(orig_meth, &orig_pkey_ed448_digestsign);

	/* Don't assume any digest related defaults */
	new_meth = EVP_PKEY_meth_new(EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM);

	/* Duplicate the original method */
	EVP_PKEY_meth_copy(new_meth, orig_meth);

	/* Override selected ED448 method callbacks with PKCS#11 implementations */
	EVP_PKEY_meth_set_sign(new_meth, NULL, pkcs11_eddsa_pmeth_sign);
	EVP_PKEY_meth_set_digestsign(new_meth, pkcs11_pkey_ed448_digestsign);
	EVP_PKEY_meth_set_ctrl(new_meth, pkcs11_eddsa_pmeth_ctrl, NULL);

	return new_meth;
}
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
#ifndef OPENSSL_NO_EC
		EVP_PKEY_EC,
#endif /* OPENSSL_NO_EC */
#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
		EVP_PKEY_ED25519,
		EVP_PKEY_ED448,
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
#ifndef OPENSSL_NO_EC
	static EVP_PKEY_METHOD *pkey_method_ec = NULL;
#endif /* OPENSSL_NO_EC */
#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	static EVP_PKEY_METHOD *pkey_method_ed448 = NULL;
	static EVP_PKEY_METHOD *pkey_method_ed25519 = NULL;
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

	(void)e; /* squash the unused parameter warning */
	/* all PKCS#11 engines currently share the same pkey_meths */

	if (!pmeth) { /* get the list of supported nids */
		*nids = pkey_nids;
		return sizeof(pkey_nids) / sizeof(int) - 1;
	}

	/* get the EVP_PKEY_METHOD */
	switch (nid) {
	case EVP_PKEY_RSA:
		if (!pkey_method_rsa)
			pkey_method_rsa = pkcs11_pkey_method_rsa();
		if (!pkey_method_rsa)
			return 0;
		*pmeth = pkey_method_rsa;
		return 1; /* success */
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		if (!pkey_method_ec)
			pkey_method_ec = pkcs11_pkey_method_ec();
		if (!pkey_method_ec)
			return 0;
		*pmeth = pkey_method_ec;
		return 1; /* success */
#endif /* OPENSSL_NO_EC */
#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED448:
		if (!pkey_method_ed448)
			pkey_method_ed448 = pkcs11_pkey_method_ed448();
		if (!pkey_method_ed448)
			return 0;
		*pmeth = pkey_method_ed448;
		return 1; /* success */
	case EVP_PKEY_ED25519:
		if (!pkey_method_ed25519)
			pkey_method_ed25519 = pkcs11_pkey_method_ed25519();
		if (!pkey_method_ed25519)
			return 0;
		*pmeth = pkey_method_ed25519;
		return 1; /* success */
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
	}
	*pmeth = NULL;
	return 0;
}

#else /* OPENSSL_VERSION_NUMBER < 0x40000000L */

int PKCS11_pkey_meths(void *e, void **pmeth, const int **nids, int nid)
{
	(void)e;
	(void)pmeth;
	(void)nids;
	(void)nid;
	fprintf(stderr, "PKCS11_pkey_meths is not available: ENGINE support was disabled for OpenSSL 4.x\n");
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

/* vim: set noexpandtab: */
