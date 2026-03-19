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

#  if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int (*orig_pkey_ed25519_digestsign)(EVP_MD_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
static int (*orig_pkey_ed448_digestsign)(EVP_MD_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
#  endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
# endif /* OPENSSL_NO_EC */
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

	pkcs11_log(pctx, LOG_DEBUG, "salt_len=%d sig_md=%s mdf1_md=%s\n",
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
	unsigned char *oaep_label, const int oaep_labellen,
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

	pkcs11_log(pctx, LOG_DEBUG, "oaep_md=%s mdf1_md=%s\n",
		EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md));

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

/* Setup PKCS#11 mechanisms for signing */
static int pkcs11_mechanism(CK_MECHANISM *mechanism,
	CK_RSA_PKCS_PSS_PARAMS *pss_params,
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params,
	PKCS11_CTX_private *pctx, EVP_PKEY *pkey,
	const int padding, const int salt_len,
	const char *mdname, const char *mgf1_mdname,
	unsigned char *oaep_label, const int oaep_labellen)
{
	if (mechanism == NULL)
		return -1;

	memset(mechanism, 0, sizeof(CK_MECHANISM));
	mechanism->pParameter = NULL;
	mechanism->ulParameterLen = 0;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		mechanism->mechanism = CKM_RSA_PKCS;
		pkcs11_log(pctx, LOG_DEBUG, "padding=RSA_PKCS1_PADDING\n");
		break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		pkcs11_log(pctx, LOG_DEBUG, "padding=RSA_NO_PADDING\n");
		break;
	case RSA_X931_PADDING:
		mechanism->mechanism = CKM_RSA_X9_31;
		pkcs11_log(pctx, LOG_DEBUG, "padding=RSA_X931_PADDING\n");
		break;
	case RSA_PKCS1_PSS_PADDING:
		if (pkcs11_params_pss(pss_params, pkey, salt_len, mdname,
			mgf1_mdname, pctx) != 0)
			return -1;
		mechanism->mechanism = CKM_RSA_PKCS_PSS;
		mechanism->pParameter = pss_params;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
		pkcs11_log(pctx, LOG_DEBUG, "padding=RSA_PKCS1_PSS_PADDING\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		if (pkcs11_oaep_param(oaep_params, mdname, mgf1_mdname,
			oaep_label, oaep_labellen, pctx) != 0)
			return -1;
		mechanism->mechanism = CKM_RSA_PKCS_OAEP;
		mechanism->pParameter = oaep_params;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		pkcs11_log(pctx, LOG_DEBUG, "padding=RSA_PKCS1_OAEP_PADDING\n");
		break;
	default:
		pkcs11_log(pctx, LOG_DEBUG, "%s:%d unsupported padding: %d\n",
			__FILE__, __LINE__, padding);
		return -1;
	}
	return 0;
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
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
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

/*
 * Sign input data with an RSA private key using a PKCS#11 token.
 *
 * For RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING and RSA_X931_PADDING,
 * the input must be the message digest.
 *
 * For RSA_PKCS1_PADDING, the token performs PKCS#1 v1.5 DigestInfo
 * encoding internally based on the selected digest algorithm.
 *
 * For RSA_PKCS1_PSS_PADDING, the digest algorithm, MGF1 digest and
 * salt length are passed separately in CK_RSA_PKCS_PSS_PARAMS.
 *
 * For RSA_X931_PADDING, the token applies X9.31 signature formatting
 * based on the provided digest.
 *
 * For RSA_NO_PADDING, the input is passed to the token unchanged.
 *
 * Returns the signature length on success or -1 on failure.
 */
int pkcs11_evp_pkey_rsa_sign(PKCS11_OBJECT_private *key, EVP_PKEY *pkey,
	const char *mdname, const int pad_mode, const int salt_len,
	const char *mgf1_mdname, unsigned char *oaep_label, const int oaep_labellen,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_RSA_PKCS_PSS_PARAMS pss_params;
	int rv;

	slot = key->slot;
	if (slot == NULL)
		return -1;

	ctx = slot->ctx;
	if (ctx == NULL)
		return -1;

	if (pkcs11_mechanism(&mechanism, &pss_params, NULL,
		ctx, pkey, pad_mode, salt_len, mdname, mgf1_mdname,
		oaep_label, oaep_labellen) < 0)
		return -1;

	rv = pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen);

	if (rv != CKR_OK)
		return -1;

	return (int)*siglen;
}

#ifndef OPENSSL_NO_EC
/* Sign digest input with EC private key via PKCS#11 and encode signature as DER */
int pkcs11_evp_pkey_ec_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	ECDSA_SIG *ossl_sig = NULL;
	CK_MECHANISM mechanism;
	size_t raw_siglen;
	int rv = -1;

	ossl_sig = ECDSA_SIG_new();
	if (ossl_sig == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	raw_siglen = *siglen;
	rv = pkcs11_sign_with_mechanism(key, &mechanism, sig, &raw_siglen, tbs, tbslen);
	if (rv == CKR_OK) {
		BIGNUM *r = BN_bin2bn(sig, raw_siglen / 2, NULL);
		BIGNUM *s = BN_bin2bn(sig + raw_siglen / 2, raw_siglen / 2, NULL);

		if (r == NULL || s == NULL)
			goto error;

		if (ECDSA_SIG_set0(ossl_sig, r, s) != 1) {
			BN_free(r);
			BN_free(s);
			goto error;
		}
		*siglen = i2d_ECDSA_SIG(ossl_sig, &sig);
		rv = (*siglen > 0) ? CKR_OK : CKR_GENERAL_ERROR;
	}

error:
	ECDSA_SIG_free(ossl_sig);

	if (rv != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_NO_EC */

/* Sign message input with EdDSA private key via PKCS#11 mechanism */
int pkcs11_evp_pkey_eddsa_sign(PKCS11_OBJECT_private *key,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_MECHANISM mechanism;
	int rv;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_EDDSA;

	rv = pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen, tbs, tbslen);
	if (rv != CKR_OK)
		return -1;

	return (int)*siglen;
}

/*
 * Decrypt RSA input via PKCS#11 using configured padding and OAEP parameters.
 * EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter (OAEP label)
 */
int pkcs11_evp_pkey_rsa_decrypt(PKCS11_OBJECT_private *key, EVP_PKEY *pkey,
	const char *mdname, const int pad_mode,
	const char *mgf1_mdname, unsigned char *oaep_label, const int oaep_labellen,
	unsigned char *out, size_t *outlen,
	size_t *outsize, const unsigned char *in, size_t inlen)
{
	CK_MECHANISM mechanism;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_ULONG ck_outlen;
	CK_ULONG ck_inlen;
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

	if (pkcs11_mechanism(&mechanism, NULL, &oaep_params,
		ctx, pkey, pad_mode, 0, mdname, mgf1_mdname,
		oaep_label, oaep_labellen) < 0)
		return -1;

	/* caller-provided output buffer size */
	if (outsize != NULL)
		ck_outlen = (CK_ULONG)*outsize;
	else
		ck_outlen = (CK_ULONG)*outlen;

	ck_inlen = (CK_ULONG)inlen;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;

	rv = CRYPTOKI_call(ctx, C_DecryptInit(session, &mechanism, key->object));
	if (rv == CKR_OK && key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);

	if (rv == CKR_OK)
		rv = CRYPTOKI_call(ctx,
			C_Decrypt(session, (CK_BYTE_PTR)in, ck_inlen, out, &ck_outlen));

	pkcs11_put_session(slot, session);

	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Decrypt rv=%d\n",
			__FILE__, __LINE__, rv);
		return -1;
	}

	*outlen = (size_t)ck_outlen;
	return (int)*outlen;
}


#if OPENSSL_VERSION_NUMBER < 0x40000000L
#ifndef OPENSSL_NO_EC

static int pkcs11_try_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	int rv = CKR_GENERAL_ERROR;
	CK_ULONG size = (CK_ULONG)*siglen;
	PKCS11_OBJECT_private *key;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	const EVP_MD *sig_md;
	ECDSA_SIG *ossl_sig;
	CK_MECHANISM mechanism;

	ossl_sig = ECDSA_SIG_new();
	if (!ossl_sig)
		goto error;
	if (!evp_pkey_ctx)
		goto error;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (!pkey)
		goto error;

	eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
	if (!eckey)
		goto error;

	if (!sig) {
		*siglen = (size_t)ECDSA_size(eckey);
		rv = CKR_OK;
		goto error;
	}

	if (*siglen < (size_t)ECDSA_size(eckey))
		goto error;

	key = pkcs11_get_ex_data_ec(eckey);
	if (check_object_fork(key) < 0)
		goto error;

	slot = key->slot;
	ctx = slot->ctx;
	if (!ctx)
		goto error;
#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_try_pkey_ec_sign() "
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
#endif
	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		goto error;

	if (tbslen < (size_t)EVP_MD_size(sig_md))
		goto error;

	rv = 0;
	memset(&mechanism, 0, sizeof mechanism);
	mechanism.mechanism = CKM_ECDSA;

	if (pkcs11_get_session(slot, 0, &session))
		return -1;
	rv = CRYPTOKI_call(ctx,
		C_SignInit(session, &mechanism, key->object));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_SignInit rv=%d\n",
			__FILE__, __LINE__, rv);
	} else if (key->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key, session);
	if (rv == CKR_OK) {
		rv = CRYPTOKI_call(ctx,
			C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)tbslen, sig, &size));
		if (rv != CKR_OK) {
			pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Sign rv=%d\n",
				__FILE__, __LINE__, rv);
		}
	}
	pkcs11_put_session(slot, session);

	if (rv == CKR_OK) {
		BIGNUM *r = BN_bin2bn(sig, size/2, NULL);
		BIGNUM *s = BN_bin2bn(sig + size/2, size/2, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
		ECDSA_SIG_set0(ossl_sig, r, s);
#else
		BN_free(ossl_sig->r);
		ossl_sig->r = r;
		BN_free(ossl_sig->s);
		ossl_sig->s = s;
#endif
		*siglen = i2d_ECDSA_SIG(ossl_sig, &sig);
	}

error:
	ECDSA_SIG_free(ossl_sig);

	if (rv != CKR_OK)
		return -1;

	return 1;
}

# if OPENSSL_VERSION_NUMBER >= 0x30000000L
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

	if (!ctx)
		return -1;

	/* PureEdDSA, no prehash */
	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_EDDSA;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG, "%s:%d pkcs11_eddsa_sign() "
		"sigret=%p *siglen=%u tbs=%p tbslen=%u\n",
		__FILE__, __LINE__, sigret, *siglen, tbs, tbslen);
#endif
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
static int pkcs11_eddsa_pmeth_sign(EVP_PKEY_CTX *evp_pkey_ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	unsigned int tmp_len;
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

	tmp_len = (unsigned int)*siglen;
	rv = pkcs11_eddsa_sign(sig, &tmp_len, tbs, (unsigned int)tbslen, key);
	if (rv < 0)
		return -1;

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
		return 1;

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
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

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

# if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#endif /* OPENSSL_NO_EC */

int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
#ifndef OPENSSL_NO_EC
		EVP_PKEY_EC,
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EVP_PKEY_ED25519,
		EVP_PKEY_ED448,
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
#ifndef OPENSSL_NO_EC
	static EVP_PKEY_METHOD *pkey_method_ec = NULL;
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static EVP_PKEY_METHOD *pkey_method_ed448 = NULL;
	static EVP_PKEY_METHOD *pkey_method_ed25519 = NULL;
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */

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
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */
	}
	*pmeth = NULL;
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x40000000L */

/* vim: set noexpandtab: */
