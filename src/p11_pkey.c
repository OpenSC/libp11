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
static int pkcs11_set_rsa_mechanism(CK_MECHANISM *mechanism,
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
		break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		break;
	case RSA_X931_PADDING:
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
	case RSA_PKCS1_OAEP_PADDING:
		if (pkcs11_oaep_param(oaep_params, mdname, mgf1_mdname,
			oaep_label, oaep_labellen, pctx) != 0)
			return -1;
		mechanism->mechanism = CKM_RSA_PKCS_OAEP;
		mechanism->pParameter = oaep_params;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		break;
	default:
		pkcs11_log(pctx, LOG_DEBUG, "%s:%d unsupported padding: %d\n",
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
#ifdef CKM_EDDSA
	case CKM_EDDSA:
		return "CKM_EDDSA";
#endif
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
 * Returns 1 on success or -1 on failure.
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

	if (key == NULL || sig == NULL || siglen == NULL || tbs == NULL)
		return -1;

	slot = key->slot;
	if (slot == NULL)
		return -1;

	ctx = slot->ctx;
	if (ctx == NULL)
		return -1;

	if (pkcs11_set_rsa_mechanism(&mechanism, &pss_params, NULL,
		ctx, pkey, pad_mode, salt_len, mdname, mgf1_mdname,
		oaep_label, oaep_labellen) < 0)
		return -1;

	if (pkcs11_sign_with_mechanism(key, &mechanism, sig, siglen,
		tbs, tbslen) != CKR_OK)
		return -1;

	return 1;
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
	if (tmp_len == 0 || tmp_len % 2 != 0)
		return NULL;

	r = BN_bin2bn(sig, tmp_len / 2, NULL);
	s = BN_bin2bn(sig + tmp_len / 2, tmp_len / 2, NULL);
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

/*
 * Decrypt RSA input via PKCS#11 using configured padding and OAEP parameters.
 * EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an encoding parameter
 * (OAEP label).
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

	if (pkcs11_set_rsa_mechanism(&mechanism, NULL, &oaep_params,
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
	if (rv != CKR_OK)
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_DecryptInit rv=%d\n",
			__FILE__, __LINE__, rv);
	else if (rv == CKR_OK && key->always_authenticate == CK_TRUE)
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
