/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2017 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2017-2026 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
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

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#define X25519_PUB_LEN  32
#define X448_PUB_LEN    56
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */


/******************************************************************************/
/* Legacy ENGINE EVP_PKEY_METHOD support                                      */
/******************************************************************************/

/* --- ENGINE method definitions and state ---------------------------------- */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && \
	OPENSSL_VERSION_NUMBER < 0x40000000L && \
	!defined(OPENSSL_NO_DEPRECATED_3_0) && \
	!defined(OPENSSL_NO_ECX)
#define LIBP11_HAVE_ECX_METHODS
#endif

#ifdef LIBP11_HAVE_ECX_METHODS
#define ED25519_SIG_LEN 64
#define ED448_SIG_LEN   114
#define X25519_KEY_LEN  X25519_PUB_LEN
#define X448_KEY_LEN    X448_PUB_LEN
#endif /* LIBP11_HAVE_ECX_METHODS */

#if OPENSSL_VERSION_NUMBER < 0x40000000L

typedef int (*P11_PKEY_INIT_FN)(EVP_PKEY_CTX *);
typedef int (*P11_PKEY_SIGN_FN)(EVP_PKEY_CTX *, unsigned char *, size_t *,
	const unsigned char *, size_t);
typedef int (*P11_PKEY_DECRYPT_FN)(EVP_PKEY_CTX *, unsigned char *, size_t *,
	const unsigned char *, size_t);
typedef int (*P11_PKEY_DIGESTSIGN_FN)(EVP_MD_CTX *, unsigned char *, size_t *,
	const unsigned char *, size_t);
typedef int (*P11_PKEY_DERIVE_FN)(EVP_PKEY_CTX *, unsigned char *, size_t *);

typedef enum {
	P11_PKEY_RSA,
#ifndef OPENSSL_NO_EC
	P11_PKEY_EC,
#endif /* OPENSSL_NO_EC */
#ifdef LIBP11_HAVE_ECX_METHODS
	P11_PKEY_EDDSA,
	P11_PKEY_XDH
#endif /* LIBP11_HAVE_ECX_METHODS */
} P11_PKEY_KIND;

typedef struct {
	int type;
	P11_PKEY_KIND kind;
	P11_PKEY_INIT_FN original_init;
	P11_PKEY_SIGN_FN original_sign;
	P11_PKEY_INIT_FN original_decrypt_init;
	P11_PKEY_DECRYPT_FN original_decrypt;
	P11_PKEY_DIGESTSIGN_FN original_digestsign;
	P11_PKEY_DERIVE_FN original_derive;
} P11_PKEY_METHOD;

static P11_PKEY_METHOD pkey_methods[] = {
	{ .type = EVP_PKEY_RSA, .kind = P11_PKEY_RSA },
#ifndef OPENSSL_NO_EC
	{ .type = EVP_PKEY_EC, .kind = P11_PKEY_EC },
#endif /* OPENSSL_NO_EC */
#ifdef LIBP11_HAVE_ECX_METHODS
	{ .type = EVP_PKEY_ED25519, .kind = P11_PKEY_EDDSA },
	{ .type = EVP_PKEY_ED448, .kind = P11_PKEY_EDDSA },
	{ .type = EVP_PKEY_X25519, .kind = P11_PKEY_XDH },
	{ .type = EVP_PKEY_X448, .kind = P11_PKEY_XDH }
#endif /* LIBP11_HAVE_ECX_METHODS */
};

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)

static CRYPTO_ONCE pkey_method_lock_once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *pkey_method_lock = NULL;

/*
 * Shared by all ENGINE instances; do not free it from per-ENGINE cleanup.
 */
static void pkey_method_lock_init(void)
{
	pkey_method_lock = CRYPTO_THREAD_lock_new();
}

static int pkey_method_lock_acquire(void)
{
	if (!CRYPTO_THREAD_run_once(&pkey_method_lock_once,
			pkey_method_lock_init) ||
			pkey_method_lock == NULL)
		return 0;

	return CRYPTO_THREAD_write_lock(pkey_method_lock);
}

static void pkey_method_lock_release(void)
{
	CRYPTO_THREAD_unlock(pkey_method_lock);
}

#else

static int pkey_method_lock_acquire(void)
{
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	return 1;
}

static void pkey_method_lock_release(void)
{
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
}

#endif

static P11_PKEY_METHOD *pkey_method_by_type(int type)
{
	size_t i;

	for (i = 0; i < sizeof(pkey_methods) / sizeof(pkey_methods[0]); i++) {
		if (pkey_methods[i].type == type)
			return &pkey_methods[i];
	}
	return NULL;
}
#endif


/* --- OpenSSL compatibility helpers ---------------------------------------- */

#if OPENSSL_VERSION_NUMBER < 0x100020d0L || defined(LIBRESSL_VERSION_NUMBER)
struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVP_PKEY_CTX *ctx);
    int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*cleanup) (EVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVP_PKEY_CTX *ctx);
    int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init) (EVP_PKEY_CTX *ctx);
    int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);
    int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVP_PKEY_CTX *ctx);
    int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
}; /* EVP_PKEY_METHOD */
#endif

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

#if OPENSSL_VERSION_NUMBER < 0x100020d0L || defined(LIBRESSL_VERSION_NUMBER)
void EVP_PKEY_meth_get_sign(EVP_PKEY_METHOD *pmeth,
		int (**psign_init) (EVP_PKEY_CTX *ctx),
		int (**psign) (EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen))
{
	if (psign_init)
		*psign_init = pmeth->sign_init;
	if (psign)
		*psign = pmeth->sign;
}

static void EVP_PKEY_meth_get_decrypt(EVP_PKEY_METHOD *pmeth,
		int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
		int (**pdecrypt) (EVP_PKEY_CTX *ctx,
			unsigned char *out,
			size_t *outlen,
			const unsigned char *in,
			size_t inlen))
{
	if (pdecrypt_init)
		*pdecrypt_init = pmeth->decrypt_init;
	if (pdecrypt)
		*pdecrypt = pmeth->decrypt;
}
#endif


/******************************************************************************/
/* PKCS#11 cryptographic operations shared by ENGINE and provider code        */
/******************************************************************************/

/*
 * Build PKCS#11 RSA-PSS parameters from the OpenSSL signing context.
 *
 * Resolve the signature and MGF1 digests, normalize OpenSSL salt-length
 * values, and fill CK_RSA_PKCS_PSS_PARAMS for the PKCS#11 mechanism.
 */
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

/*
 * Build PKCS#11 RSA-OAEP parameters from the OpenSSL decryption context.
 *
 * Resolve the OAEP and MGF1 digests, apply the default digest if needed,
 * and fill CK_RSA_PKCS_OAEP_PARAMS including the optional OAEP label.
 */
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

	/* mgf1 default = OAEP digest */
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
	case CKM_ML_KEM:
		return "CKM_ML_KEM";
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
static CK_RV pkcs11_sign_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_siglen;
	CK_ULONG ck_tbslen;

	if (key == NULL || mechanism == NULL || siglen == NULL || tbs == NULL)
		return CKR_ARGUMENTS_BAD;

	if (*siglen > (size_t)(CK_ULONG)-1 || tbslen > (size_t)(CK_ULONG)-1)
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

	if (pkcs11_session_pool_acquire(slot, 0, &session))
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
			pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Encrypt rv=0x%08lX (%lu)\n",
				__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
			goto end;
		}
	}
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Sign rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
		goto end;
	}

	*siglen = (size_t)ck_siglen;

end:
	pkcs11_session_pool_release(slot, session);
	return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Execute a PKCS#11 verify operation using the specified mechanism.
 * Returns: CKR_OK on success or PKCS#11 error code on failure
 */
static CK_RV pkcs11_verify_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_siglen;
	CK_ULONG ck_tbslen;

	if (key == NULL || mechanism == NULL || sig == NULL || tbs == NULL)
		return CKR_ARGUMENTS_BAD;

	if (siglen > (size_t)(CK_ULONG)-1 || tbslen > (size_t)(CK_ULONG)-1)
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

	if (pkcs11_session_pool_acquire(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	rv = CRYPTOKI_call(ctx,
		C_VerifyInit(session, mechanism, key->object));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_VerifyInit rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
		goto end;
	}

	rv = CRYPTOKI_call(ctx,
		C_Verify(session,
			(CK_BYTE_PTR)tbs, ck_tbslen,
			(CK_BYTE_PTR)sig, ck_siglen));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Verify rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
		goto end;
	}

end:
	pkcs11_session_pool_release(slot, session);
	return rv;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/*
 * Execute a PKCS#11 decryption operation using the specified mechanism.
 * Returns: CKR_OK on success or PKCS#11 error code on failure.
 */
static CK_RV pkcs11_decrypt_with_mechanism(PKCS11_OBJECT_private *key,
	CK_MECHANISM *mechanism,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	PKCS11_SLOT_private *slot;
	PKCS11_CTX_private *ctx;
	CK_SESSION_HANDLE session;
	CK_ULONG ck_outlen;
	CK_ULONG ck_inlen;

	if (key == NULL || mechanism == NULL || outlen == NULL || in == NULL)
		return CKR_ARGUMENTS_BAD;

	if (*outlen > (size_t)(CK_ULONG)-1 || inlen > (size_t)(CK_ULONG)-1)
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

	if (pkcs11_session_pool_acquire(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	rv = CRYPTOKI_call(ctx, C_DecryptInit(session, mechanism, key->object));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_DecryptInit rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
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
		pkcs11_log(ctx, LOG_DEBUG, "%s:%d C_Decrypt rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__, (unsigned long)rv, (unsigned long)rv);
		goto end;
	}

	*outlen = (size_t)ck_outlen;

end:
	pkcs11_session_pool_release(slot, session);
	return rv;
}

#if !defined(OPENSSL_NO_EC) || \
	(!defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L)
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

	if (pkcs11_session_pool_acquire(slot, 0, &session))
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

	pkcs11_clear_free(value, value_len_alloc);
	pkcs11_session_pool_release(slot, session);
	return rv;
}
#endif /* #if !defined(OPENSSL_NO_EC) || \
	(!defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L) */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Execute a PKCS#11 decapsulation operation using the specified mechanism.
 *
 * The resulting secret key is created as an extractable session object,
 * read through CKA_VALUE and destroyed before the session is released.
 *
 * Returns CKR_OK on success or a PKCS#11/vendor-defined error code on failure.
 */
static CK_RV pkcs11_decapsulate_with_mechanism(
	PKCS11_OBJECT_private *key, CK_MECHANISM *mechanism,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
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
	CK_ULONG ck_inlen;
	unsigned char *value = NULL;
	size_t len, value_len_alloc = 0;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &ck_false, sizeof(ck_false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_VALUE_LEN, &newkey_len, sizeof(newkey_len)},
		{CKA_SENSITIVE, &ck_false, sizeof(ck_false)},
		{CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
	};

	if (key == NULL || mechanism == NULL || out == NULL ||
			outlen == NULL || *outlen == 0 || in == NULL)
		return CKR_ARGUMENTS_BAD;

	if (*outlen > (size_t)(CK_ULONG)-1 ||
			inlen > (size_t)(CK_ULONG)-1)
		return CKR_ARGUMENTS_BAD;

	slot = key->slot;
	if (slot == NULL)
		return CKR_GENERAL_ERROR;

	ctx = slot->ctx;
	if (ctx == NULL)
		return CKR_GENERAL_ERROR;

#ifdef DEBUG
	pkcs11_log(ctx, LOG_DEBUG,
		"%s:%d pkcs11_decapsulate_with_mechanism() "
		"%s out=%p *outlen=%lu in=%p inlen=%lu\n",
		__FILE__, __LINE__,
		pkcs11_mechanism_name(mechanism),
		out, (unsigned long)*outlen,
		in, (unsigned long)inlen);
#endif

	len = *outlen;
	newkey_len = (CK_ULONG)len;
	ck_inlen = (CK_ULONG)inlen;

	if (pkcs11_session_pool_acquire(slot, 0, &session))
		return CKR_GENERAL_ERROR;

	if (key->always_authenticate == CK_TRUE) {
		rv = pkcs11_authenticate(key, session);
		if (rv != CKR_OK)
			goto end;
	}

	if (ctx->method_3_2 == NULL ||
			ctx->method_3_2->C_DecapsulateKey == NULL) {
		pkcs11_log(ctx, LOG_DEBUG,
			"PKCS#11 3.2 C_DecapsulateKey is not available\n");
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto end;
	}

	rv = CRYPTOKI_call_3_2(ctx,
		C_DecapsulateKey(session, mechanism, key->object,
			newkey_template,
			sizeof(newkey_template) / sizeof(*newkey_template),
			(CK_BYTE_PTR)in, ck_inlen, &newkey));
	if (rv != CKR_OK) {
		pkcs11_log(ctx, LOG_DEBUG,
			"%s:%d C_DecapsulateKey rv=0x%08lX (%lu)\n",
			__FILE__, __LINE__,
			(unsigned long)rv, (unsigned long)rv);
		goto end;
	}

	if (newkey == CK_INVALID_HANDLE) {
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	if (pkcs11_getattr_alloc(ctx, session, newkey, CKA_VALUE,
			&value, &value_len_alloc)) {
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	if (value_len_alloc > len) {
		*outlen = value_len_alloc;
		rv = CKR_BUFFER_TOO_SMALL;
		goto end;
	}

	memcpy(out, value, value_len_alloc);
	*outlen = value_len_alloc;
	rv = CKR_OK;

end:
	if (newkey != CK_INVALID_HANDLE)
		CRYPTOKI_call(ctx, C_DestroyObject(session, newkey));

	pkcs11_clear_free(value, value_len_alloc);
	pkcs11_session_pool_release(slot, session);
	return rv;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#ifndef OPENSSL_NO_EC
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	alg = x509_sig->algor;
	digest = x509_sig->digest;
#else
	X509_SIG_getm(x509_sig, &alg, &digest);
#endif

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
	CK_RV rv;

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

	pkcs11_clear_free(der_pub, der_pub_len);

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
	static const unsigned char zero[X448_PUB_LEN] = {0};
	CK_RV rv;

	if (key == NULL || peer_pub == NULL || secretlen == NULL)
		return -1;

	if (peer_pub_len != X25519_PUB_LEN && peer_pub_len != X448_PUB_LEN)
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

	/* X25519/X448 shared secrets have fixed lengths. */
	if (*secretlen != peer_pub_len)
		return -1;

	/* Reject low-order inputs producing an all-zero shared secret,
	 * matching OpenSSL's X25519/X448 behavior. */
	if (CRYPTO_memcmp(secret, zero, *secretlen) == 0)
		return -1;

	return 1;
}
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
extern int pkcs11_evp_pkey_rsa_decapsulate(PKCS11_OBJECT_private *key,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || outlen == NULL || in == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_X_509;

	if (pkcs11_decapsulate_with_mechanism(key, &mechanism,
			out, outlen, in, inlen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if !defined(OPENSSL_NO_ML_KEM) && OPENSSL_VERSION_NUMBER >= 0x30500000L
/*
 * Decapsulate an ML-KEM ciphertext using a private key on the token.
 */
extern int pkcs11_evp_pkey_ml_kem_decapsulate(PKCS11_OBJECT_private *key,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	CK_MECHANISM mechanism;

	if (key == NULL || outlen == NULL || in == NULL)
		return -1;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ML_KEM;

	if (pkcs11_decapsulate_with_mechanism(key, &mechanism,
			out, outlen, in, inlen) != CKR_OK)
		return -1;

	return 1;
}
#endif /* !defined(OPENSSL_NO_ML_KEM) && OPENSSL_VERSION_NUMBER >= 0x30500000L */


/******************************************************************************/
/* Legacy ENGINE EVP_PKEY_METHOD callbacks and registration                   */
/******************************************************************************/

#if OPENSSL_VERSION_NUMBER < 0x40000000L

/* --- RSA ENGINE method callbacks ------------------------------------------ */

/* Attempt to sign using the PKCS#11-backed RSA implementation */
static int pkcs11_try_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	int padding;
	PKCS11_OBJECT_private *key;
	const EVP_MD *md, *mgf1_md;
	const char *mdname, *mgf1_mdname;
	int salt_len;

	/* RSA method has EVP_PKEY_FLAG_AUTOARGLEN set. OpenSSL core will handle
	 * the size inquiry internally. */
	if (!sig)
		return -1;

	if (!evp_pkey_ctx)
		return -1;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (!pkey)
		return -1;

	rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
	if (!rsa)
		return -1;

	key = pkcs11_get_ex_data_rsa(rsa);
	if (!key)
		return -1;

	if (check_object_fork(key) < 0)
		return -1;

	/* retrieve PSS parameters */
	if (EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding) <= 0)
		return -1;

	if (padding != RSA_PKCS1_PSS_PADDING)
		return -1; /* unsupported */

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &md) <= 0)
		return -1;

	if (tbslen != (size_t)EVP_MD_size(md))
		return -1;

	if (EVP_PKEY_CTX_get_rsa_mgf1_md(evp_pkey_ctx, &mgf1_md) <= 0)
		return -1;

	if (EVP_PKEY_CTX_get_rsa_pss_saltlen(evp_pkey_ctx, &salt_len) == 0)
		return -1;

	mdname = EVP_MD_name(md);
	mgf1_mdname = EVP_MD_name(mgf1_md);

	return pkcs11_evp_pkey_rsa_sign(key, pkey, mdname, padding,
		salt_len, mgf1_mdname, sig, siglen, tbs, tbslen);
}

/* Attempt to decrypt using the PKCS#11-backed RSA implementation */
static int pkcs11_try_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	int padding;
	PKCS11_OBJECT_private *key;
	const EVP_MD *md, *mgf1_md;
	const char *mdname = NULL, *mgf1_mdname = NULL;
	unsigned char *oaep_label = NULL;
	int oaep_labellen = 0;

	/* RSA method has EVP_PKEY_FLAG_AUTOARGLEN set. OpenSSL core will handle
	 * the size inquiry internally. */
	if (!out)
		return -1;

	if (!evp_pkey_ctx)
		return -1;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (!pkey)
		return -1;

	rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
	if (!rsa)
		return -1;

	key = pkcs11_get_ex_data_rsa(rsa);
	if (!key)
		return -1;

	if (check_object_fork(key) < 0)
		return -1;

	/* check RSA padding */
	if (EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding) <= 0)
		return -1;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		break;

	case RSA_PKCS1_OAEP_PADDING:
		/* retrieve OAEP parameters */
		if (EVP_PKEY_CTX_get_rsa_oaep_md(evp_pkey_ctx, &md) <= 0 ||
				md == NULL)
			return -1;

		if (EVP_PKEY_CTX_get_rsa_mgf1_md(evp_pkey_ctx, &mgf1_md) <= 0 ||
				mgf1_md == NULL)
			return -1;

		mdname = EVP_MD_name(md);
		mgf1_mdname = EVP_MD_name(mgf1_md);

		oaep_labellen = EVP_PKEY_CTX_get0_rsa_oaep_label(evp_pkey_ctx,
			&oaep_label);
		if (oaep_labellen < 0) {
			oaep_labellen = 0;
			oaep_label = NULL;
		}
		break;

	default:
		return -1;
	}

	return pkcs11_evp_pkey_rsa_decrypt(key, mdname, padding, mgf1_mdname,
		oaep_label, oaep_labellen, out, outlen, in, inlen);
}

static int pkcs11_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	P11_PKEY_METHOD *state;
	int ret;

	state = pkey_method_by_type(EVP_PKEY_RSA);
	if (state == NULL || state->kind != P11_PKEY_RSA)
		return 0;

	ret = pkcs11_try_pkey_rsa_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0 && state->original_sign != NULL)
		ret = state->original_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static int pkcs11_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	P11_PKEY_METHOD *state;
	int ret;

	state = pkey_method_by_type(EVP_PKEY_RSA);
	if (state == NULL || state->kind != P11_PKEY_RSA)
		return 0;

	ret = pkcs11_try_pkey_rsa_decrypt(evp_pkey_ctx, out, outlen, in, inlen);
	if (ret < 0 && state->original_decrypt != NULL)
		ret = state->original_decrypt(evp_pkey_ctx, out, outlen, in, inlen);
	return ret;
}

#ifndef OPENSSL_NO_EC


/* --- EC ENGINE method callbacks ------------------------------------------- */

/* Attempt to sign using the PKCS#11-backed EC implementation */
static int pkcs11_try_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	PKCS11_OBJECT_private *key;
	const EVP_MD *sig_md = NULL;

	if (!evp_pkey_ctx || !siglen)
		return -1;

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;

	if (sig_md != NULL && EVP_MD_size(sig_md) > 0 &&
			tbslen < (size_t)EVP_MD_size(sig_md))
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
	if (!key)
		return -1;

	if (check_object_fork(key) < 0)
		return -1;

	return pkcs11_evp_pkey_ec_sign(key, sig, siglen, tbs, tbslen);
}

static int pkcs11_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	P11_PKEY_METHOD *state;
	int ret;

	state = pkey_method_by_type(EVP_PKEY_EC);
	if (state == NULL || state->kind != P11_PKEY_EC)
		return 0;

	ret = pkcs11_try_pkey_ec_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0 && state->original_sign != NULL)
		ret = state->original_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}
#endif /* OPENSSL_NO_EC */

#ifdef LIBP11_HAVE_ECX_METHODS


/* --- ECX ENGINE method callbacks ------------------------------------------ */

/*
 * Try Ed25519/Ed448 signing through PKCS#11.
 *
 * Return -1 only when the key should be handled by the original OpenSSL
 * method.  Once a PKCS#11 private key has been recognized, operational
 * failures return 0 and must not fall back to the original method.
 */
static int pkcs11_eddsa_pmeth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	size_t required;

	if (ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	key = pkcs11_get_ex_data_object(pkey);
	if (key == NULL)
		return -1;

	if (key->object_class != CKO_PRIVATE_KEY)
		return -1;

	if (key->slot == NULL || key->slot->ctx == NULL)
		return 0;

	if ((key->slot->ctx->flags & PKCS11_FLAG_NO_METHODS) != 0)
		return -1;

	if (check_object_fork(key) < 0)
		return 0;

	if (siglen == NULL || tbs == NULL)
		return 0;

	switch (EVP_PKEY_get_id(pkey)) {
	case EVP_PKEY_ED25519:
		required = ED25519_SIG_LEN;
		break;
	case EVP_PKEY_ED448:
		required = ED448_SIG_LEN;
		break;
	default:
		return 0;
	}

	if (sig == NULL) {
		*siglen = required;
		return 1;
	}

	if (*siglen < required) {
		*siglen = required;
		return 0;
	}

	return pkcs11_evp_pkey_eddsa_sign(key, sig, siglen,
		tbs, tbslen) > 0 ? 1 : 0;
}

static int pkcs11_eddsa_pmeth_digestsign(EVP_MD_CTX *mdctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY_CTX *ctx;

	if (mdctx == NULL)
		return 0;

	ctx = EVP_MD_CTX_pkey_ctx(mdctx);
	if (ctx == NULL)
		return 0;

	return pkcs11_eddsa_pmeth_sign(ctx, sig, siglen, tbs, tbslen);
}

/*
 * Try X25519/X448 derive through PKCS#11.
 *
 * The peer is validated before the length query so an incomplete derive
 * context is not reported as usable.  The raw peer public key passed to
 * CKM_ECDH1_DERIVE is the RFC 7748 representation.
 */
static int pkcs11_xdh_pmeth_derive(EVP_PKEY_CTX *ctx,
	unsigned char *secret, size_t *secretlen)
{
	EVP_PKEY *pkey;
	EVP_PKEY *peerkey;
	PKCS11_OBJECT_private *key;
	unsigned char peer_public[X448_KEY_LEN];
	size_t peer_public_len;
	size_t required;
	int type;

	if (ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	key = pkcs11_get_ex_data_object(pkey);
	if (key == NULL)
		return -1;

	if (key->object_class != CKO_PRIVATE_KEY)
		return -1;

	if (key->slot == NULL || key->slot->ctx == NULL)
		return 0;

	if ((key->slot->ctx->flags & PKCS11_FLAG_NO_METHODS) != 0)
		return -1;

	if (check_object_fork(key) < 0)
		return 0;

	if (secretlen == NULL)
		return 0;

	type = EVP_PKEY_get_id(pkey);
	switch (type) {
	case EVP_PKEY_X25519:
		required = X25519_KEY_LEN;
		break;
	case EVP_PKEY_X448:
		required = X448_KEY_LEN;
		break;
	default:
		return 0;
	}

	peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);
	if (peerkey == NULL || EVP_PKEY_get_id(peerkey) != type)
		return 0;

	if (secret == NULL) {
		*secretlen = required;
		return 1;
	}

	if (*secretlen < required) {
		*secretlen = required;
		return 0;
	}

	peer_public_len = 0;
	if (EVP_PKEY_get_raw_public_key(peerkey, NULL,
			&peer_public_len) != 1 || peer_public_len != required)
		return 0;

	if (EVP_PKEY_get_raw_public_key(peerkey,
			peer_public, &peer_public_len) != 1 ||
			peer_public_len != required)
		return 0;

	/* Request the required secret size, not the caller's buffer capacity. */
	*secretlen = required;

	if (pkcs11_evp_pkey_xdh_derive(key, peer_public,
			peer_public_len, secret, secretlen) <= 0)
		return 0;

	/* RFC 7748 derives have a fixed-width output. */
	return *secretlen == required ? 1 : 0;
}

static int pkcs11_ecx_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey = NULL;
	P11_PKEY_METHOD *state = NULL;
	int ret;

	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = pkey_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_PKEY_EDDSA)
		return 0;

	ret = pkcs11_eddsa_pmeth_sign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0 && state->original_sign != NULL)
		ret = state->original_sign(ctx, sig, siglen, tbs, tbslen);

	return ret;
}

static int pkcs11_ecx_digestsign(EVP_MD_CTX *mdctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	P11_PKEY_METHOD *state = NULL;
	int ret;

	if (mdctx != NULL)
		ctx = EVP_MD_CTX_pkey_ctx(mdctx);
	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = pkey_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_PKEY_EDDSA)
		return 0;

	ret = pkcs11_eddsa_pmeth_digestsign(mdctx, sig, siglen, tbs, tbslen);
	if (ret < 0 && state->original_digestsign != NULL)
		ret = state->original_digestsign(mdctx, sig, siglen, tbs, tbslen);

	return ret;
}

static int pkcs11_ecx_derive(EVP_PKEY_CTX *ctx,
	unsigned char *secret, size_t *secretlen)
{
	EVP_PKEY *pkey = NULL;
	P11_PKEY_METHOD *state = NULL;
	int ret;

	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = pkey_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_PKEY_XDH)
		return 0;

	ret = pkcs11_xdh_pmeth_derive(ctx, secret, secretlen);
	if (ret < 0 && state->original_derive != NULL)
		ret = state->original_derive(ctx, secret, secretlen);

	return ret;
}

#endif /* LIBP11_HAVE_ECX_METHODS */


/* --- ENGINE method construction and registration ------------------------- */

/*
 * Build an ENGINE-scoped EVP_PKEY_METHOD by preserving the original OpenSSL
 * method, flags and callbacks and overriding only the callbacks implemented
 * by PKCS#11.
 */
static EVP_PKEY_METHOD *pkcs11_pkey_method(int type)
{
	P11_PKEY_METHOD *state;
	EVP_PKEY_METHOD *method = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_METHOD *original_meth;
#else
	const EVP_PKEY_METHOD *original_meth;
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER) */
	int original_type;
	int original_flags;

	state = pkey_method_by_type(type);
	if (state == NULL)
		return NULL;

	if (!pkey_method_lock_acquire())
		return NULL;

	/*
	 * PKEY methods are wrappers around the original OpenSSL method.
	 * Preserve all callbacks that are not explicitly overridden below.
	 */
#if OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER)
	original_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(state->type);
#else
	original_meth = EVP_PKEY_meth_find(state->type);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L || defined(LIBRESSL_VERSION_NUMBER) */
	if (original_meth == NULL)
		goto end;

	EVP_PKEY_meth_get0_info(&original_type, &original_flags, original_meth);
	if (original_type != state->type)
		goto end;

#ifdef LIBP11_HAVE_ECX_METHODS
	/*
	 * Ed25519/Ed448 methods handle all signature operations and must
	 * not rely on generic digest-related defaults.
	 */
	if (state->kind == P11_PKEY_EDDSA &&
			!(original_flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM))
		goto end;
#endif /* LIBP11_HAVE_ECX_METHODS */

	method = EVP_PKEY_meth_new(state->type, original_flags);
	if (method == NULL)
		goto end;

	/*
	 * Start with the complete OpenSSL implementation so that ctrl,
	 * keygen, cleanup, peer-key handling, etc. remain unchanged.
	 */
	EVP_PKEY_meth_copy(method, original_meth);

	switch (state->kind) {
	case P11_PKEY_RSA:
		EVP_PKEY_meth_get_sign(original_meth, &state->original_init,
			&state->original_sign);

		if (state->original_sign == NULL)
			goto error;

		EVP_PKEY_meth_get_decrypt(original_meth,
			&state->original_decrypt_init, &state->original_decrypt);

		if (state->original_decrypt == NULL)
			goto error;

		EVP_PKEY_meth_set_sign(method, state->original_init,
			pkcs11_pkey_rsa_sign);
		EVP_PKEY_meth_set_decrypt(method, state->original_decrypt_init,
			pkcs11_pkey_rsa_decrypt);
		break;

#ifndef OPENSSL_NO_EC
	case P11_PKEY_EC:
		EVP_PKEY_meth_get_sign(original_meth, &state->original_init,
			&state->original_sign);

		if (state->original_sign == NULL)
			goto error;

		EVP_PKEY_meth_set_sign(method, state->original_init,
			pkcs11_pkey_ec_sign);
		break;
#endif /* OPENSSL_NO_EC */

#ifdef LIBP11_HAVE_ECX_METHODS
	case P11_PKEY_EDDSA:
		/*
		 * EVP_PKEY_sign() is useful for the ENGINE interface even though
		 * the native OpenSSL EdDSA implementation primarily uses the
		 * one-shot digestsign callback.
		 */
		EVP_PKEY_meth_get_sign(original_meth, &state->original_init,
			&state->original_sign);

		EVP_PKEY_meth_get_digestsign(original_meth,
			&state->original_digestsign);

		if (state->original_digestsign == NULL)
			goto error;

		EVP_PKEY_meth_set_sign(method, state->original_init,
			pkcs11_ecx_sign);
		EVP_PKEY_meth_set_digestsign(method,
			pkcs11_ecx_digestsign);
		break;

	case P11_PKEY_XDH:
		EVP_PKEY_meth_get_derive(original_meth, &state->original_init,
			&state->original_derive);

		if (state->original_derive == NULL)
			goto error;

		EVP_PKEY_meth_set_derive(method, state->original_init,
			pkcs11_ecx_derive);
		break;
#endif /* LIBP11_HAVE_ECX_METHODS */

	default:
		goto error;
	}
	goto end;

error:
	EVP_PKEY_meth_free(method);
	method = NULL;

end:
	pkey_method_lock_release();
	return method;
}

/*
 * Return the ENGINE-supported EVP_PKEY_METHOD for the requested key type.
 */
int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
#ifndef OPENSSL_NO_EC
		EVP_PKEY_EC,
#endif /* OPENSSL_NO_EC */
#ifdef LIBP11_HAVE_ECX_METHODS
		EVP_PKEY_ED25519,
		EVP_PKEY_ED448,
		EVP_PKEY_X25519,
		EVP_PKEY_X448,
#endif /* LIBP11_HAVE_ECX_METHODS */
		0
	};
	(void)e; /* squash the unused parameter warning */

	if (!pmeth) { /* get the list of supported nids */
		if (nids == NULL)
			return 0;
		*nids = pkey_nids;
		return sizeof(pkey_nids) / sizeof(int) - 1;
	}

	*pmeth = NULL;

	/* get the EVP_PKEY_METHOD */
	switch (nid) {
	case EVP_PKEY_RSA:
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
#endif /* OPENSSL_NO_EC */
#ifdef LIBP11_HAVE_ECX_METHODS
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
	case EVP_PKEY_X25519:
	case EVP_PKEY_X448:
#endif /* LIBP11_HAVE_ECX_METHODS */
		*pmeth = pkcs11_pkey_method(nid);
		return *pmeth != NULL;
	}

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
