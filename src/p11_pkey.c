/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2017 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2017 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef EVP_PKEY_CTX_get_signature_md
#define EVP_PKEY_CTX_get_signature_md(ctx, pmd) *(pmd)=(ctx)->md, 1
#endif
#ifndef EVP_PKEY_CTX_get_rsa_mgf1_md
#define EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd) *(pmd)=(ctx)->mgf1md, 1
#endif

static int (*orig_pkey_rsa_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_rsa_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);

/* Setup PKCS#11 mechanisms for encryption/decryption */
int pkcs11_mechanism(CK_MECHANISM *mechanism,
		PKCS11_RSA_PKCS_PARAMS *rsa_pkcs_params,
		const int padding, EVP_PKEY_CTX *evp_pkey_ctx)
{
	const EVP_MD *sig_md, *mgf1_md;
	EVP_PKEY *evp_pkey;
	int salt_len;

	memset(mechanism, 0, sizeof(CK_MECHANISM));
	if (rsa_pkcs_params)
		memset(rsa_pkcs_params, 0, sizeof(PKCS11_RSA_PKCS_PARAMS));

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
		/* retrieve PSS parameters */
		if (evp_pkey_ctx == NULL || rsa_pkcs_params == NULL)
			return -1;
		if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
			return -1;
		if (EVP_PKEY_CTX_get_rsa_mgf1_md(evp_pkey_ctx, &mgf1_md) <= 0)
			return -1;
		if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(evp_pkey_ctx, &salt_len))
			return -1;
		switch (salt_len) {
		case -1:
			salt_len = EVP_MD_size(sig_md);
			break;
		case -2:
			evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
			if (evp_pkey == NULL)
				return -1;
			salt_len = EVP_PKEY_size(evp_pkey) - EVP_MD_size(sig_md) - 2;
			if (((EVP_PKEY_bits(evp_pkey) - 1) & 0x7) == 0)
				salt_len--;
			if (salt_len < 0) /* integer underflow detected */
				return -1;
		}
		fprintf(stderr, "salt_len=%d sig_md=%d mdf1_md=%d\n",
			salt_len, EVP_MD_type(sig_md), EVP_MD_type(mgf1_md));

		/* fill rsa_pkcs_params */
		switch (EVP_MD_type(sig_md)) {
		case NID_sha256:
			rsa_pkcs_params->pss.hashAlg = CKM_SHA256;
			break;
		case NID_sha512:
			rsa_pkcs_params->pss.hashAlg = CKM_SHA512;
			break;
		case NID_sha384:
			rsa_pkcs_params->pss.hashAlg = CKM_SHA384;
			break;
		default:
			return -1;
		}
		switch (EVP_MD_type(mgf1_md)) {
		case NID_sha256:
			rsa_pkcs_params->pss.mgf = CKG_MGF1_SHA256;
			break;
		case NID_sha512:
			rsa_pkcs_params->pss.mgf = CKG_MGF1_SHA512;
			break;
		case NID_sha384:
			rsa_pkcs_params->pss.mgf = CKG_MGF1_SHA384;
			break;
		case NID_sha224:
			rsa_pkcs_params->pss.mgf = CKG_MGF1_SHA224;
			break;
		default:
			return -1;
		}
		rsa_pkcs_params->pss.sLen = salt_len;

		/* fill mechanism */
		mechanism->mechanism = CKM_RSA_PKCS_PSS;
		mechanism->pParameter = &rsa_pkcs_params->pss;
		mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
		break;
	default:
		fprintf(stderr, "PKCS#11: Unsupported padding type\n");
		return -1;
	}
	return 0;
}

static int pkcs11_try_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	PKCS11_KEY *key;
	CK_MECHANISM mechanism;
	PKCS11_RSA_PKCS_PARAMS rsa_pkcs_params;
	int padding, rv;
	CK_ULONG size = *siglen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	const EVP_MD *sig_md;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;
	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return -1;
	key = pkcs11_get_ex_data_rsa(rsa);
	if (key == NULL)
		return -1;
	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;
	if (tbslen != (size_t)EVP_MD_size(sig_md))
		return -1;

	EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding);
	if (pkcs11_mechanism(&mechanism, &rsa_pkcs_params,
			padding, evp_pkey_ctx) < 0)
		return -1;

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);
	rv = CRYPTOKI_call(ctx,
		C_SignInit(spriv->session, &mechanism, kpriv->object));
	if (!rv || kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (unsigned char *)tbs, tbslen, sig, &size));
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);
	fprintf(stderr, "C_SignInit and or C_Sign rv =%u\n", rv);

	if (rv != 0)
		return -1;
	*siglen = size;
	return 1;
}

static int pkcs11_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	fprintf(stderr, "pkcs11_pkey_rsa_sign called\n");
	ret = pkcs11_try_pkey_rsa_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_rsa_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_rsa()
{
	EVP_PKEY_METHOD *orig_evp_pkey_meth_rsa, *new_evp_pkey_meth_rsa;

	orig_evp_pkey_meth_rsa = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_RSA);
	EVP_PKEY_meth_get_sign(orig_evp_pkey_meth_rsa,
		&orig_pkey_rsa_sign_init, &orig_pkey_rsa_sign);

	new_evp_pkey_meth_rsa = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
	EVP_PKEY_meth_copy(new_evp_pkey_meth_rsa, orig_evp_pkey_meth_rsa);
	EVP_PKEY_meth_set_sign(new_evp_pkey_meth_rsa,
		orig_pkey_rsa_sign_init, pkcs11_pkey_rsa_sign);
	return new_evp_pkey_meth_rsa;
}

int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
	if (pkey_method_rsa == NULL)
		pkey_method_rsa = pkcs11_pkey_method_rsa();
	if (pkey_method_rsa == NULL)
		return 0;
	if (!pmeth) { /* get the list of supported nids */
		*nids = pkey_nids;
		return 1; /* the number of returned nids */
	}
	/* get the EVP_PKEY_METHOD */
	if (nid == EVP_PKEY_RSA) {
		*pmeth = pkey_method_rsa;
		return 1; /* success */
	}
	*pmeth = NULL;
	return 0;
}

/* vim: set noexpandtab: */
