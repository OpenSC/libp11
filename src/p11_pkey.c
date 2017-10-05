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

/* TODO: implement the rest of PKEY functionality *here* */

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

static EVP_PKEY_METHOD *pkcs11_pkey_method_rsa()
{
	/* TODO: return our own method */
	/* in the meantime we just return the default one: */
	return EVP_PKEY_meth_find(EVP_PKEY_RSA);
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
