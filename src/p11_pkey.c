/* libp11, a simple layer on to of PKCS#11 API
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

/* TODO: implement the rest of PKEY functionality *here* */

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
