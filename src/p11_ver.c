/* libp11, a simple layer on to of PKCS#11 API
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

int pkcs11_convert_version(unsigned char major, unsigned char minor)
{
	return major * 1000 + minor;
}

int pkcs11_get_cryptoki_version(PKCS11_CTX_private* ctx)
{
	int rv;
	CK_INFO ck_info;

	memset(&ck_info, 0, sizeof(ck_info));
	rv = CRYPTOKI_call(ctx, C_GetInfo(&ck_info));
	if (rv == CKR_OK) {
		CK_VERSION version = ck_info.cryptokiVersion;
		return pkcs11_convert_version(version.major, version.minor);
	} else {
		/* TODO(mihai): handle error */
		return -1;
	}
}

/* vim: set noexpandtab: */
