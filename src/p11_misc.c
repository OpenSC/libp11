/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
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

#include <config.h>
#include <string.h>
#include <openssl/crypto.h>
#include "libp11-int.h"

void *pkcs11_malloc(size_t size)
{
	void *p = OPENSSL_malloc(size);
	if (p == NULL)
		return NULL;
	memset(p, 0, size);
	return p;
}

/* PKCS11 strings are fixed size blank padded,
 * so when strduping them we must make sure
 * we stop at the end of the buffer, and while we're
 * at it it's nice to remove the padding */
char *pkcs11_strdup(char *mem, size_t size)
{
	char *res;

	while (size && mem[size - 1] == ' ')
		size--;
	res = (char *) OPENSSL_malloc(size + 1);
	if (res == NULL)
		return NULL;
	memcpy(res, mem, size);
	res[size] = '\0';
	return res;
}

/*
 * Dup memory
 */
void *memdup(const void *src, size_t size)
{
	void *dst;

	dst = malloc(size);
	if (dst == NULL)
		return NULL;
	memcpy(dst, src, size);
	return dst;
}
