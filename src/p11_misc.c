/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include <openssl/crypto.h>

/* PKCS11 strings are fixed size blank padded,
 * so when strduping them we must make sure
 * we stop at the end of the buffer, and while we're
 * at it it's nice to remove the padding */
char *pkcs11_strdup(char *mem, size_t size)
{
	char *res;

	while (size && mem[size - 1] == ' ')
		size--;
	res = OPENSSL_malloc(size + 1);
	if (!res)
		return NULL;
	memcpy(res, mem, size);
	res[size] = '\0';
	return res;
}

int pkcs11_atomic_add(int *value, int amount, pthread_mutex_t *lock)
{
#if defined( _WIN32)
	(void) lock;
	/* both int and long are 32-bit on all WIN32 platforms */
	return InterlockedExchangeAdd((LONG *)value, amount) + amount;
#elif defined(__GNUC__) && defined(__ATOMIC_ACQ_REL)
	(void) lock;
	return __atomic_add_fetch(value, amount, __ATOMIC_ACQ_REL);
#else
	int ret;

	pthread_mutex_lock(lock);
	*value += amount;
	ret = *value;
	pthread_mutex_unlock(lock);

	return ret;
#endif
}

/* vim: set noexpandtab: */
