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

/* Stolen from OpenSC/src/libopensc/sc.c */
int pkcs11_hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
	const char *sc_hex_to_bin_separators = " :";
	if (in == NULL || out == NULL || outlen == NULL) {
		return -1;
	}

	int byte_needs_nibble = 0;
	int r = 0;
	size_t left = *outlen;
	unsigned char byte = 0;
	while (*in != '\0' && 0 != left) {
		char c = *in++;
		unsigned char nibble;
		if ('0' <= c && c <= '9')
			nibble = c - '0';
		else if ('a' <= c && c <= 'f')
			nibble = c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			nibble = c - 'A' + 10;
		else {
			if (strchr(sc_hex_to_bin_separators, (int) c)) {
				if (byte_needs_nibble) {
					r = -2;
					goto err;
				}
				continue;
			}
			r = -3;
			goto err;
		}

		if (byte_needs_nibble) {
			byte |= nibble;
			*out++ = (unsigned char) byte;
			left--;
			byte_needs_nibble = 0;
		} else {
			byte  = nibble << 4;
			byte_needs_nibble = 1;
		}
	}

	if (left == *outlen && 1 == byte_needs_nibble && 0 != left) {
		/* no output written so far, but we have a valid nibble in the upper
		 * bits. Allow this special case. */
		*out = (unsigned char) byte>>4;
		left--;
		byte_needs_nibble = 0;
	}

	/* for ease of implementation we only accept completely hexed bytes. */
	if (byte_needs_nibble) {
		r = -4;
		goto err;
	}

	/* skip all trailing separators to see if we missed something */
	while (*in != '\0') {
		if (NULL == strchr(sc_hex_to_bin_separators, (int) *in))
			break;
		in++;
	}
	if (*in != '\0') {
		r = -5;
		goto err;
	}

err:
	*outlen -= left;
	return r;
}


/* vim: set noexpandtab: */
