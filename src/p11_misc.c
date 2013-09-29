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

/* parse string containing slot and id information */
static int parse_slot_id_string(const char *slot_id, int *slot,
				unsigned char *id, size_t * id_len,
				char **label)
{
	int n, i;

	if (!slot_id)
		return 0;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is 0) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = 0;
		return hex_to_bin(slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i, id, id_len);
	}

	/* third: id_<id>  */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = 0;
		return hex_to_bin(slot_id + 3, id, id_len);
	}

	/* label_<label>  */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*label = strdup(slot_id + 6);
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		fprintf(stderr, "format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		fprintf(stderr, "slot number not deciphered!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-') {
		fprintf(stderr, "could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i !=
		    strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		return (*label = strdup(slot_id + i + 6)) != NULL;
	}

	fprintf(stderr, "could not parse string!\n");
	return 0;
}

struct PKCS11_RSA_CRYPTO_EX *PKCS11_RSA_CRYPTO_EX_create(PKCS11_CTX *ctx, PKCS11_SLOT *slots, int slotcount, PKCS11_KEY *keys, int keycount, PKCS11_KEY *key)
{
	struct PKCS11_RSA_CRYPTO_EX *r = OPENSSL_malloc(sizeof(struct PKCS11_RSA_CRYPTO_EX));
	if (r == 0)
		return NULL;
	r->ctx = ctx;
	r->slots.data = slots;
	r->slots.count = slotcount;
	r->keys.data = keys;
	r->keys.count = keycount;
	r->key = key;
	return r;
}

static void PKCS11_RSA_CRYPTO_EX_destroy(struct PKCS11_RSA_CRYPTO_EX *data)
{
	printf("destroy\n");
	/* avoid recursion */
	data->key->evp_key = NULL;
	PKCS11_release_all_slots(data->ctx, data->slots.data, data->slots.count);
	OPENSSL_free(data);
}

void PKCS11_RSA_CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	if (ptr == NULL || idx != RSA_CRYPTO_EX_idx)
		return;
	PKCS11_RSA_CRYPTO_EX_destroy(ptr);
	CRYPTO_set_ex_data(ad, RSA_CRYPTO_EX_idx, NULL);
}
