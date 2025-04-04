/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * Elliptic Curve key generation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <libp11.h>
#include <string.h>

#define CHECK_ERR(cond, txt, code) \
	do { \
		if (cond) { \
			fprintf(stderr, "%s\n", (txt)); \
			rc=(code); \
			goto end; \
		} \
	} while (0)

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

static int parse_hex_key_id(const char *input, unsigned char **output, size_t *size)
{
	size_t i, len = strlen(input);

	if (len % 2 != 0) {
		return -1;
	}
	*size = len / 2;
	*output = OPENSSL_malloc(*size);
	if (!*output) {
		return -1;
	}
	memset(*output, 0, *size);
	for (i = 0; i < *size; i++) {
		sscanf(input + (i * 2), "%2hhx", *output + i);
	}
	return 0;
}

static void list_keys(const char *title, const PKCS11_KEY *keys,
		const unsigned int nkeys) {
	unsigned int i;

	printf("\n%s:\n", title);
	for (i = 0; i < nkeys; i++) {
		printf(" #%d id=", i);
		for (size_t j = 0; j < keys[i].id_len; j++) {
			printf("%02x", keys[i].id[j]);
		}
		printf(";object=%s\n", keys[i].label);
	}
}

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	PKCS11_KEY *keys;
	unsigned int nslots, nkeys;
	unsigned char *key_id = NULL;
	size_t key_id_len = 0;
	int rc = 0;
	PKCS11_params params = {.sensitive = 1, .extractable = 0};
	PKCS11_EC_KGEN ec = {.curve = "P-256"};
	PKCS11_KGEN_ATTRS eckg = {0};
	
	if (argc < 6) {
		fprintf(stderr, "usage: %s [module] [TOKEN] [KEY-LABEL] [KEY-ID] [PIN]\n", argv[0]);
		return 1;
	}
	
	key_id_len = strlen(argv[4]);
	rc = parse_hex_key_id(argv[4], &key_id, &key_id_len);
	CHECK_ERR(rc < 0, "Invalid key ID format", 1);
	
	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load PKCS#11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading PKCS#11 module failed", 2);

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 3);

	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	while (slot) {
		if (slot->token && slot->token->initialized && slot->token->label
			&& strcmp(argv[2], slot->token->label) == 0)
			break;
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);
	};
	CHECK_ERR(!slot || !slot->token, "no token available", 4);

	printf("Found token:\n");
	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);
	
	rc = PKCS11_login(slot, 0, argv[5]);
	error_queue("PKCS11_login");
	CHECK_ERR(rc < 0, "PKCS11_login failed", 5);

	eckg.type = EVP_PKEY_EC;
	eckg.kgen.ec = &ec;
	eckg.token_label = argv[2];
	eckg.key_label = argv[3];
	eckg.key_id = (const unsigned char *)key_id;
	eckg.id_len = key_id_len;
	eckg.key_params = &params;

	rc = PKCS11_keygen(slot->token, &eckg);
	error_queue("PKCS11_keygen");
	CHECK_ERR(rc < 0, "Failed to generate a key pair on the token", 6);

	printf("\nEC keys generated\n");

	/* get private keys */
	rc = PKCS11_enumerate_keys(slot->token, &keys, &nkeys);
	error_queue("PKCS11_enumerate_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_keys failed", 7);
	CHECK_ERR(nkeys == 0, "No private keys found", 8);
	list_keys("Private keys", keys, nkeys);

end:
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}
	OPENSSL_free(key_id);

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");
	return rc;
}

/* vim: set noexpandtab: */
