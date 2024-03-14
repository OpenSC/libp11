/*
 * Copyright © 2020, Michał Trojnara <Michal.Trojnara@stunnel.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* libp11 example code: listkeys.c
 *
 * This examply simply connects to your smart card
 * and list the keys.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <libp11.h>
#include <unistd.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 256

static void list_keys(const char *title,
	const PKCS11_KEY *keys, const unsigned int nkeys);
static void error_queue(const char *name);

#define CHECK_ERR(cond, txt, code) \
	do { \
		if (cond) { \
			fprintf(stderr, "%s\n", (txt)); \
			rc=(code); \
			goto end; \
		} \
	} while (0)

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots=NULL, *slot;
	PKCS11_KEY *keys;
	unsigned int nslots, nkeys;
	int rc = 0;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so [PIN]\n",
			argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading pkcs11 engine failed", 1);

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 2);

	/* get first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	CHECK_ERR(!slot || !slot->token, "no token available", 3);

	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token manufacturer: %s\n", slot->token->manufacturer);
	printf("Slot token model.......: %s\n", slot->token->model);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	/* get public keys */
	rc = PKCS11_enumerate_public_keys(slot->token, &keys, &nkeys);
	error_queue("PKCS11_enumerate_public_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_public_keys failed", 4);
	CHECK_ERR(nkeys == 0, "No public keys found", 5);
	list_keys("Public keys", keys, nkeys);

	if (slot->token->loginRequired && argc > 2) {
		/* perform pkcs #11 login */
		rc = PKCS11_login(slot, 0, argv[2]);
		error_queue("PKCS11_login");
		CHECK_ERR(rc < 0, "PKCS11_login failed", 6);
	}

	/* get private keys */
	rc = PKCS11_enumerate_keys(slot->token, &keys, &nkeys);
	error_queue("PKCS11_enumerate_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_keys failed", 7);
	CHECK_ERR(nkeys == 0, "No private keys found", 8);
	list_keys("Private keys", keys, nkeys);

end:
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");
	return rc;
}

static void list_keys(const char *title, const PKCS11_KEY *keys,
		const unsigned int nkeys) {
	unsigned int i;

	printf("\n%s:\n", title);
	for (i = 0; i < nkeys; i++)
		printf(" * %s key: %s\n",
			keys[i].isPrivate ? "Private" : "Public", keys[i].label);
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

/* vim: set noexpandtab: */
