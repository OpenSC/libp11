/*
 * Copyright © 2023, Koninklijke Philips N.V.
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

/* libp11 example code: listkeys_ext.c
 *
 * This example connects to your smart card and
 * list the keys matching provided id or label.
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

void print_usage(const char *prog)
{
	fprintf(stderr,
			"usage: %s -m /usr/lib/opensc-pkcs11.so [-p PIN] [-i ID-in-hex] [-l LABEL] \n",
			prog);
}

int getbin(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/**
 * As per RFC7512 section 2.3, id is non-textual arbitrary length data.
 * So this hex2bin function is here to help convert arbitrary length hexstring to byte array
 *
 * Function interprets the hex string from end to begin and fills dst buffer from end to begin
 * If hex string is of even length (fox ex: abcd) resulting dst buffer will look like {0xab, 0xcd}
 * If hex string is not of even length (for ex: abc) it would behave as if 0 was appended in beginning of string (ex: 0abc)
 * and dst buffer will be {0x0a, 0xbc}
 *
 * params,
 * dst [out] destination buffer will be filled with parsed bytes from str
 * str [in] string with hexadecimal characters
 * op_len [in|out] : number of bytes in dst buffer, and if function is successful, op_len will contain actual bytes in dst
 *
 * Return:
 * On error this function returns -1, op_len is set to 0
 * On success this function returns 0 and op_len contains number of bytes filled in dst
*/
int hex2bin(unsigned char *dst, const char *str, size_t *op_len)
{
	const char HEXDIGITS[] = "01234567890ABCDEFabcdef";

	if (!str || !dst) {
		*op_len = 0;
		return -1;
	}

	ssize_t len = 0, byte_len = 0;
	len = strspn(str, HEXDIGITS);
	/* 0x010 needs 2 bytes , 0x0110 needs 2 bytes, 0x010203 needs 3 bytes, 0x10203 needs 3 bytes, and so on */
	byte_len = (len + 1) / 2;

	/* avoid overflow on dst */
	if (*op_len < byte_len) {
		*op_len = 0;
		return -1;
	}

	*op_len = byte_len;
	while(byte_len--) {
		/* start parsing from end of hexstring to beginning of hex string */
		/* len is including '\0' so use pre-decrement */
		int lsb = getbin(str[--len]); // this never goes out of bounds, we will have at least one byte to process!
		int msb = --len >= 0 ? getbin(str[len]) : 0; // avoid underflow on str (when len is not even we assume 0)

		/* combine msb and lsb to make uint8_t; */
		dst[byte_len] = msb << 4 | lsb;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	const size_t max_id_len = 256;
	PKCS11_CTX *ctx=NULL;
	PKCS11_SLOT *slots=NULL, *slot;
	PKCS11_KEY *keys;
	PKCS11_KEY key_template = {0};
	unsigned int nslots, nkeys;
	int option = -1;
	char *module = NULL, *pin = NULL;
	int rc = 0;

	while( (option = getopt(argc, argv, "m:p:i:l:")) != -1 ) {
		switch(option) {
		case 'm':
			if (!module) {
				errno = 0;
				module = strdup(optarg);
				CHECK_ERR(errno != 0, "Could not allocate memory for module", 9);
			}
			break;
		case 'p':
			if (!pin) {
				errno = 0;
				pin = strdup(optarg);
				CHECK_ERR(errno != 0, "Could not allocate memory for pin", 10);
			}
			break;
		case 'i':
			if (!key_template.id) {
				errno = 0;
				key_template.id = malloc(max_id_len);
				CHECK_ERR(errno != 0, "Could not allocate memory for id", 11);
			}
			key_template.id_len = max_id_len;
			rc = hex2bin(key_template.id, optarg, &key_template.id_len);
			CHECK_ERR(rc != 0, "ID is too big or not valid", 12);
			break;
		case 'l':
			if (!key_template.label) {
				errno = 0;
				key_template.label = strdup(optarg);
				CHECK_ERR(errno != 0, "Could not allocate memory for label", 13);
			}
			break;
		case '?':
			print_usage(argv[0]);
			goto end;
		}
	}

	/* module is required argument */
	if (!module) {
		print_usage(argv[0]);
		goto end;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, module);
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
	key_template.isPrivate = 0;
	rc = PKCS11_enumerate_public_keys_ext(slot->token, &key_template, &keys, &nkeys);
	error_queue("PKCS11_enumerate_public_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_public_keys failed", 4);
	CHECK_ERR(nkeys == 0, "No public keys found", 5);
	list_keys("Public keys", keys, nkeys);

	if (slot->token->loginRequired && pin) {
		/* perform pkcs #11 login */
		rc = PKCS11_login(slot, 0, pin);
		error_queue("PKCS11_login");
		CHECK_ERR(rc < 0, "PKCS11_login failed", 6);
	}

	/* get private keys */
	key_template.isPrivate = 1;
	rc = PKCS11_enumerate_keys_ext(slot->token, &key_template, &keys, &nkeys);
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

	free(module);
	free(pin);
	free(key_template.id);
	free(key_template.label);

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");
	return rc;
}

static void list_keys(const char *title, const PKCS11_KEY *keys,
		const unsigned int nkeys) {
	unsigned int i;

	printf("\n%s (nkeys:%d):\n", title, nkeys);
	for (i = 0; i < nkeys; i++)
		printf(" * %s key: %s \n",
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
