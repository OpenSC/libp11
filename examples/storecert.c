/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
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

/* libp11 example code: storecert.c
 *
 * This example demonstrates how to connect to a PKCS#11-compatible
 * smart card (token) and store an X.509 certificate on it.
 */

#include <libp11.h>
#include <string.h>
#include <openssl/pem.h>

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

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
	size_t i;

	for (i = 0; i < out_len; i++) {
		if (sscanf(hex + (i * 2), "%2hhx", &out[i]) != 1) {
			return -1;
		}
	}
	return 0;
}

static int extract_url_fields(char *uri, char **out_token, char **out_label,
	char **out_id, char **out_pin)
{
	static const char DELIMITERS[] = ":;?&=";
	char *str, *token;

	if (strncmp(uri, "pkcs11:", strlen("pkcs11:")) != 0) {
		printf("URL does not look valid: %s\n", uri);
		return 0;
	}
	str = uri + strlen("pkcs11:");
	while ((token = strtok(str, DELIMITERS))) {
		char **out = NULL;

		str = NULL;
		if (!strcmp(token, "token")) {
			out = out_token;
		} else if (!strcmp(token, "object")) {
			out = out_label;
		} else if (!strcmp(token, "id") ) {
			out = out_id;
		} else if (!strcmp(token, "pin-value")) {
			out = out_pin;
		} else {
			printf("Unrecognized token: %s\n", token);
			return 0;
		}
		if (out) {
			if (*out) {
				printf("Repeated token: %s\n", token);
				return 0;
			} else if ((token = strtok(str, DELIMITERS))) {
				*out = token;
			}
		}
	}
	if (!*out_token || !*out_label || !*out_pin) {
		printf("URL incomplete\n");
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	unsigned int nslots;
	char *token = NULL, *label = NULL, *id_str = NULL, *pin = NULL;
	unsigned char *id = NULL;
	size_t id_len = 0;
	FILE *file;
	X509 *cert = NULL;
	int rc = 0;

	if (argc < 4) {
		fprintf(stderr, "usage: %s [source certificate file] [target certificate URI] [module]\n", argv[0]);
		return 1;
	}

	/* load an X509 certificate from a PEM file */
	file = fopen(argv[1], "rb");
	CHECK_ERR(!file, "Failed to open source certificate file\n", 1);

	cert = PEM_read_X509(file, NULL, NULL, NULL);
	fclose(file);
	CHECK_ERR(!cert, "Failed to load certificate\n", 2);

	printf("Certificate found: %s\n", argv[1]);

	/* parse the target PKCS#11 URI */
	rc = extract_url_fields(argv[2], &token, &label, &id_str, &pin);
	CHECK_ERR(rc < 0, "Invalid certificate URI", 3);

	if (id_str) {
		size_t len = strlen(id_str);

		CHECK_ERR(len % 2 != 0, "Invalid key ID format: odd length", 4);
		id_len = len / 2;
		id = OPENSSL_malloc(id_len);
		CHECK_ERR(!id, "Memory allocation failed", 5);
		rc = hex_to_bytes(id_str, id, id_len);
		CHECK_ERR(rc < 0, "Invalid hex ID format", 6);
	} else {
		id = (unsigned char*)label;
		id_len = strlen(label);
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");
	CHECK_ERR(!ctx, "Could not initialize libp11 context", 7);

	/* load PKCS#11 module */
	rc = PKCS11_CTX_load(ctx, argv[3]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "Failed to load PKCS#11 module", 8);

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 9);

	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	while (slot) {
		if (!strncmp(token, slot->token->label, strlen(token)))
			break;
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);
	}
	CHECK_ERR(!slot || !slot->token, "No token available", 10);

	rc = PKCS11_open_session(slot, 1);
	error_queue("PKCS11_open_session");
	CHECK_ERR(rc < 0, "Failed to open session", 11);

	/* log in with a provided PIN */
	rc = PKCS11_login(slot, 0, pin);
	error_queue("PKCS11_login ");
	CHECK_ERR(rc < 0, "PKCS11_login failed", 12);

	/* store the certificate using the specified label and ID */
	rc = PKCS11_store_certificate(slot->token, cert, label, id, id_len, NULL);
	error_queue("PKCS11_store_certificate");
	CHECK_ERR(rc < 0, "PKCS11_store_certificate failed", 13);

end:
	X509_free(cert);
	if (id_str)
		OPENSSL_free(id);
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	if (rc)
		printf("Storing failed (error code %d).\n", rc);
	else
		printf("Certificate stored.\n");
	return rc;
}

/* vim: set noexpandtab: */
