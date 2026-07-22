/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka
 * All rights reserved.
 *
 * PKCS#11 provider test
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "helpers_prov.h"
#include "oneshot_common.h"

#if !defined(OPENSSL_NO_ML_KEM) && OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <openssl/crypto.h>

#define EVP_PKEY_ML_KEM_768 NID_ML_KEM_768

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

static void print_hex(const char *name, const unsigned char *data, size_t len)
{
	size_t i;

	fprintf(stderr, "%s (%zu bytes): ", name, len);
	for (i = 0; i < len; i++)
		fprintf(stderr, "%02x", data[i]);
	fprintf(stderr, "\n");
}

/* Test ML-KEM encapsulation and decapsulation. */
static int mlkem_test(EVP_PKEY *private_key, EVP_PKEY *public_key)
{
	EVP_PKEY_CTX *pkey_ctx = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *secret = NULL;
	unsigned char *dec_secret = NULL;
	size_t ciphertext_len = 0;
	size_t secret_len = 0;
	size_t dec_secret_len = 0;
	size_t ciphertext_size = 0;
	size_t secret_size = 0;
	size_t dec_secret_size = 0;
	int ret = 0;

	if (private_key == NULL || public_key == NULL)
		goto cleanup;

	if (!EVP_PKEY_is_a(private_key, "ML-KEM-768") ||
			!EVP_PKEY_is_a(public_key, "ML-KEM-768")) {
		fprintf(stderr, "Keys are not ML-KEM-768 keys\n");
		goto cleanup;
	}

	/* Encapsulate using the public key. */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
	if (pkey_ctx == NULL) {
		fprintf(stderr, "Could not create encapsulation context\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (EVP_PKEY_encapsulate_init(pkey_ctx, NULL) <= 0) {
		fprintf(stderr, "Could not initialize encapsulation\n");
		display_openssl_errors();
		goto cleanup;
	}

	/* Query ciphertext and shared-secret sizes. */
	if (EVP_PKEY_encapsulate(pkey_ctx, NULL, &ciphertext_len,
			NULL, &secret_len) <= 0) {
		fprintf(stderr, "Could not query encapsulation output sizes\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (ciphertext_len == 0 || secret_len == 0) {
		fprintf(stderr, "Invalid encapsulation output sizes\n");
		goto cleanup;
	}

	ciphertext_size = ciphertext_len;
	secret_size = secret_len;

	ciphertext = OPENSSL_malloc(ciphertext_size);
	secret = OPENSSL_malloc(secret_size);
	if (ciphertext == NULL || secret == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		goto cleanup;
	}

	if (EVP_PKEY_encapsulate(pkey_ctx, ciphertext, &ciphertext_len,
			secret, &secret_len) <= 0) {
		fprintf(stderr, "Encapsulation failed\n");
		display_openssl_errors();
		goto cleanup;
	}

	printf("Shared secret encapsulated.\n");

	EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL;

	/*
	 * Decapsulate using the private key.
	 */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
	if (pkey_ctx == NULL) {
		fprintf(stderr, "Could not create decapsulation context\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (EVP_PKEY_decapsulate_init(pkey_ctx, NULL) <= 0) {
		fprintf(stderr, "Could not initialize decapsulation\n");
		display_openssl_errors();
		goto cleanup;
	}

	/* Query the recovered shared-secret size. */
	if (EVP_PKEY_decapsulate(pkey_ctx, NULL, &dec_secret_len,
			ciphertext, ciphertext_len) <= 0) {
		fprintf(stderr, "Could not query decapsulation output size\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (dec_secret_len == 0) {
		fprintf(stderr, "Invalid decapsulation output size\n");
		goto cleanup;
	}

	dec_secret_size = dec_secret_len;
	dec_secret = OPENSSL_malloc(dec_secret_size);
	if (dec_secret == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		goto cleanup;
	}

	if (EVP_PKEY_decapsulate(pkey_ctx, dec_secret, &dec_secret_len,
			ciphertext, ciphertext_len) <= 0) {
		fprintf(stderr, "Decapsulation failed\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (secret_len != dec_secret_len ||
			CRYPTO_memcmp(secret, dec_secret, secret_len) != 0) {
		fprintf(stderr, "Decapsulated secret does not match the encapsulated secret\n");
		print_hex("Encapsulated secret", secret, secret_len);
		print_hex("Decapsulated secret", dec_secret, dec_secret_len);
		goto cleanup;
	}

	printf("ML-KEM-768 encapsulation/decapsulation successful.\n");
	ret = 1;

cleanup:
	EVP_PKEY_CTX_free(pkey_ctx);
	OPENSSL_free(ciphertext);
	OPENSSL_clear_free(secret, secret_size);
	OPENSSL_clear_free(dec_secret, dec_secret_size);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int rc;
	int len;
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *slot;
	unsigned int nslots = 0;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;
	PKCS11_NID_KGEN mlkem = {
		.nid = NID_ML_KEM_768
	};
	PKCS11_params params = {
		.sensitive = 1,
		.extractable = 0,
	};
	PKCS11_KGEN_ATTRS mlkem_kg = {
		.type = EVP_PKEY_ML_KEM_768,
		.kgen.nid = &mlkem,
		.token_label = NULL,
		.key_label = NULL,
		.key_id = (const unsigned char *)"\x22\x33",
		.id_len = 2,
		.key_params = &params,
	};
	char private_uri[1024];
	char public_uri[1024];

	if (argc < 5) {
		fprintf(stderr,
			"usage: %s [MODULE] [TOKEN] [KEY-LABEL] [PIN]\n",
			argv[0]);
		goto cleanup;
	}

	mlkem_kg.token_label = argv[2];
	mlkem_kg.key_label = argv[3];

	len = snprintf(private_uri, sizeof(private_uri),
		"pkcs11:token=%s;object=%s;type=private;pin-value=%s",
		argv[2], argv[3], argv[4]);
	if (len < 0 || (size_t)len >= sizeof(private_uri)) {
		fprintf(stderr, "Private key URI is too long\n");
		goto cleanup;
	}

	len = snprintf(public_uri, sizeof(public_uri),
		"pkcs11:token=%s;object=%s;type=public",
		argv[2], argv[3]);
	if (len < 0 || (size_t)len >= sizeof(public_uri)) {
		fprintf(stderr, "Public key URI is too long\n");
		goto cleanup;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");
	CHECK_ERR(ctx == NULL, "PKCS11_CTX_new failed", 3);

	/* Load the PKCS#11 module. */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading PKCS#11 module failed", 4);

	/* Get information on all slots. */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 5);

	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");

	while (slot != NULL) {
		if (slot->token != NULL &&
				slot->token->initialized &&
				slot->token->label != NULL &&
				strcmp(argv[2], slot->token->label) == 0)
			break;

		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);
	}

	CHECK_ERR(slot == NULL || slot->token == NULL,
		"no token available", 6);

	printf("Found token:\n");
	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	rc = PKCS11_login(slot, 0, argv[4]);
	error_queue("PKCS11_login");
	CHECK_ERR(rc < 0, "PKCS11_login failed", 7);

	/*
	 * ML-KEM key generation test.
	 */
	rc = PKCS11_keygen(slot->token, &mlkem_kg);
	error_queue("PKCS11_keygen");
	CHECK_ERR(rc < 0, "Failed to generate a key pair on the token", 8);

	printf("ML-KEM-768 keys generated\n");

	/*
	 * Release libp11 resources before initializing pkcs11prov.
	 */
	PKCS11_release_all_slots(ctx, slots, nslots);
	slots = NULL;
	nslots = 0;

	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);
	ctx = NULL;

	/* Load pkcs11prov and default providers. */
	if (!providers_load()) {
		display_openssl_errors();
		goto cleanup;
	}

	/* Load the generated private key. */
	private_key = load_pkey(private_uri, "provider=pkcs11prov", NULL);
	if (private_key == NULL) {
		fprintf(stderr, "Cannot load private key: %s\n", private_uri);
		display_openssl_errors();
		goto cleanup;
	}

	printf("Private key found.\n");

	/* Load the generated public key. */
	public_key = load_pubkey(public_uri, "provider=pkcs11prov");
	if (public_key == NULL) {
		fprintf(stderr, "Cannot load public key: %s\n", public_uri);
		display_openssl_errors();
		goto cleanup;
	}

	printf("Public key found.\n");

	if (!mlkem_test(private_key, public_key))
		goto cleanup;

	ret = EXIT_SUCCESS;

cleanup:
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);

	if (slots != NULL)
		PKCS11_release_all_slots(ctx, slots, nslots);

	if (ctx != NULL) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	providers_cleanup();

	printf("\n");
	return ret;
}

#else /* !defined(OPENSSL_NO_ML_KEM) &&
	OPENSSL_VERSION_NUMBER >= 0x30500000L */

#include <stdio.h>

int main(void)
{
	fprintf(stderr,
		"Skipped: requires OpenSSL >= 3.5 built with ML-KEM support\n");
	return 77;
}

#endif /* !defined(OPENSSL_NO_ML_KEM) &&
	OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* vim: set noexpandtab: */
