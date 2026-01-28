/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * PKCS#11 provider test
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

#include "helpers_prov.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define TEST_DATA "test data"

/* UI method that is only used to fail if PIN is not set with PKCS#11
 "pin-value" or "pin-source" attribute */
static UI_METHOD *ui_detect_failed_ctrl = NULL;

/* This function is called when an attempt is made to open the UI */
static int ui_open_fail(UI *ui)
{
	(void) ui;
	fprintf(stderr, "The PIN should already be set\n");
	return 0;
}

/* method that's to be used for prompting with a default */
static UI_METHOD *ui_console_with_default = NULL;

static int setup_ui(void)
{
	UI_METHOD *default_method = UI_OpenSSL();

	ui_detect_failed_ctrl = UI_create_method("Fail if used");
	if (!ui_detect_failed_ctrl)
		return 0; /* FAILED */

	UI_method_set_opener(ui_detect_failed_ctrl, ui_open_fail);
	/* No other functions need setting, as the UI will never use them */

	ui_console_with_default = UI_create_method("Reader with possible default");
	if (!ui_console_with_default)
		return 0; /* FAILED */

	UI_method_set_opener(ui_console_with_default, UI_method_get_opener(default_method));
	UI_method_set_reader(ui_console_with_default, UI_method_get_reader(default_method));
	UI_method_set_writer(ui_console_with_default, UI_method_get_writer(default_method));
	UI_method_set_flusher(ui_console_with_default, UI_method_get_flusher(default_method));
	UI_method_set_closer(ui_console_with_default, UI_method_get_closer(default_method));
	return 1; /* OK */
}

int main(int argc, char **argv)
{
	unsigned char buf[4096];
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key = NULL, *public_key = NULL;
	unsigned n;
	EVP_MD_CTX *ctx;
	enum { NONE, BY_DEFAULT, BY_CTRL } pin_method = NONE;
	UI_METHOD *ui_method = NULL;
	int ret = EXIT_FAILURE;

	if (argc < 3) {
		fprintf(stderr, "usage: %s [PIN setting method] [private key URL] [public key URL]\n", argv[0]);
		return ret;
	}
	if (strcmp(argv[1], "default") == 0) {
		pin_method = BY_DEFAULT;
		printf("Default PIN setting method.\n");
	} else if (strcmp(argv[1], "ctrl") == 0) {
		pin_method = BY_CTRL;
		printf("Ctrl PIN setting method, ignore PIN value\n");
	} else {
		fprintf(stderr, "First argument MUST be 'default' or 'ctrl'\n");
		return ret;
	}

	if (!setup_ui()) {
		fprintf(stderr, "Failed to create UI methods\n");
		display_openssl_errors();
		goto cleanup;
	}

	switch (pin_method) {
	case BY_DEFAULT:
		ui_method = ui_console_with_default;
		break;
	case BY_CTRL:
		ui_method = ui_detect_failed_ctrl;
		break;
	default:
		break;
	}

	/* Load pkcs11prov and default providers */
	if (!providers_load()) {
		display_openssl_errors();
		return ret;
	}

	/* Load keys */
	private_key = load_pkey(argv[2], ui_method);
	if (!private_key) {
		fprintf(stderr, "Cannot load private key: %s\n", argv[2]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");
	public_key = load_pubkey(argv[3]);
	if (!public_key) {
		fprintf(stderr, "Cannot load public key: %s\n", argv[3]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Public key found.\n");

	digest_algo = EVP_get_digestbyname("sha256");
	ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(ctx, digest_algo) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	EVP_SignInit(ctx, digest_algo);
	if (EVP_SignUpdate(ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	n = sizeof(buf);
	if (EVP_SignFinal(ctx, buf, &n, private_key) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	EVP_MD_CTX_destroy(ctx);
	printf("Signature created.\n");

	ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(ctx, digest_algo) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, digest_algo, NULL, public_key) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_DigestVerifyUpdate(ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_DigestVerifyFinal(ctx, buf, n) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	EVP_MD_CTX_destroy(ctx);
	printf("Signature verified.\n");
	ret = EXIT_SUCCESS;

cleanup:
	if (ui_detect_failed_ctrl)
		UI_destroy_method(ui_detect_failed_ctrl);
	if (ui_console_with_default)
		UI_destroy_method(ui_console_with_default);
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);
	providers_cleanup();
	printf("\n");
	return ret;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#include <stdio.h>

int main() {
	fprintf(stderr, "Skipped: requires OpenSSL >= 3.0\n");
	return 77;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
