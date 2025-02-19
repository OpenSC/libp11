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

#include <libp11.h>

static PKCS11_CTX *global_pkcs11_ctx = NULL;
static PKCS11_SLOT *global_pkcs11_slots = NULL;
static unsigned int global_pkcs11_slot_num;

static int extract_url_fields(char *address, char **out_token, char **out_label, char **out_pin)
{
	static const char DELIMITERS[] = ":;?&=";
	char *str, *token;
	if (strncmp(address, "pkcs11:", strlen("pkcs11:")) != 0) {
		printf("URL does not look valid: %s\n", address);
		return 0;
	}
	str = address + strlen("pkcs11:");
	while ((token = strtok(str, DELIMITERS))) {
		char** out = NULL;
		str = NULL;
		if (strcmp(token, "token") == 0) {
			out = out_token;
		} else if (strcmp(token, "object") == 0) {
			out = out_label;
		} else if (strcmp(token, "pin-value") == 0) {
			out = out_pin;
		} else {
			printf("Unrecognized token: %s\n", token);
			return 0;
		}
		if (out) {
			if (*out) {
				return 0;
				printf("Repeated token: %s\n", token);
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

static int store_certificate(char* address, X509* cert)
{
	PKCS11_SLOT *slot;
	char *token = NULL, *label = NULL, *pin = NULL;

	if (!extract_url_fields(address, &token, &label, &pin))
		return 0;

	slot = PKCS11_find_token(global_pkcs11_ctx, global_pkcs11_slots,
			global_pkcs11_slot_num);
	while (slot) {
		if (strcmp(token, slot->token->label) == 0)
			break;
		slot = PKCS11_find_next_token(global_pkcs11_ctx,
			global_pkcs11_slots, global_pkcs11_slot_num, slot);
	}

	if (!slot) {
		printf("Could not find token: %s\n", token);
		return 0;
	}

	if (PKCS11_open_session(slot, 1)) {
		printf("Could not open session\n");
		return 0;
	}

	if (PKCS11_login(slot, 0, pin)) {
		printf("Could not login to slot\n");
		return 0;
	}

	if (PKCS11_store_certificate(slot->token, cert, label,
			(unsigned char*)label, strlen(label), NULL)) {
		printf("Could not store certificate\n");
		return 0;
	}
	PKCS11_release_all_slots(global_pkcs11_ctx, global_pkcs11_slots,
	        global_pkcs11_slot_num);

	return 1;
}

int main(int argc, char *argv[])
{
	X509 *cert = NULL;
	int ret = EXIT_FAILURE;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [source certificate file] [target certificate URL] [module]\n", argv[0]);
		return ret;
	}

	/* Load pkcs11prov and default providers */
        if (!providers_load()) {
		display_openssl_errors();
		return ret;
        }

	/* Load certificate */
	cert = load_cert(argv[1]);
	if (!cert) {
		fprintf(stderr, "Cannot load certificate: %s\n", argv[1]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Certificate found: %s\n", argv[1]);

	global_pkcs11_ctx = PKCS11_CTX_new();
	if (!global_pkcs11_ctx) {
		fprintf(stderr, "Could not initialize libp11 context\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (PKCS11_CTX_load(global_pkcs11_ctx, argv[3])) {
		fprintf(stderr, "Could not load PKCS11 module\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (PKCS11_enumerate_slots(global_pkcs11_ctx,
			&global_pkcs11_slots, &global_pkcs11_slot_num)) {
		display_openssl_errors();
		goto cleanup;
	}

	ret = store_certificate(argv[2], cert);
	if (ret == 1) {
		printf("Certificate stored.\n");
		ret = EXIT_SUCCESS;
	} else {
		printf("Storing failed.\n");
		display_openssl_errors();
		ret = EXIT_FAILURE;
	}

cleanup:
	if (global_pkcs11_ctx)
		PKCS11_CTX_free(global_pkcs11_ctx);
	X509_free(cert);
	providers_cleanup();
	printf("\n");
	return ret;
}

#else

int main() {
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
