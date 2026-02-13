/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "helpers_prov.h"
#include "eddsa_common.h"

#if !defined(OPENSSL_NO_EC) && (OPENSSL_VERSION_NUMBER >= 0x30000000L)

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int rc = 0;
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	unsigned int nslots;
	EVP_PKEY *private_key = NULL, *public_key = NULL;
	PKCS11_EDDSA_KGEN eddsa = {
		.nid = NID_ED25519
	};
	PKCS11_params params = {
		.sensitive = 1,
		.extractable = 0,
	};
	PKCS11_KGEN_ATTRS eckg = {
		.type = EVP_PKEY_ED25519,
		.kgen.eddsa = &eddsa,
		.token_label = NULL,
		.key_label = NULL,
		.key_id = (const unsigned char *)"\x22\x33",
		.id_len = 2,
		.key_params = &params,
	};

	if (argc < 4) {
		printf("Too few arguments\n");
		printf("%s /usr/lib/opensc-pkcs11.so [MODULE] [TOKEN1] [KEY-LABEL] [PIN]\n", argv[0]);
		goto cleanup;
	}
	eckg.token_label = argv[2];
	eckg.key_label = argv[3];

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load PKCS#11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading PKCS#11 module failed", 4);

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 5);

	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	while (slot) {
		if (slot->token && slot->token->initialized && slot->token->label
			&& strcmp(argv[2], slot->token->label) == 0)
			break;
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);
	};
	CHECK_ERR(!slot || !slot->token, "no token available", 6);

	printf("Found token:\n");
	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	rc = PKCS11_login(slot, 0, argv[4]);
	error_queue("PKCS11_login");
	CHECK_ERR(rc < 0, "PKCS11_login failed", 7);
	/*
	 * Ed25519 key generation test
	 */
	rc = PKCS11_keygen(slot->token, &eckg);
	error_queue("PKCS11_keygen");
	CHECK_ERR(rc < 0, "Failed to generate a key pair on the token", 8);
	printf("Ed25519 keys generated\n");

	/* Load pkcs11prov and default providers */
	if (!providers_load()) {
		display_openssl_errors();
		goto cleanup;
	}

	/* Load keys */
	private_key = load_pkey("pkcs11:token=token1;object=libp11-keylabel;type=private", NULL);
	if (!private_key) {
		printf("Cannot load private key: %s\n", argv[3]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");

	public_key = load_pubkey("pkcs11:token=token1;object=libp11-keylabel;type=public");
	if (!public_key) {
		printf("Cannot load public key: %s\n", argv[3]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Public key found.\n");

	if ((ret = EVP_Digest_sign_verify_test(private_key, public_key)) < 0) {
		printf("EVP_Digest_sign_verify_test() failed with err code: %d\n", ret);
		display_openssl_errors();
		goto cleanup;
	}
	if ((ret = EVP_PKEY_sign_verify_test(private_key, public_key)) < 0) {
		printf("EVP_PKEY_sign_verify_test() failed with err code: %d\n", ret);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Ed25519 Sign-verify success\n");

	ret = 0;
cleanup:
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}
	providers_cleanup();
	printf("\n");
	return ret;
}

#else /* !OPENSSL_NO_EC && OpenSSL 3.x */

#include <stdio.h>

int main() {
	fprintf(stderr, "Skipped: requires OpenSSL >= 3.0 built with EC support\n");
	return 77;
}

#endif /* !OPENSSL_NO_EC && OPENSSL_VERSION_NUMBER >= 0x30000000L  */

/* vim: set noexpandtab: */
