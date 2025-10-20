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

#include <libp11.h>
#include <string.h>
#include "helpers_prov.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define CHECK_ERR(cond, txt, code) \
	do { \
		if (cond) { \
			fprintf(stderr, "%s\n", (txt)); \
			rc=(code); \
			goto cleanup; \
		} \
	} while (0)

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

static int sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub) {
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	const char *msg = "libp11";
	size_t siglen, msglen = strlen(msg);
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		printf("Where are the keys?\n");
		return -1;
	}

	siglen = (size_t)EVP_PKEY_get_size(priv);
	sig = OPENSSL_malloc(siglen);
	if (!sig) {
		ERR_print_errors_fp(stderr);
		return -2;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		retval = -3;
		goto err;
	}

	if (EVP_PKEY_sign_init(ctx) <= 0) {
		ERR_print_errors_fp(stderr);
		retval = -4;
		goto err;
	}

	if (EVP_PKEY_sign(ctx, sig, &siglen, msg, msglen) <= 0) {
		ERR_print_errors_fp(stderr);
		retval = -5;
		goto err;
	}
	printf("Sign success\n");

	/* --- Verify --- */
	EVP_MD_CTX_reset(mdctx);

	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub) != 1) {
		ERR_print_errors_fp(stderr);
		retval = -6;
		goto err;
	}

	if (EVP_DigestVerify(mdctx, sig, siglen, (const unsigned char *)msg, msglen) == 1) {
		printf("Verify success\n");
		retval = 0;
	} else {
		ERR_print_errors_fp(stderr);
		printf("Verify fail\n");
		retval = -7;
	}

err:
	if (sig)
		OPENSSL_free(sig);
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	return retval;
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
		printf("%s /usr/lib/opensc-pkcs11.so [TOKEN1] [KEY-LABEL] [PIN]\n", argv[0]);
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
	 * EC key generation test
	 */
	rc = PKCS11_keygen(slot->token, &eckg);
	error_queue("PKCS11_keygen");
	CHECK_ERR(rc < 0, "Failed to generate a key pair on the token", 8);
	printf("EC keys generated\n");

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

	if ((ret = sign_verify_test(private_key, public_key)) < 0) {
		printf("EC Sign-verify failed with err code: %d\n", ret);
		goto cleanup;
	}
	printf("EC Sign-verify success\n");

	ret = 0;
cleanup:
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);
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
