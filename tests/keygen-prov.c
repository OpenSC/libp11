 /*
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
#include <string.h>

#include "helpers_prov.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <libp11.h>

static PKCS11_CTX *global_pkcs11_ctx = NULL;
static PKCS11_SLOT *global_pkcs11_slots = NULL;
static unsigned int global_pkcs11_slot_num;

static int sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub)
{
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	char *msg = "libp11";
	size_t slen;
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		printf("Where are the keys?\n");
		return -1;
	}
	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		display_openssl_errors();
		retval = -2;
		goto err;
	}
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv)) {
		display_openssl_errors();
		retval = -3;
		goto err;
	}
	if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors();
		retval = -4;
		goto err;
	}
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
		display_openssl_errors();
		retval = -5;
		goto err;
	}
	if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen)))) {
		display_openssl_errors();
		retval = -6;
		goto err;
	}
	if (1 != EVP_DigestSignFinal(mdctx, sig, &slen)) {
		display_openssl_errors();
		retval = -7;
		printf("Sign fail\n");
		goto err;
	}
	printf("Sign success\n");

	if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub)) {
		display_openssl_errors();
		retval = -8;
		goto err;
	}
	if (1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors();
		retval = -9;
		goto err;
	}
	if (1 == EVP_DigestVerifyFinal(mdctx, sig, slen)) {
		printf("Verify success\n");
		retval = 0;
		goto err;
	} else {
		display_openssl_errors();
		printf("Verify fail\n");
		retval = -10;
		goto err;
	}

err:
	if(sig) OPENSSL_free(sig);
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	return retval;
}

static EVP_PKEY *setup_private(const char *token, const char *id, const char *obj,
				const char *pin)
{
	char uri[200];

	uri[0] = '\0';
	strcat(uri, "pkcs11:token=");
	strcat(uri, token);
	strcat(uri, ";id=");
	strcat(uri, id);
	strcat(uri, ";object=");
	strcat(uri, obj);
	strcat(uri, ";type=private;pin-value=");
	strcat(uri, pin);
	printf("private uri: '%s'\n", uri);

	return load_pkey(uri, NULL);
}

static EVP_PKEY *setup_public(const char *token, const char *id, const char *obj)
{
	char uri[200];

	uri[0] = '\0';
	strcat(uri, "pkcs11:token=");
	strcat(uri, token);
	strcat(uri, ";id=");
	strcat(uri, id);
	strcat(uri, ";object=");
	strcat(uri, obj);
	strcat(uri, ";type=public");
	printf("public uri: '%s'\n", uri);

	return load_pubkey(uri);
}

int main(int argc, char* argv[])
{
	int ret = EXIT_FAILURE;
	PKCS11_SLOT *slot;

	if (argc < 4) {
		printf("Too few arguments\n");
		printf("%s [TOKEN1] [KEY-LABEL] [PIN] [module]\n", argv[0]);
		exit(ret);
	}
	const char *token_label = argv[1], *key_label = argv[2], *module = argv[4];
	char *key_pass = argv[3];

	/* Load pkcs11prov and default providers */
	if (!providers_load()) {
		display_openssl_errors();
		return ret;
	}

	global_pkcs11_ctx = PKCS11_CTX_new();
	if (!global_pkcs11_ctx) {
		fprintf(stderr, "Could not initialize libp11 context\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (PKCS11_CTX_load(global_pkcs11_ctx, module)) {
		fprintf(stderr, "Could not load PKCS11 module\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (PKCS11_enumerate_slots(global_pkcs11_ctx,
			&global_pkcs11_slots, &global_pkcs11_slot_num)) {
		display_openssl_errors();
		goto cleanup;
	}

	slot = PKCS11_find_token(global_pkcs11_ctx, global_pkcs11_slots,
			global_pkcs11_slot_num);
	while (slot) {
		if (slot->token && strcmp(token_label, slot->token->label) == 0)
			break;
		slot = PKCS11_find_next_token(global_pkcs11_ctx,
			global_pkcs11_slots, global_pkcs11_slot_num, slot);
	}

	if (!slot) {
		printf("Could not find token: %s\n", token_label);
		display_openssl_errors();
		goto cleanup;
	}

	if (PKCS11_open_session(slot, 1)) {
		printf("Could not open session\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (PKCS11_login(slot, 0, key_pass)) {
		printf("Could not login to slot\n");
		display_openssl_errors();
		goto cleanup;
	}

	int res;
	if (!PKCS11_is_logged_in(slot, 0, &res) && res != 1) {
		printf("Login was unsuccessful.\n");
		display_openssl_errors();
		goto cleanup;
	}
	printf("Starting the key generation\n");
	/*
	 * EC key generation test
	 */
	PKCS11_EC_KGEN ec = {
		.curve = "P-256"
	};
	PKCS11_params params = {
		.sensitive = 1,
		.extractable = 0,
	};
	PKCS11_KGEN_ATTRS eckg = {
		.type = EVP_PKEY_EC,
		.kgen.ec = &ec,
		.token_label = token_label,
		.key_label = key_label,
		.key_id = (const unsigned char *)"\x12\x34",
		.id_len = 2,
		.key_params = &params,
	};

	if (!PKCS11_keygen(slot->token, &eckg)) {
		printf("Could not generate ECC keys\n");
		unsigned long err = ERR_get_error();
		char err_buf[256];
		ERR_error_string_n(err, err_buf, sizeof(err_buf));
		printf("PKCS11_keygen failed: %s\n", err_buf);

		display_openssl_errors();
		goto cleanup;
	}
	printf("ECC keys generated\n");

	EVP_PKEY *ecpb = setup_public(token_label, "%01%02%03%04", key_label);
	EVP_PKEY *ecpr = setup_private(token_label, "%01%02%03%04", key_label, key_pass);
	if ((ret = sign_verify_test(ecpr, ecpb)) < 0) {
		printf("ECC Sign-verify failed with err code: %d\n", ret);
		goto cleanup;
	}
	printf("ECC Sign-verify success\n");

	/*
	 * RSA key generation test
	 */
	PKCS11_RSA_KGEN rsa = {
		.bits = 2048
	};
	PKCS11_KGEN_ATTRS rsakg = {
		.type = EVP_PKEY_RSA,
		.kgen.rsa = &rsa,
		.token_label = token_label,
		.key_label = key_label,
		.key_id = (const unsigned char *)"\x43\x21",
		.id_len = 2,
		.key_params = &params,
	};

	if (!PKCS11_keygen(slot->token, &rsakg)) {
		printf("Could not generate RSA keys\n");
		goto cleanup;
	}
	printf("RSA keys generated\n");


	EVP_PKEY *rsapb = setup_public(token_label, "%04%03%02%01", key_label);
	EVP_PKEY *rsapr = setup_private(token_label, "%04%03%02%01", key_label, key_pass);
	if ((ret = sign_verify_test(rsapr, rsapb)) < 0) {
		printf("RSA Sign-verify failed with err code: %d\n", ret);
		exit(1);
	}
	printf("RSA Sign-verify success\n");

	PKCS11_release_all_slots(global_pkcs11_ctx, global_pkcs11_slots,
				 global_pkcs11_slot_num);

	ret = 0;
cleanup:
	if (global_pkcs11_ctx)
		PKCS11_CTX_free(global_pkcs11_ctx);
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
