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

/* this code extensively uses deprecated features, so warnings are useless */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <libp11.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#ifndef OPENSSL_NO_ENGINE

static void display_openssl_errors(int l)
{
	const char* file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	printf("At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		printf("- SSL %s: %s:%d\n", buf, file, line);
	}
}

static int sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub) {
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
		display_openssl_errors(__LINE__);
		retval = -2;
		goto err;
	}
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv) != 1) {
		display_openssl_errors(__LINE__);
		retval = -3;
		goto err;
	}
	if (EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) != 1) {
		display_openssl_errors(__LINE__);
		retval = -4;
		goto err;
	}
	if (EVP_DigestSignFinal(mdctx, NULL, &slen) != 1) {
		display_openssl_errors(__LINE__);
		retval = -5;
		goto err;
	}
	if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen)))) {
		display_openssl_errors(__LINE__);
		retval = -6;
		goto err;
	}
	if (EVP_DigestSignFinal(mdctx, sig, &slen) != 1) {
		display_openssl_errors(__LINE__);
		retval = -7;
		printf("Sign fail\n");
		goto err;
	}
	printf("Sign success\n");

	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub) != 1) {
		display_openssl_errors(__LINE__);
		retval = -8;
		goto err;
	}
	if (EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)) != 1) {
		display_openssl_errors(__LINE__);
		retval = -9;
		goto err;
	}
	if (EVP_DigestVerifyFinal(mdctx, sig, slen) == 1) {
		printf("Verify success\n");
		retval = 0;
		goto err;
	} else {
		display_openssl_errors(__LINE__);
		printf("Verify fail\n");
		retval = -10;
		goto err;
	}

err:
	if (sig)
		OPENSSL_free(sig);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	return retval;
}

int main(int argc, char* argv[])
{
	int ret = EXIT_FAILURE, res;
	ENGINE* engine = NULL;
	const char *efile, *module;
	char *key_pass;
	EVP_PKEY *ecpb = NULL;
	EVP_PKEY *ecpr = NULL;
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
		.token_label = NULL,
		.key_label = NULL,
		.key_id = (const unsigned char *)"\x22\x33",
		.id_len = 2,
		.key_params = &params,
	};

	if (argc < 5) {
		printf("Too few arguments\n");
		printf("%s [TOKEN1] [KEY-LABEL] [PIN] [CONF] [module]\n", argv[0]);
		goto cleanup;
	}
	eckg.token_label = argv[1];
	eckg.key_label = argv[2];
	key_pass = argv[3];
	efile = argv[4];
	module = argv[5];

	res = CONF_modules_load_file(efile, "engines", 0);
	if (res <= 0) {
		printf("cannot load %s\n", efile);
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	ENGINE_add_conf_module();
#if OPENSSL_VERSION_NUMBER>=0x10100000
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
		| OPENSSL_INIT_ADD_ALL_DIGESTS \
		| OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
#endif
	ERR_clear_error();

	ENGINE_load_builtin_engines();
	engine = ENGINE_by_id("pkcs11");
	if (engine == NULL) {
		printf("Could not get engine\n");
		display_openssl_errors(__LINE__);
		goto cleanup;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "PIN", key_pass, 0)) {
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	if (!ENGINE_ctrl_cmd_string(engine, "DEBUG_LEVEL", "7", 0)) {
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	if (module) {
		if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module, 0)) {
			display_openssl_errors(__LINE__);
			goto cleanup;
		}
	}
	if (!ENGINE_init(engine)) {
		printf("Could not initialize engine\n");
		display_openssl_errors(__LINE__);
		goto cleanup;
	}
	/*
	 * ENGINE_init() returned a functional reference, so free the structural
	 * reference from ENGINE_by_id().
	 */
	ENGINE_free(engine);

	/*
	 * EC key generation test
	 */
	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &eckg, NULL, 1)) {
		printf("Could not generate EC keys\n");
		goto cleanup;
	}
	printf("EC keys generated\n");

	ecpb = ENGINE_load_public_key(engine, "2233", NULL, NULL);
	ecpr = ENGINE_load_private_key(engine, "2233", NULL, NULL);
	if ((ret = sign_verify_test(ecpr, ecpb)) < 0) {
		printf("EC Sign-verify failed with err code: %d\n", ret);
		goto cleanup;
	}
	printf("EC Sign-verify success\n");

	ret = 0;
cleanup:
	ENGINE_finish(engine);
	EVP_PKEY_free(ecpb);
	EVP_PKEY_free(ecpr);

	return ret;
}

#else /* OPENSSL_NO_ENGINE */

#include <stdio.h>

int main() {
	fprintf(stderr, "Skipped: ENGINE support not available\n");
	return 77;
}

#endif /* OPENSSL_NO_ENGINE */

/* vim: set noexpandtab: */
