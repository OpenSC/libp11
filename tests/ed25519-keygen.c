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

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/engine.h>
#include "eddsa_common.h"

#if !defined(OPENSSL_NO_ENGINE) && \
    !defined(OPENSSL_NO_EC) && \
    (OPENSSL_VERSION_NUMBER >= 0x30000000L) && \
    (OPENSSL_VERSION_NUMBER < 0x40000000L)

void display_openssl_errors(void)
{
	unsigned long e;
	const char *file = NULL, *func = NULL, *reason = NULL;
	int line = 0, flags = 0;
	char err_buf[256];

	while ((e = ERR_get_error_all(&file, &line, &func, &reason, &flags))) {
		ERR_error_string_n(e, err_buf, sizeof(err_buf));
		fprintf(stderr, "%s:%d: %s: %s: %s\n", file ? file : "unknown file",
			line, func ? func : "unknown function",
			err_buf, reason ? reason : "unknown reason");
	}
}

int main(int argc, char *argv[])
{
	ENGINE *engine = NULL;
	int ret = EXIT_FAILURE;
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

	if (argc < 5) {
		printf("Too few arguments\n");
		printf("%s /usr/lib/opensc-pkcs11.so [MODULE] [TOKEN1] [KEY-LABEL] [PIN] [CONF]\n", argv[0]);
		goto cleanup;
	}
	eckg.token_label = argv[2];
	eckg.key_label = argv[3];

	if (CONF_modules_load_file(argv[5], "engines", 0) <= 0) {
		printf("cannot load %s\n", argv[5]);
		display_openssl_errors();
		goto cleanup;
	}

	ENGINE_add_conf_module();
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
		| OPENSSL_INIT_ADD_ALL_DIGESTS \
		| OPENSSL_INIT_LOAD_CONFIG, NULL);
	ERR_clear_error();

	ENGINE_load_builtin_engines();
	engine = ENGINE_by_id("pkcs11");
	if (engine == NULL) {
		printf("Could not get engine\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "PIN", argv[4], 0)) {
		display_openssl_errors();
		goto cleanup;
	}
	if (!ENGINE_ctrl_cmd_string(engine, "DEBUG_LEVEL", "7", 0)) {
		display_openssl_errors();
		goto cleanup;
	}
	if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", argv[1], 0)) {
		display_openssl_errors();
		goto cleanup;
	}
	if (!ENGINE_init(engine)) {
		printf("Could not initialize engine\n");
		display_openssl_errors();
		goto cleanup;
	}
	/*
	 * ENGINE_init() returned a functional reference, so free the structural
	 * reference from ENGINE_by_id().
	 */
	ENGINE_free(engine);

	/*
	 * Ed25519 key generation test
	 */
	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &eckg, NULL, 1)) {
		printf("Could not generate  keys\n");
		goto cleanup;
	}
	printf("Ed25519 keys generated\n");

	/* Load keys */
	private_key = ENGINE_load_private_key(engine, "2233", NULL, NULL);
	if (!private_key) {
		printf("Cannot load private key: %s\n", argv[3]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");

	public_key = ENGINE_load_public_key(engine, "2233", NULL, NULL);
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
	ENGINE_finish(engine);
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);
	printf("\n");
	return ret;
}

#else /* !OPENSSL_NO_ENGINE && !OPENSSL_NO_EC && OpenSSL 3.x */

#include <stdio.h>

int main() {
	fprintf(stderr, "Skipped: requires OpenSSL 3.x built with ENGINE and EC support\n");
	return 77;
}

#endif /* !OPENSSL_NO_ENGINE && !OPENSSL_NO_EC && OpenSSL 3.x */

/* vim: set noexpandtab: */
