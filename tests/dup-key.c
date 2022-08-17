/*
* Copyright (C) 2019 - 2022 Red Hat, Inc.
*
* Authors: Anderson Toshiyuki Sasaki
*          Jakub Jelen <jjelen@redhat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static void usage(char *argv[])
{
	fprintf(stderr, "%s [private key URL] [module] [conf]\n", argv[0]);
}

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At dup-key.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

int main(int argc, char *argv[])
{
	ENGINE *engine = NULL;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL, *ec_dup = NULL;

	const char *module, *efile, *privkey;

	int ret = 0;

	if (argc < 3){
		printf("Too few arguments\n");
		usage(argv);
		return 1;
	}

	privkey = argv[1];
	module = argv[2];
	efile = argv[3];

	ret = CONF_modules_load_file(efile, "engines", 0);
	if (ret <= 0) {
		fprintf(stderr, "cannot load %s\n", efile);
		display_openssl_errors(__LINE__);
		exit(1);
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
		ret = 1;
		goto end;
	}

	if (!ENGINE_ctrl_cmd_string(engine, "VERBOSE", NULL, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_init(engine)) {
		printf("Could not initialize engine\n");
		display_openssl_errors(__LINE__);
		ret = 1;
		goto end;
	}

	pkey = ENGINE_load_private_key(engine, privkey, 0, 0);

	if (pkey == NULL) {
		printf("Could not load key\n");
		display_openssl_errors(__LINE__);
		ret = 1;
		goto end;
	}

	switch (EVP_PKEY_base_id(pkey)) {
	case EVP_PKEY_RSA:
		/* TODO */
		break;
	case EVP_PKEY_EC:
		ec = EVP_PKEY_get1_EC_KEY(pkey);
		if (ec == NULL) {
			printf("Could not get the EC_KEY\n");
			display_openssl_errors(__LINE__);
			ret = 1;
			goto end;
		}

		ec_dup = EC_KEY_dup(ec);
		if (ec_dup == NULL) {
			printf("Could not dup EC_KEY\n");
			display_openssl_errors(__LINE__);
			ret = 1;
			goto end;
		}
		EC_KEY_free(ec);
		EC_KEY_free(ec_dup);
		break;
	}
	ENGINE_finish(engine);

	ret = 0;

	CONF_modules_unload(1);
end:
	EVP_PKEY_free(pkey);

	return ret;
}

