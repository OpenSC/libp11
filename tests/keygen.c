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

static void usage(char* prog)
{
	fprintf(stderr, "%s token_label key_label [PIN] [CONF] [module]\n", prog);
}

static void display_openssl_errors(int l)
{
	const char* file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

/* UI method that's only used to fail if get_pin inside engine_pkcs11
 * has failed to pick up in a PIN sent in with ENGINE_ctrl_cmd_string */
static UI_METHOD *ui_detect_failed_ctrl = NULL;

static int ui_open_fail(UI *ui)
{
	(void) ui;
	fprintf(stderr, "It seems like get_pin fell through even though the pin should already be set!\n");
	return 0;
}

/* method that's to be used for prompting with a default (which is an
 * alternative to sending in a PIN sent in with ENGINE_ctrl_cmd_string) */
static UI_METHOD *ui_console_with_default = NULL;

static int ui_read(UI *ui, UI_STRING *uis)
{
	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
			UI_get0_user_data(ui)) {
		switch (UI_get_string_type(uis)) {
		case UIT_PROMPT:
		case UIT_VERIFY:
		{
			/* If there is a default PIN, use it
			 * instead of reading from the console */
			const char *password =
				((const char *)UI_get0_user_data(ui));
			if (password && password[0] != '\0') {
				UI_set_result(ui, uis, password);
				return 1;
			}
		}
		default:
			break;
		}
	}
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
			UI_get0_user_data(ui)) {
		switch (UI_get_string_type(uis)) {
		case UIT_PROMPT:
		case UIT_VERIFY:
		{
			/* If there is a default PIN, just
			 * return without outputting any prompt */
			const char *password =
				((const char *)UI_get0_user_data(ui));
			if (password && password[0] != '\0')
				return 1;
		}
		default:
			break;
		}
	}
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static void setup_ui()
{
	UI_METHOD *default_method = UI_OpenSSL();

	ui_detect_failed_ctrl = UI_create_method("Fail if used");
	UI_method_set_opener(ui_detect_failed_ctrl, ui_open_fail);
	/* No other functions need setting, as the UI will never use them */

	ui_console_with_default = UI_create_method("Reader with possible default");
	UI_method_set_opener(ui_console_with_default,
		UI_method_get_opener(default_method));
	UI_method_set_reader(ui_console_with_default, ui_read);
	UI_method_set_writer(ui_console_with_default, ui_write);
	UI_method_set_flusher(ui_console_with_default,
		UI_method_get_flusher(default_method));
	UI_method_set_closer(ui_console_with_default,
		UI_method_get_closer(default_method));
}

static int sign_verify_test(EVP_PKEY *priv, EVP_PKEY *pub) {
	EVP_MD_CTX *mdctx = NULL;
	int retval = 0;
	char *msg = "libp11";
	size_t slen;
	unsigned char *sig = NULL;

	if (!priv || !pub) {
		fprintf(stderr, "Where are the keys?\n");
		return -1;
	}
	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		display_openssl_errors(__LINE__);
		retval = -2;
		goto err;
	}
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv)) {
		display_openssl_errors(__LINE__);
		retval = -3;
		goto err;
	}
	if (1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors(__LINE__);
		retval = -4;
		goto err;
	}
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
		display_openssl_errors(__LINE__);
		retval = -5;
		goto err;
	}
	if (!(sig = OPENSSL_malloc(sizeof(unsigned char) * (slen)))) {
		display_openssl_errors(__LINE__);
		retval = -6;
		goto err;
	}
	if (1 != EVP_DigestSignFinal(mdctx, sig, &slen)) {
		display_openssl_errors(__LINE__);
		retval = -7;
		fprintf(stderr, "Sign fail\n");
		goto err;
	}
	printf("Sign success\n");

	if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub)) {
		display_openssl_errors(__LINE__);
		retval = -8;
		goto err;
	}
	if (1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) {
		display_openssl_errors(__LINE__);
		retval = -9;
		goto err;
	}
	if (1 == EVP_DigestVerifyFinal(mdctx, sig, slen)) {
		printf("Verify success\n");
		retval = 0;
		goto err;
	} else {
		display_openssl_errors(__LINE__);
		fprintf(stderr, "Verify fail\n");
		retval = -10;
		goto err;
	}

err:
	if(sig) OPENSSL_free(sig);
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	return retval;
}

int main(int argc, char* argv[])
{
	int ret = 0;
	ENGINE* engine = NULL;
	const char *key_pass = argv[3], *efile = argv[4], *module = argv[5];

	if (argc < 5) {
		fprintf(stderr, "Too few arguments\n");
		usage(argv[0]);
		return 1;
	}

	setup_ui();

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

	if (!ENGINE_ctrl_cmd_string(engine, "PIN", key_pass, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	if (!ENGINE_ctrl_cmd_string(engine, "DEBUG_LEVEL", "7", 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	if (module) {
		if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module, 0)) {
			display_openssl_errors(__LINE__);
			exit(1);
		}
	}
	if (!ENGINE_init(engine)) {
		fprintf(stderr, "Could not initialize engine\n");
		display_openssl_errors(__LINE__);
		exit(1);
	}

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
		.token_label = argv[1],
		.key_label = argv[2],
		.key_id = "1234",
		.id_len = 4,
		.key_params = &params,
	};

	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &eckg, NULL, 1)) {
		fprintf(stderr, "Could not generate ECC keys\n");
		exit(1);
	}

	EVP_PKEY *ecpb = ENGINE_load_public_key(engine, "1234", NULL, NULL);
	EVP_PKEY *ecpr = ENGINE_load_private_key(engine, "1234", NULL, NULL);
	if ((ret = sign_verify_test(ecpr, ecpb)) < 0) {
		fprintf(stderr, "ECC Sign-verify failed with err code: %d\n", ret);
		exit(1);
	}

	/*
	 * RSA key generation test
	 */
	PKCS11_RSA_KGEN rsa = {
		.bits = 2048
	};
	PKCS11_KGEN_ATTRS rsakg = {
		.type = EVP_PKEY_RSA,
		.kgen.rsa = &rsa,
		.token_label = argv[1],
		.key_label = argv[2],
		.key_id = "4321",
		.id_len = 4,
		.key_params = &params,
	};

	if (!ENGINE_ctrl_cmd(engine, "KEYGEN", 0, &rsakg, NULL, 1)) {
		fprintf(stderr, "Could not generate RSA keys\n");
		exit(1);
	}
	EVP_PKEY *rsapb = ENGINE_load_public_key(engine, "4321", NULL, NULL);
	EVP_PKEY *rsapr = ENGINE_load_private_key(engine, "4321", NULL, NULL);
	if ((ret = sign_verify_test(rsapr, rsapb)) < 0) {
		fprintf(stderr, "RSA Sign-verify failed with err code: %d\n", ret);
		exit(1);
	}

	ENGINE_finish(engine);
end:

	return ret;
}
