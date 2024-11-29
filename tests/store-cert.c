/*
 * Copyright (C) 2019 Anderson Toshiyuki Sasaki
 * Copyright (C) 2019 Red Hat, Inc.
 * Copyright (C) 2020 Mateusz Kwiatkowski
 * Copyright (C) 2020 AVSystem
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

#include <string.h>

/* this code extensively uses deprecated features, so warnings are useless */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <libp11.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

static void
usage(char* argv[])
{
	fprintf(stderr,
		"%s [source certificate file] [target certificate URL]\n",
		argv[0]);
}

static void
display_openssl_errors(int l)
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

static int
extract_url_fields(char* address,
		   char** out_token,
		   char** out_label,
		   char** out_pin)
{
	static const char DELIMITERS[] = ":;?&=";
	char *str, *token;
	if (strncmp(address, "pkcs11:", strlen("pkcs11:")) != 0) {
		printf("URL does not look valid: %s\n", address);
		return -1;
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
			return -1;
		}
		if (out) {
			if (*out) {
				return -1;
				printf("Repeated token: %s\n", token);
			} else if ((token = strtok(str, DELIMITERS))) {
				*out = token;
			}
		}
	}
	if (!*out_token || !*out_label || !*out_pin) {
		printf("URL incomplete\n");
		return -1;
	}
	return 0;
}

static PKCS11_CTX* global_pkcs11_ctx;
static PKCS11_SLOT* global_pkcs11_slots;
static unsigned int global_pkcs11_slot_num;

static int
store_certificate(char* address, X509* cert)
{
	char *token = NULL, *label = NULL, *pin = NULL;
	if (extract_url_fields(address, &token, &label, &pin)) {
		return -1;
	}

	PKCS11_SLOT* slot = PKCS11_find_token(
	  global_pkcs11_ctx, global_pkcs11_slots, global_pkcs11_slot_num);
	while (slot) {
		if (strcmp(token, slot->token->label) == 0) {
			break;
		}
		slot = PKCS11_find_next_token(global_pkcs11_ctx,
					      global_pkcs11_slots,
					      global_pkcs11_slot_num,
					      slot);
	}

	if (!slot) {
		printf("Could not find token: %s\n", token);
		return -1;
	}

	if (PKCS11_open_session(slot, 1)) {
		printf("Could not open session\n");
		return -1;
	}

	if (PKCS11_login(slot, 0, pin)) {
		printf("Could not login to slot\n");
		return -1;
	}

	if (PKCS11_store_certificate(slot->token,
				     cert,
				     label,
				     (unsigned char*)label,
				     strlen(label),
				     NULL)) {
		printf("Could not store certificate\n");
		return -1;
	}
	PKCS11_release_all_slots(global_pkcs11_ctx, global_pkcs11_slots,
	        global_pkcs11_slot_num);

	return 0;
}

int
main(int argc, char* argv[])
{
	ENGINE* engine = NULL;
	X509* cert = NULL;
	FILE* cert_fp = NULL;

	char *certfile, *target, *module, *efile;

	int ret = 0;

	struct
	{
		const char* cert_id;
		X509* cert;
	} params = { 0 };

	if (argc < 2) {
		printf("Too few arguments\n");
		usage(argv);
		return 1;
	}

	certfile = argv[1];
	target = argv[2];
	module = argv[3];
	efile = argv[4];

	ret = CONF_modules_load_file(efile, "engines", 0);
	if (ret <= 0) {
		fprintf(stderr, "cannot load %s\n", efile);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	ENGINE_add_conf_module();
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
			      OPENSSL_INIT_ADD_ALL_DIGESTS |
			      OPENSSL_INIT_LOAD_CONFIG,
			    NULL);
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
	/*
	 * ENGINE_init() returned a functional reference, so free the structural
	 * reference from ENGINE_by_id().
	 */
	ENGINE_free(engine);

	if (!strncmp(certfile, "pkcs11:", 7)) {
		params.cert_id = certfile;
		if (!ENGINE_ctrl_cmd(
		      engine, "LOAD_CERT_CTRL", 0, &params, NULL, 1)) {
			fprintf(
			  stderr, "Could not get certificate %s\n", certfile);
			ret = 1;
			goto end;
		}
		cert = params.cert;
	} else {
		cert_fp = fopen(certfile, "rb");
		if (!cert_fp) {
			fprintf(stderr, "Could not open file %s\n", certfile);
			ret = 1;
			goto end;
		}

		cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
		if (!cert) {
			fprintf(stderr,
				"Could not read certificate file"
				"(must be PEM format)\n");
		}

		if (cert_fp) {
			fclose(cert_fp);
		}
	}

	if (!(global_pkcs11_ctx = PKCS11_CTX_new())) {
		printf("Could not initialize libp11 context\n");
		ret = 1;
	} else if (PKCS11_CTX_load(global_pkcs11_ctx, module)) {
		printf("Could not load PKCS11 module\n");
		ret = 1;
	} else if (PKCS11_enumerate_slots(global_pkcs11_ctx,
					  &global_pkcs11_slots,
					  &global_pkcs11_slot_num)) {
		printf("Could not enumerate slots\n");
		ret = 1;
	} else if (!(ret = store_certificate(target, cert) ? 1 : 0)) {
		printf("Certificate stored\n");
		ret = 0;
	}
	PKCS11_CTX_free(global_pkcs11_ctx);

	/* Free the functional reference from ENGINE_init */
	ENGINE_finish(engine);

	CONF_modules_unload(1);
end:
	X509_free(cert);

	return ret;
}
