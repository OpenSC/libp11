/*
 * Copyright (c) 2015 Red Hat, Inc.
 * All rights reserved.
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

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
			 * return without outputing any prompt */
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


static void display_openssl_errors(int l)
{
	const char *file;
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

int main(int argc, char **argv)
{
	char *private_key_name, *public_key_name;
	unsigned char buf[4096];
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key, *public_key;
	char *key_pass = NULL;
	unsigned n;
	int ret;
	ENGINE *e;
	EVP_MD_CTX *ctx;
	const char *module_path, *efile;
	enum { NONE, BY_DEFAULT, BY_CTRL } pin_method = NONE;
	UI_METHOD *ui_method = NULL;
	void *ui_extra = NULL;

	if (argc < 5) {
		fprintf(stderr, "usage: %s [PIN setting method] [PIN] [CONF] [private key URL] [public key URL] [module]\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "PIN setting method can be 'default' or 'ctrl'\n");
		exit(1);
	}

	if (strcmp(argv[1], "default") == 0)
		pin_method = BY_DEFAULT;
	else if (strcmp(argv[1], "ctrl") == 0)
		pin_method = BY_CTRL;
	else {
		fprintf(stderr, "First argument MUST be 'default' or 'ctrl'\n");
		exit(1);
	}
	key_pass = argv[2];
	efile = argv[3];
	private_key_name = argv[4];
	public_key_name = argv[5];
	module_path = argv[6];

	setup_ui();

	ret = CONF_modules_load_file(efile, "engines", 0);
	if (ret <= 0) {
		fprintf(stderr, "cannot load %s\n", efile);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	ENGINE_add_conf_module();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	ENGINE_load_builtin_engines();
	e = ENGINE_by_id("pkcs11");
	if (e == NULL) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_ctrl_cmd_string(e, "MODULE_PATH", module_path, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_init(e)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	switch (pin_method) {
	case BY_DEFAULT:
		ui_method = ui_console_with_default;
		ui_extra = key_pass;
		break;
	case BY_CTRL:
		ui_method = ui_detect_failed_ctrl;
		ui_extra = NULL;
		if (key_pass && !ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0)) {
			display_openssl_errors(__LINE__);
			exit(1);
		}
	default: /* NONE */
		break;
	}

	private_key = ENGINE_load_private_key(e, private_key_name,
		ui_method, ui_extra);
	if (private_key == NULL) {
		fprintf(stderr, "cannot load: %s\n", private_key_name);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	public_key = ENGINE_load_public_key(e, public_key_name,
		ui_method, ui_extra);
	if (public_key == NULL) {
		fprintf(stderr, "cannot load: %s\n", public_key_name);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	/* Digest the module data. */
	OpenSSL_add_all_digests();
	display_openssl_errors(__LINE__);

	digest_algo = EVP_get_digestbyname("sha1");

	ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(ctx, digest_algo) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	EVP_SignInit(ctx, digest_algo);

#define TEST_DATA "test data"
	if (EVP_SignUpdate(ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	n = sizeof(buf);
	if (EVP_SignFinal(ctx, buf, &n, private_key) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	EVP_MD_CTX_destroy(ctx);

	ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(ctx, digest_algo) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyInit(ctx, NULL, digest_algo, NULL, public_key) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyUpdate(ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyFinal(ctx, buf, n) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
	EVP_MD_CTX_destroy(ctx);

	EVP_PKEY_free(public_key);
	EVP_PKEY_free(private_key);
	ENGINE_finish(e);
	CONF_modules_unload(1);
	return 0;
}

/* vim: set noexpandtab: */
