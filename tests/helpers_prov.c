/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * PKCS#11 provider tests support library
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

DEFINE_STACK_OF(OSSL_PROVIDER)
static STACK_OF(OSSL_PROVIDER) *providers;

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

 /* store_type == 0 means here multiple types of credentials are to be loaded */
void load_objects(const char *uri, const UI_METHOD *ui_method, OBJ_SET *obj_set) {
	OSSL_STORE_CTX *store_ctx;
	int type;

	store_ctx = OSSL_STORE_open(uri, ui_method, NULL, NULL, NULL);
	if (!store_ctx)
		return; /* FAILED */

	while (!OSSL_STORE_eof(store_ctx)) {
		OSSL_STORE_INFO *object = OSSL_STORE_load(store_ctx);

		if (!object)
			continue;

		type = OSSL_STORE_INFO_get_type(object);
		switch (type) {
		case OSSL_STORE_INFO_PKEY:
			obj_set->private_key = OSSL_STORE_INFO_get1_PKEY(object);
			break;
		case OSSL_STORE_INFO_PUBKEY:
			obj_set->public_key = OSSL_STORE_INFO_get1_PUBKEY(object);
			break;
		case OSSL_STORE_INFO_CERT:
			obj_set->cert = OSSL_STORE_INFO_get1_CERT(object);
			break;
		default:
			break; /* skip any other type */
		}
		OSSL_STORE_INFO_free(object);
	}
	OSSL_STORE_close(store_ctx);
}

EVP_PKEY *load_pkey(const char *uri, const UI_METHOD *ui_method)
{
	EVP_PKEY *pkey = NULL;
	OSSL_STORE_INFO *info;
	OSSL_STORE_CTX *store_ctx;

	store_ctx = OSSL_STORE_open(uri, ui_method, NULL, NULL, NULL);
	if (!store_ctx) {
		return NULL;
	}
	if (!OSSL_STORE_expect(store_ctx, OSSL_STORE_INFO_PKEY)) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	info = OSSL_STORE_load(store_ctx);
	if (info == NULL) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
		pkey = OSSL_STORE_INFO_get1_PKEY(info);
	}
	OSSL_STORE_INFO_free(info);
	OSSL_STORE_close(store_ctx);
	return pkey;
}

EVP_PKEY *load_pubkey(const char *uri)
{
	EVP_PKEY *pkey = NULL;
	OSSL_STORE_INFO *info;
	OSSL_STORE_CTX *store_ctx;

	store_ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!store_ctx) {
		return NULL;
	}
	if (!OSSL_STORE_expect(store_ctx, OSSL_STORE_INFO_PUBKEY)) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	info = OSSL_STORE_load(store_ctx);
	if (info == NULL) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PUBKEY) {
		pkey = OSSL_STORE_INFO_get1_PUBKEY(info);
	}
	OSSL_STORE_INFO_free(info);
	OSSL_STORE_close(store_ctx);
	return pkey;
}

X509 *load_cert(const char *uri)
{
	X509 *cert = NULL;
	OSSL_STORE_INFO *info;
	OSSL_STORE_CTX *store_ctx;

	store_ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!store_ctx) {
		return NULL;
	}
	if (!OSSL_STORE_expect(store_ctx, OSSL_STORE_INFO_CERT)) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	info = OSSL_STORE_load(store_ctx);
	if (info == NULL) {
		OSSL_STORE_close(store_ctx);
		return NULL;
	}
	if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT) {
		cert = OSSL_STORE_INFO_get1_CERT(info);
	}
	OSSL_STORE_INFO_free(info);
	OSSL_STORE_close(store_ctx);
	return cert;
}

void provider_free(OSSL_PROVIDER *prov)
{
	printf("Provider \"%s\" unloaded.\n", OSSL_PROVIDER_get0_name(prov));
	OSSL_PROVIDER_unload(prov);
}

void providers_cleanup(void)
{
	sk_OSSL_PROVIDER_pop_free(providers, provider_free);
	providers = NULL;
}

int provider_load(const char *pname)
{
	OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, pname);

	if (prov == NULL) {
		fprintf(stderr, "Unable to load provider: %s\n", pname);
		return 0; /* FAILED */
	}
	if (providers == NULL) {
		providers = sk_OSSL_PROVIDER_new_null();
	}
	if (providers == NULL || !sk_OSSL_PROVIDER_push(providers, prov)) {
		providers_cleanup();
		return 0; /* FAILED */
	}
	printf("Provider \"%s\" set.\n", OSSL_PROVIDER_get0_name(prov));
	return 1; /* OK */
}

int providers_load(void)
{
	/* Load PKCS#11 provider */
	if (!OSSL_PROVIDER_available(NULL, "pkcs11prov")) {
		if (!provider_load("pkcs11prov")) {
			fprintf(stderr, "Failed to load \"pkcs11prov\" provider\n");
			return 0; /* FAILED */
		}
		/* load the default provider explicitly */
		if (!provider_load("default")) {
			fprintf(stderr, "Failed to load \"default\" provider\n");
			return 0; /* FAILED */
		}
	}
	return 1; /* OK */
}

#else

/* Disable ISO C forbids an empty translation unit [-Wpedantic] warning */
extern int make_iso_compilers_happy;

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
