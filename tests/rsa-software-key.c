/*
 * Copyright (C) 2026 OpenSC Project
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

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x40000000L && \
	!defined(OPENSSL_NO_RSA)

#include <libp11.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static EVP_PKEY *generate_software_key(void)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx)
		return NULL;
	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
			EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
			EVP_PKEY_generate(ctx, &key) <= 0) {
		EVP_PKEY_free(key);
		key = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return key;
}

static int sign_certificate(EVP_PKEY *key)
{
	static const unsigned char common_name[] = "libp11 software RSA test";
	X509_NAME *name;
	X509 *cert;
	int ret = 0;

	cert = X509_new();
	if (!cert)
		return 0;
	name = X509_get_subject_name(cert);
	if (!name || !X509_set_version(cert, 2) ||
			!ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) ||
			!X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
			!X509_gmtime_adj(X509_getm_notAfter(cert), 3600) ||
			!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				common_name, -1, -1, 0) ||
			!X509_set_issuer_name(cert, name) ||
			!X509_set_pubkey(cert, key) ||
			X509_sign(cert, key, EVP_sha256()) <= 0 ||
			X509_verify(cert, key) <= 0)
		goto cleanup;
	ret = 1;

cleanup:
	X509_free(cert);
	return ret;
}

int main(int argc, char **argv)
{
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	PKCS11_KEY *keys;
	EVP_PKEY *software_key = NULL, *new_software_key = NULL;
	EVP_PKEY *token_key = NULL;
	unsigned int nslots = 0, nkeys = 0;
	int ret = EXIT_FAILURE;

	if (argc != 3) {
		fprintf(stderr, "usage: %s [module] [PIN]\n", argv[0]);
		return EXIT_FAILURE;
	}

	software_key = generate_software_key();
	if (!software_key || !EVP_PKEY_get0_provider(software_key) ||
			!sign_certificate(software_key)) {
		fprintf(stderr, "Initial software RSA operation failed\n");
		goto cleanup;
	}

	ctx = PKCS11_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to initialize PKCS#11\n");
		goto cleanup;
	}
	if (PKCS11_CTX_load(ctx, argv[1]) < 0 ||
			PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
		fprintf(stderr, "Failed to initialize PKCS#11\n");
		goto cleanup;
	}
	slot = PKCS11_find_token(ctx, slots, nslots);
	if (!slot || PKCS11_login(slot, 0, argv[2]) < 0 ||
			PKCS11_enumerate_keys(slot->token, &keys, &nkeys) < 0 ||
			nkeys == 0) {
		fprintf(stderr, "Failed to find a PKCS#11 private key\n");
		goto cleanup;
	}
	token_key = PKCS11_get_private_key(&keys[0]);
	if (!token_key) {
		fprintf(stderr, "PKCS11_get_private_key failed\n");
		goto cleanup;
	}
	/* X509_sign() uses PKCS#1 v1.5 for an unrestricted RSA key. */
	if (!sign_certificate(token_key)) {
		fprintf(stderr, "PKCS#1 v1.5 signing with the PKCS#11 key failed\n");
		goto cleanup;
	}

	/* Loading a token key must not alter a provider-backed key that was
	 * created earlier, or change how subsequent software keys are created. */
	new_software_key = generate_software_key();
	if (!EVP_PKEY_get0_provider(software_key) ||
			!sign_certificate(software_key) || !new_software_key ||
			!EVP_PKEY_get0_provider(new_software_key) ||
			!sign_certificate(new_software_key)) {
		fprintf(stderr, "PKCS#11 key affected an unrelated software RSA key\n");
		goto cleanup;
	}

	ret = EXIT_SUCCESS;

cleanup:
	if (ret != EXIT_SUCCESS)
		ERR_print_errors_fp(stderr);
	EVP_PKEY_free(new_software_key);
	EVP_PKEY_free(token_key);
	EVP_PKEY_free(software_key);
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}
	return ret;
}

#else

int main(void)
{
	fprintf(stderr, "Skipped: test requires RSA with OpenSSL 3.x\n");
	return 77;
}

#endif

/* vim: set noexpandtab: */
