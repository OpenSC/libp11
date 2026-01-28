/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * PKCS#11 provider test
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

#define TEST_DATA "test data"

int main(int argc, char **argv) {
	EVP_PKEY *private_key = NULL, *public_key = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	const EVP_MD *digest_algo = NULL;
	unsigned char sig[4096], md[128];
	size_t sig_len, md_len;
	unsigned int digest_len;
	int ret = EXIT_FAILURE;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [private key URL] [public key URL]\n", argv[0]);
		return ret;
	}

	/* Load pkcs11prov and default providers */
	if (!providers_load()) {
		display_openssl_errors();
		return ret;
	}

	/* Load keys */
	private_key = load_pkey(argv[1], NULL);
	if (!private_key) {
		fprintf(stderr, "Cannot load private key: %s\n", argv[1]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");
	public_key = load_pubkey(argv[2]);
	if (!public_key) {
		fprintf(stderr, "Cannot load public key: %s\n", argv[2]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Public key found.\n");

	/* Digest calculation */
	digest_algo = EVP_get_digestbyname("sha256");
	if (!digest_algo) {
		fprintf(stderr, "Could not get digest algorithm\n");
		goto cleanup;
	}
	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx || EVP_DigestInit(md_ctx, digest_algo) <= 0 ||
		EVP_DigestUpdate(md_ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0 ||
		EVP_DigestFinal(md_ctx, md, &digest_len) <= 0) {
		fprintf(stderr, "Digest computation failed\n");
		display_openssl_errors();
		goto cleanup;
	}
	md_len = (size_t)digest_len;
	EVP_MD_CTX_free(md_ctx);
	md_ctx = NULL;

	/* Signing */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
	if (!pkey_ctx || EVP_PKEY_sign_init(pkey_ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo) <= 0) {
		fprintf(stderr, "Signing initialization failed\n");
		display_openssl_errors();
		goto cleanup;
	}
	sig_len = sizeof(sig);
	if (EVP_PKEY_sign(pkey_ctx, sig, &sig_len, md, (size_t)EVP_MD_size(digest_algo)) <= 0) {
		fprintf(stderr, "Signing failed\n");
		display_openssl_errors();
		goto cleanup;
	}
	EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL;
	printf("Signature created.\n");

	/* Verification */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
	if (!pkey_ctx || EVP_PKEY_verify_init(pkey_ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo) <= 0) {
		fprintf(stderr, "Verification initialization failed\n");
		display_openssl_errors();
		goto cleanup;
	}
	ret = EVP_PKEY_verify(pkey_ctx, sig, sig_len, md, md_len);
	if (ret < 0) {
		fprintf(stderr, "Verification error\n");
		display_openssl_errors();
		goto cleanup;
	}

	if (ret == 1) {
		printf("Signature verified.\n");
		ret = EXIT_SUCCESS;
	} else {
		printf("Verification failed.\n");
		display_openssl_errors();
		ret = EXIT_FAILURE;
	}

cleanup:
	EVP_PKEY_CTX_free(pkey_ctx);
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(private_key);
	EVP_PKEY_free(public_key);
	providers_cleanup();
	printf("\n");
	return ret;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#include <stdio.h>

int main() {
	fprintf(stderr, "Skipped: requires OpenSSL >= 3.0\n");
	return 77;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
