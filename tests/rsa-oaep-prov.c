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

#include <openssl/rand.h>

int main(int argc, char **argv)
{
	EVP_PKEY *private_key = NULL, *public_key = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	unsigned char data[32], dec[4096], enc[4096];
	size_t data_len, dec_len, enc_len;
	int ret = EXIT_FAILURE;

	if (argc < 2) {
		fprintf(stderr, "usage: %s [private key URL] [public key URL]\n", argv[0]);
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

	/* Generate random data */
	data_len = sizeof(data);
	if (!RAND_bytes(data, data_len)) {
		display_openssl_errors();
		goto cleanup;
	}
	/* Encrypt the data */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
	if (pkey_ctx == NULL) {
		fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_PKEY_encrypt_init(pkey_ctx) <= 0) {
		fprintf(stderr, "Could not init encryption\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
		fprintf(stderr, "Could not set padding\n");
		display_openssl_errors();
		goto cleanup;
	}
	enc_len = sizeof(enc);
	if (EVP_PKEY_encrypt(pkey_ctx, enc, &enc_len, data, data_len) <= 0) {
		display_openssl_errors();
		goto cleanup;
	}
	EVP_PKEY_CTX_free(pkey_ctx);
	printf("Data encrypted\n");

	/* Decrypt the data */
	pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
	if (pkey_ctx == NULL) {
		fprintf(stderr, "Could not create context\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {
		fprintf(stderr, "Could not init decryption\n");
		display_openssl_errors();
		goto cleanup;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
		fprintf(stderr, "Could not set padding\n");
		display_openssl_errors();
		goto cleanup;
	}

	/* Get the output length */
	ret = EVP_PKEY_decrypt(pkey_ctx, NULL, &dec_len, enc, enc_len);
	if (ret < 0) {
		display_openssl_errors();
		goto cleanup;
	}
	if (dec_len > sizeof(dec)){
		fprintf(stderr, "Buffer too small to hold decrypted data\n");
		goto cleanup;
	}
	ret = EVP_PKEY_decrypt(pkey_ctx, dec, &dec_len, enc, enc_len);
	if (ret < 0) {
		display_openssl_errors();
		goto cleanup;
	}

	/* Compare output */
	if (!memcmp(dec, data, data_len)) {
		printf("Successfully decrypted\n");
		ret = EXIT_SUCCESS;
	} else {
		printf("Decrypted data does not match original data\n");
		display_openssl_errors();
		ret = EXIT_FAILURE;
	}

cleanup:
	EVP_PKEY_CTX_free(pkey_ctx);
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
