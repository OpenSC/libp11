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

int main(int argc, char *argv[])
{
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *private_key_dup = NULL;
	int ret = EXIT_FAILURE;

	if (argc < 1) {
		fprintf(stderr, "Usage: %s [private key URL]\n", argv[0]);
		return ret;
	}

	/* Load pkcs11prov and default providers */
        if (!providers_load()) {
		display_openssl_errors();
		return ret;
        }

	/* Load private key */
	private_key = load_pkey(argv[1], NULL);
	if (!private_key) {
		fprintf(stderr, "Cannot load private key: %s\n", argv[1]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");

	private_key_dup = EVP_PKEY_dup(private_key);
	if (!private_key_dup) {
		fprintf(stderr, "Cannot duplicate private key\n");
		display_openssl_errors();
		goto cleanup;
	}	
	printf("Duplicate private key created.\n");

	EVP_PKEY_free(private_key_dup);
	EVP_PKEY_free(private_key);

	/* Do it one more time */
	private_key = load_pkey(argv[1], NULL);
	if (!private_key) {
		fprintf(stderr, "Cannot load private key: %s\n", argv[1]);
		display_openssl_errors();
		goto cleanup;
	}
	printf("Private key found.\n");
	ret = EXIT_SUCCESS;

cleanup:
	EVP_PKEY_free(private_key);
	providers_cleanup();
	printf("\n");
	return ret;
}

#else

int main() {
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
