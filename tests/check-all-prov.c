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
	OBJ_SET *obj_set;
	int ret = EXIT_FAILURE;

	if (argc < 1) {
		fprintf(stderr, "usage: %s [object URL]\n", argv[0]);
		return ret;
	}

	obj_set = OPENSSL_zalloc(sizeof(OBJ_SET));
	if (!obj_set)
		return ret;

	/* Load pkcs11prov and default providers */
	if (!providers_load()) {
		display_openssl_errors();
		return ret;
	}

	/* Load private key, public key and certificate */
	load_objects(argv[1], NULL, obj_set);

	if (!obj_set->private_key) {
		printf("Cannot load private key: %s\n", argv[1]);
		goto cleanup;
	}
	if (!obj_set->public_key) {
		printf("Cannot load public key: %s\n", argv[1]);
		goto cleanup;
	}
	if (!obj_set->cert) {
		printf("Cannot load certificate: %s\n", argv[1]);
		goto cleanup;
	}
	ret = X509_check_private_key(obj_set->cert, obj_set->private_key);
	if (!ret) {
		printf("Could not check private key.\n");
		display_openssl_errors();
		goto cleanup;
	}
	printf("Key and certificate matched.\n");
	ret = EXIT_SUCCESS;

cleanup:
	EVP_PKEY_free(obj_set->private_key);
	EVP_PKEY_free(obj_set->public_key);
	X509_free(obj_set->cert);
	OPENSSL_free(obj_set);
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
