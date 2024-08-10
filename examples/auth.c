/*
 * Copyright © 2020, Andreas Jellinghaus <andreas@ionisiert.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* libp11 example code: auth.c
 *
 * This examply simply connects to your smart card
 * and does a public key authentication.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if !defined(_WIN32) || defined(__CYGWIN__)
#include <termios.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/* this code extensively uses deprecated features, so warnings are useless */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <libp11.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 256

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots, *slot;
	PKCS11_CERT *certs;

	PKCS11_KEY *authkey;
	PKCS11_CERT *authcert;
	EVP_PKEY *pubkey = NULL;

	unsigned char *random = NULL, *signature = NULL;

	char password[20];
	int rc, fd, logged_in;
	unsigned int nslots, ncerts, siglen;

	if (argc < 2) {
		fprintf(stderr, "usage: auth /usr/lib/opensc-pkcs11.so [PIN]\n");
		return 1;
	}

	ctx = PKCS11_CTX_new();

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		rc = 1;
		goto nolib;
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		rc = 2;
		goto noslots;
	}

	/* get first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	if (slot == NULL || slot->token == NULL) {
		fprintf(stderr, "no token available\n");
		rc = 3;
		goto notoken;
	}
	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token manufacturer: %s\n", slot->token->manufacturer);
	printf("Slot token model.......: %s\n", slot->token->model);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	if (!slot->token->loginRequired)
		goto loggedin;

	/* get password */
	if (argc > 2) {
		strncpy(password, argv[2], sizeof password);
		password[(sizeof password) - 1] = '\0';
	} else {
#if !defined(_WIN32) || defined(__CYGWIN__)
		struct termios old, new;

		/* Turn echoing off and fail if we can't. */
		if (tcgetattr(0, &old) != 0) {
			rc = 4;
			goto failed;
		}

		new = old;
		new.c_lflag &= ~ECHO;
		if (tcsetattr(0, TCSAFLUSH, &new) != 0) {
			rc = 5;
			goto failed;
		}
#endif
		/* Read the password. */
		printf("Password for token %.32s: ", slot->token->label);
		if (fgets(password, sizeof(password), stdin) == NULL) {
			rc = 6;
			goto failed;
		}
#if !defined(_WIN32) || defined(__CYGWIN__)
		/* Restore terminal. */
		(void)tcsetattr(0, TCSAFLUSH, &old);
#endif
		/* strip tailing \n from password */
		rc = strlen(password);
		if (rc <= 0) {
			rc = 7;
			goto failed;
		}
		password[rc-1]=0;
	}

 loggedin:
	/* check if user is logged in */
	rc = PKCS11_is_logged_in(slot, 0, &logged_in);
	if (rc != 0) {
		fprintf(stderr, "PKCS11_is_logged_in failed\n");
		rc = 8;
		goto failed;
	}
	if (logged_in) {
		fprintf(stderr, "PKCS11_is_logged_in says user is logged in, expected to be not logged in\n");
		rc = 9;
		goto failed;
	}

	/* perform pkcs #11 login */
	rc = PKCS11_login(slot, 0, password);
	memset(password, 0, strlen(password));
	if (rc != 0) {
		fprintf(stderr, "PKCS11_login failed\n");
		rc = 10;
		goto failed;
	}

	/* check if user is logged in */
	rc = PKCS11_is_logged_in(slot, 0, &logged_in);
	if (rc != 0) {
		fprintf(stderr, "PKCS11_is_logged_in failed\n");
		rc = 11;
		goto failed;
	}
	if (!logged_in) {
		fprintf(stderr, "PKCS11_is_logged_in says user is not logged in, expected to be logged in\n");
		rc = 12;
		goto failed;
	}

	/* get all certs */
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rc) {
		fprintf(stderr, "PKCS11_enumerate_certs failed\n");
		rc = 13;
		goto failed;
	}
	if (ncerts <= 0) {
		fprintf(stderr, "no certificates found\n");
		rc = 14;
		goto failed;
	}

	/* use the first cert */
	authcert=&certs[0];

	/* get random bytes */
	random = OPENSSL_malloc(RANDOM_SIZE);
	if (random == NULL) {
		rc = 15;
		goto failed;
	}

	fd = open(RANDOM_SOURCE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "fatal: cannot open RANDOM_SOURCE: %s\n",
				strerror(errno));
		rc = 16;
		goto failed;
	}

	rc = read(fd, random, RANDOM_SIZE);
	if (rc < 0) {
		fprintf(stderr, "fatal: read from random source failed: %s\n",
			strerror(errno));
		close(fd);
		rc = 17;
		goto failed;
	}

	if (rc < RANDOM_SIZE) {
		fprintf(stderr, "fatal: read returned less than %d<%d bytes\n",
			rc, RANDOM_SIZE);
		close(fd);
		rc = 18;
		goto failed;
	}

	close(fd);

	authkey = PKCS11_find_key(authcert);
	if (authkey == NULL) {
		fprintf(stderr, "no key matching certificate available\n");
		rc = 19;
		goto failed;
	}

	/* ask for a sha1 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	signature = OPENSSL_malloc(MAX_SIGSIZE);
	if (signature == NULL) {
		rc = 20;
		goto failed;
	}

	rc = PKCS11_sign(NID_sha1, random, RANDOM_SIZE,
		signature, &siglen, authkey);
	if (rc != 1) {
		fprintf(stderr, "fatal: pkcs11_sign failed\n");
		rc = 21;
		goto failed;
	}

	/* verify the signature */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		fprintf(stderr, "could not extract public key\n");
		rc = 22;
		goto failed;
	}

	/* now verify the result */
	rc = RSA_verify(NID_sha1, random, RANDOM_SIZE,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L || ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3050000fL )
			signature, siglen, (RSA *)EVP_PKEY_get0_RSA(pubkey));
#else
			signature, siglen, (RSA *)pubkey->pkey.rsa);
#endif
	if (rc != 1) {
		fprintf(stderr, "fatal: RSA_verify failed\n");
		rc = 23;
		goto failed;
	}

	rc = 0;

failed:
	if (rc)
		ERR_print_errors_fp(stderr);
	if (random != NULL)
		OPENSSL_free(random);
	if (pubkey != NULL)
		EVP_PKEY_free(pubkey);
	if (signature != NULL)
		OPENSSL_free(signature);

notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

noslots:
	PKCS11_CTX_unload(ctx);

nolib:
	PKCS11_CTX_free(ctx);

	if (rc)
		printf("authentication failed.\n");
	else
		printf("authentication successful.\n");
	return rc;
}

/* vim: set noexpandtab: */
