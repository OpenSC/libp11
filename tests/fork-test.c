/*
 * Copyright © 2020, Nikos Mavrogiannopoulos <nmav@redhat.com>
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
 * This examply simply connects to your smart card / SoftHSM  token
 * and does a public key authentication.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libp11.h>
#include <unistd.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 1024

static void do_fork(void);
static void error_queue(const char *name);

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots, *slot;
	PKCS11_CERT *certs;

	PKCS11_KEY *authkey;
	PKCS11_CERT *authcert;
	EVP_PKEY *privkey = NULL, *pubkey = NULL;
	const EVP_MD *digest_algo = NULL;
	EVP_MD_CTX *md_ctx = NULL;

	unsigned char *random = NULL, *signature = NULL;

	char password[20];
	int rc = 0, fd;
	unsigned int nslots, ncerts, siglen;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so [PIN]\n",
			argv[0]);
		return 1;
	}

	do_fork();
	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load pkcs #11 module */
	do_fork();
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		rc = 1;
		goto nolib;
	}

	/* get information on all slots */
	do_fork();
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		rc = 2;
		goto noslots;
	}

	/* get first slot with a token */
	do_fork();
	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
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
		strcpy(password, argv[2]);
	} else {
		exit(1);
	}

loggedin:
	/* perform pkcs #11 login */
	do_fork();
	rc = PKCS11_login(slot, 0, password);
	error_queue("PKCS11_login");
	memset(password, 0, strlen(password));
	if (rc != 0) {
		fprintf(stderr, "PKCS11_login failed\n");
		goto failed;
	}

	/* get all certs */
	do_fork();
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	error_queue("PKCS11_enumerate_certs");
	if (rc) {
		fprintf(stderr, "PKCS11_enumerate_certs failed\n");
		goto failed;
	}
	if (ncerts == 0) {
		fprintf(stderr, "no certificates found\n");
		goto failed;
	}

	/* use the first cert */
	authcert=&certs[0];

	/* get random bytes */
	random = OPENSSL_malloc(RANDOM_SIZE);
	if (random == NULL)
		goto failed;

	fd = open(RANDOM_SOURCE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "fatal: cannot open RANDOM_SOURCE: %s\n",
				strerror(errno));
		goto failed;
	}

	rc = read(fd, random, RANDOM_SIZE);
	if (rc < 0) {
		fprintf(stderr, "fatal: read from random source failed: %s\n",
			strerror(errno));
		close(fd);
		goto failed;
	}

	if (rc < RANDOM_SIZE) {
		fprintf(stderr, "fatal: read returned less than %d<%d bytes\n",
			rc, RANDOM_SIZE);
		close(fd);
		goto failed;
	}

	close(fd);

	do_fork();
	authkey = PKCS11_find_key(authcert);
	error_queue("PKCS11_find_key");
	if (authkey == NULL) {
		fprintf(stderr, "no key matching certificate available\n");
		goto failed;
	}

	do_fork();
	/* ask for a sha256 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	signature = OPENSSL_malloc(MAX_SIGSIZE);
	if (signature == NULL)
		goto failed;

	digest_algo = EVP_get_digestbyname("sha256");

	privkey = PKCS11_get_private_key(authkey);
	if (privkey == NULL) {
		fprintf(stderr, "Could not extract the private key\n");
		goto failed;
	}

	/* sign on the PKCS#11 device */
	md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
		error_queue("EVP_DigestInit");
		goto failed;
	}

	EVP_SignInit(md_ctx, digest_algo);
	if (EVP_SignUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
		error_queue("EVP_SignUpdate");
		goto failed;
	}

	if (EVP_SignFinal(md_ctx, signature, &siglen, privkey) <= 0) {
		error_queue("EVP_SignFinal");
		goto failed;
	}
	EVP_MD_CTX_destroy(md_ctx);

	printf("%u-byte signature created\n", siglen);

	/* Get the public key for verification */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		fprintf(stderr, "Could not extract the public key\n");
		goto failed;
	}

	/* Now verify the result */
	md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
		error_queue("EVP_DigestInit");
		goto failed;
	}

	EVP_VerifyInit(md_ctx, digest_algo);
	if (EVP_VerifyUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
		error_queue("EVP_VerifyUpdate");
		goto failed;
	}

	if (EVP_VerifyFinal(md_ctx, signature, siglen, pubkey) <= 0) {
		error_queue("EVP_VerifyFinal");
		goto failed;
	}
	EVP_MD_CTX_destroy(md_ctx);

	printf("Signature matched\n");

	/* If key is NULL nothing is done */
	EVP_PKEY_free(privkey);
	EVP_PKEY_free(pubkey);

	OPENSSL_free(random);
	OPENSSL_free(signature);

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	printf("Cleanup complete\n");
	return 0;

failed:

notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

noslots:
	PKCS11_CTX_unload(ctx);

nolib:
	PKCS11_CTX_free(ctx);

	printf("authentication failed.\n");
	return 1;
}

static void do_fork(void)
{
	int status = 0;
	pid_t pid = fork();
	switch (pid) {
	case -1: /* failed */
		perror("fork");
		exit(5);
	case 0: /* child */
		return;
	default: /* parent */
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status))
			fprintf(stderr, "Child terminated by signal #%d\n",
				WTERMSIG(status));
		else
			perror("waitpid");
		exit(2);
	}
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

/* vim: set noexpandtab: */
