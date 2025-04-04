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
 *
 * This program loads a key pair using the pkcs11prov provider, forks to create
 * a new process, and waits for a SIGUSR1 signal before trying to sign/verify
 * random data in both parent and child processes.
 *
 * The intention of the signal waiting is to allow the user to add/remove
 * devices before continuing to the signature/verifying test.
 *
 * Adding or removing devices can lead to a change in the list of slot IDs
 * obtained from the PKCS#11 module. If the pkcs11prov does not handle the
 * slot ID referenced by the previously loaded key properly, then the key in
 * the child process can reference to the wrong slot ID after forking.
 * This would lead to an error, since the pkcs11prov will try to sign the data
 * using the key in the wrong slot.
 */

#include "helpers_prov.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/rand.h>

#define RANDOM_SIZE 20
#define MAX_SIGSIZE 1024

static int do_wait(pid_t pids[], int num)
{
	int i, status = 0;

	for (i = 0; i < num; i++) {
		waitpid(pids[i], &status, 0);
		if (WIFEXITED(status)) {
			printf("child %d exited with status %d\n", pids[i], WEXITSTATUS(status));
			return (WEXITSTATUS(status));
		}
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "Child %d terminated by signal #%d\n", pids[i],
				WTERMSIG(status));
			return (WTERMSIG(status));
		} else {
			perror("waitpid");
		}
	}
	return 0;
}

static int spawn_processes(int num)
{
	int i, chld_ret = 0;
	pid_t *pids;
	pid_t pid;
	sigset_t set, oldset;
	int signal;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);

	/* If only 1 process was requested, no more processes are required */
	if (num <= 1) {
		return 0;
	}

	pids = (pid_t *)malloc(num * sizeof(pid_t));
	if (pids == NULL) {
		exit(12);
	}

	/* Spawn (num - 1) new processes to get a total of num processes */
	for (i = 0; i < (num - 1); i++) {
		pid = fork();
		switch (pid) {
			case -1: /* failed */
				perror("fork");
				do_wait(pids, i);
				free(pids);
				exit(5);
			case 0: /* child */
				printf("Remove or add a device to try to cause an error\n");
				printf("Waiting for signal SIGUSR1\n");
				sigprocmask(SIG_BLOCK, &set, &oldset);
				sigwait(&set, &signal);
				sigprocmask(SIG_SETMASK, &oldset, NULL);
				free(pids);
				return 0;
			default: /* parent */
				pids[i] = pid;
				printf("spawned %d\n", pid);
		}
	}

	/* Wait for the created processes */
	chld_ret = do_wait(pids, (num - 1));
	free(pids);

	return chld_ret;
}

static void error_queue(const char *name, int pid)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "pid %d: %s generated errors:\n", pid, name);
		ERR_print_errors_fp(stderr);
	}
}

int main(int argc, char *argv[])
{
	const EVP_MD *digest_algo = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char random[RANDOM_SIZE], signature[MAX_SIGSIZE];
	unsigned int siglen = MAX_SIGSIZE;
	pid_t pid;
	int num_processes = 2;
	int ret = EXIT_FAILURE;

	if (argc < 1) {
		fprintf(stderr, "Usage: %s [private key URL]\n", argv[0]);
		return ret;
	}

	pid = getpid();
	printf("pid %d is the parent\n", pid);

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

	/* Spawn processes and check child return */
	if (spawn_processes(num_processes)) {
		goto cleanup;
	}
	pid = getpid();

	/* Generate random data */
	if (!RAND_bytes(random, RANDOM_SIZE)){
		error_queue("RAND_bytes", pid);
		goto cleanup;
	}

	/* Create context to sign the random data */
	digest_algo = EVP_get_digestbyname("sha256");
	md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
		error_queue("EVP_DigestInit", pid);
		goto cleanup;
	}
	EVP_SignInit(md_ctx, digest_algo);
	if (EVP_SignUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
		error_queue("EVP_SignUpdate", pid);
		goto cleanup;
	}
	if (EVP_SignFinal(md_ctx, signature, &siglen, private_key) <= 0) {
		error_queue("EVP_SignFinal", pid);
		goto cleanup;
	}
	EVP_MD_CTX_destroy(md_ctx);

	printf("pid %d: %u-byte signature created\n", pid, siglen);

	/* Now verify the result */
	md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
		error_queue("EVP_DigestInit", pid);
		goto cleanup;
	}
	EVP_VerifyInit(md_ctx, digest_algo);
	if (EVP_VerifyUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
		error_queue("EVP_VerifyUpdate", pid);
		goto cleanup;
	}
	if (EVP_VerifyFinal(md_ctx, signature, siglen, private_key) <= 0) {
		error_queue("EVP_VerifyFinal", pid);
		goto cleanup;
	}
	printf("pid %d: Signature matched\n", pid);
	ret = EXIT_SUCCESS;

cleanup:
	if (md_ctx != NULL)
		EVP_MD_CTX_destroy(md_ctx);
	if (private_key != NULL)
		EVP_PKEY_free(private_key);

	return ret;
}

#else

int main() {
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* vim: set noexpandtab: */
