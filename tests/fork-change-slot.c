/*
 * Copyright (C) 2020 Anderson Toshiyuki Sasaki
 * Copyright (c) 2020 Red Hat, Inc.
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

/* libp11 test code: fork-change-slot.c
 *
 * This program loads a key pair using the engine pkcs11, forks to create
 * a new process, and waits for a SIGUSR1 signal before trying to sign/verify
 * random data in both parent and child processes.
 *
 * The intention of the signal waiting is to allow the user to add/remove
 * devices before continuing to the signature/verifying test.
 *
 * Adding or removing devices can lead to a change in the list of slot IDs
 * obtained from the PKCS#11 module. If the engine does not handle the
 * slot ID referenced by the previously loaded key properly, then the key in
 * the child process can reference to the wrong slot ID after forking.
 * This would lead to an error, since the engine will try to sign the data
 * using the key in the wrong slot.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

/* this code extensively uses deprecated features, so warnings are useless */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define RANDOM_SIZE 20
#define MAX_SIGSIZE 1024

static int do_wait(pid_t pids[], int num)
{
    int i;
    int status = 0;

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
        }
        else {
            perror("waitpid");
        }
    }

    return 0;
}

static int spawn_processes(int num)
{
    int i;
    int chld_ret = 0;
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

static void usage(char *arg)
{
    printf("usage: %s (Key PKCS#11 URL) [opt: PKCS#11 module path]\n",
            arg);
}

int main(int argc, char *argv[])
{
    const EVP_MD *digest_algo = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    ENGINE *engine = NULL;
    unsigned char random[RANDOM_SIZE], signature[MAX_SIGSIZE];
    unsigned int siglen = MAX_SIGSIZE;

    int ret, num_processes = 2;
    pid_t pid;

    int rv = 1;

    /* Check arguments */
    if (argc < 2) {
        fprintf(stderr, "Missing required arguments\n");
        usage(argv[0]);
        goto failed;
    }

    if (argc > 4) {
        fprintf(stderr, "Too many arguments\n");
        usage(argv[0]);
        goto failed;
    }

    /* Check PKCS#11 URL */
    if (strncmp(argv[1], "pkcs11:", 7)) {
        fprintf(stderr, "fatal: invalid PKCS#11 URL\n");
        usage(argv[0]);
        goto failed;
    }

    pid = getpid();
    printf("pid %d is the parent\n", pid);

    /* Load configuration file, if provided */
    if (argc >= 3) {
        ret = CONF_modules_load_file(argv[2], "engines", 0);
        if (ret <= 0) {
            fprintf(stderr, "cannot load %s\n", argv[2]);
            error_queue("CONF_modules_load_file", pid);
            goto failed;
        }
        ENGINE_add_conf_module();
    }

    ENGINE_add_conf_module();
#if OPENSSL_VERSION_NUMBER>=0x10100000
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
		| OPENSSL_INIT_ADD_ALL_DIGESTS \
		| OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
    ERR_clear_error();
    ENGINE_load_builtin_engines();

    /* Get structural reference */
    engine = ENGINE_by_id("pkcs11");
    if (engine == NULL) {
        fprintf(stderr, "fatal: engine \"pkcs11\" not available\n");
        error_queue("ENGINE_by_id", pid);
        goto failed;
    }

    /* Set the used  */
    if (argc >= 4) {
        ENGINE_ctrl_cmd(engine, "MODULE_PATH", 0, argv[3], NULL, 1);
    }

    /* Initialize to get the engine functional reference */
    if (!ENGINE_init(engine)) {
        printf("Could not initialize engine\n");
        error_queue("ENGINE_init", pid);
        goto failed;
    }
    /*
     * ENGINE_init() returned a functional reference, so free the structural
     * reference from ENGINE_by_id().
     */
    ENGINE_free(engine);

    pkey = ENGINE_load_private_key(engine, argv[1], 0, 0);
    if (pkey == NULL) {
        error_queue("ENGINE_load_private_key", pid);
        goto failed;
    }

    /* Spawn processes and check child return */
    if (spawn_processes(num_processes)) {
        goto failed;
    }
    pid = getpid();

    /* Generate random data */
    if (!RAND_bytes(random, RANDOM_SIZE)){
        error_queue("RAND_bytes", pid);
        goto failed;
    }

    /* Create context to sign the random data */
    digest_algo = EVP_get_digestbyname("sha256");
    md_ctx = EVP_MD_CTX_create();
    if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
        error_queue("EVP_DigestInit", pid);
        goto failed;
    }

    EVP_SignInit(md_ctx, digest_algo);
    if (EVP_SignUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
        error_queue("EVP_SignUpdate", pid);
        goto failed;
    }

    if (EVP_SignFinal(md_ctx, signature, &siglen, pkey) <= 0) {
        error_queue("EVP_SignFinal", pid);
        goto failed;
    }
    EVP_MD_CTX_destroy(md_ctx);

    printf("pid %d: %u-byte signature created\n", pid, siglen);

    /* Now verify the result */
    md_ctx = EVP_MD_CTX_create();
    if (EVP_DigestInit(md_ctx, digest_algo) <= 0) {
        error_queue("EVP_DigestInit", pid);
        goto failed;
    }

    EVP_VerifyInit(md_ctx, digest_algo);
    if (EVP_VerifyUpdate(md_ctx, random, RANDOM_SIZE) <= 0) {
        error_queue("EVP_VerifyUpdate", pid);
        goto failed;
    }

    if (EVP_VerifyFinal(md_ctx, signature, siglen, pkey) <= 0) {
        error_queue("EVP_VerifyFinal", pid);
        goto failed;
    }
    printf("pid %d: Signature matched\n", pid);

    rv = 0;

failed:
    if (md_ctx != NULL)
        EVP_MD_CTX_destroy(md_ctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    /* Free the functional reference from ENGINE_init */
    ENGINE_finish(engine);

    return rv;
}
