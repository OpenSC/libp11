/* libp11 example code: auth.c
 *
 * This examply simply connects to your smart card
 * and does a public key authentication.
 *
 * Feel free to copy all of the code as needed.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
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
	int rc = 0, fd;
	unsigned int nslots, ncerts, siglen;

	if (argc != 2) {
		fprintf(stderr, "usage: auth /usr/lib/opensc-pkcs11.so\n");
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
	if (!slot || !slot->token) {
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

	/* get all certs */
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rc) {
		fprintf(stderr, "PKCS11_enumerate_certs failed\n");
		goto failed;
	}
	if (ncerts <= 0) {
		fprintf(stderr, "no certificates found\n");
		goto failed;
	}

	/* use the first cert */
	authcert=&certs[0];

	if (!slot->token->loginRequired)
		goto loggedin;

	/* get password */
	struct termios old, new;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr(0, &old) != 0)
		goto failed;

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(0, TCSAFLUSH, &new) != 0)
		goto failed;

	/* Read the password. */
	printf("Password for token %.32s: ", slot->token->label);
	fgets(password, sizeof(password), stdin);

	/* Restore terminal. */
	(void)tcsetattr(0, TCSAFLUSH, &old);

	/* strip tailing \n from password */
	rc = strlen(password);
	if (rc <= 0)
		goto failed;
	password[rc-1]=0;

	/* perform pkcs #11 login */
	rc = PKCS11_login(slot, 0, password);
	memset(password, 0, strlen(password));
	if (rc != 0) {
		fprintf(stderr, "PKCS11_login failed\n");
		goto failed;
	}

      loggedin:
	/* get random bytes */
	random = malloc(RANDOM_SIZE);
	if (!random)
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

	authkey = PKCS11_find_key(authcert);
	if (!authkey) {
		fprintf(stderr, "no key matching certificate available\n");
		goto failed;
	}

	/* ask for a sha1 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	signature = malloc(MAX_SIGSIZE);
	if (!signature)
		goto failed;

	rc = PKCS11_sign(NID_sha1, random, RANDOM_SIZE, signature, &siglen,
			 authkey);
	if (rc != 1) {
		fprintf(stderr, "fatal: pkcs11_sign failed\n");
		goto failed;
	}

	/* verify the signature */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		fprintf(stderr, "could not extract public key\n");
		goto failed;
	}

	/* now verify the result */
	rc = RSA_verify(NID_sha1, random, RANDOM_SIZE,
			signature, siglen, pubkey->pkey.rsa);
	if (rc != 1) {
		fprintf(stderr, "fatal: RSA_verify failed\n");
		goto failed;
	}

	if (pubkey != NULL)
		EVP_PKEY_free(pubkey);

	if (random != NULL)
		free(random);
	if (signature != NULL)
		free(signature);

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);

	printf("authentication successfull.\n");
	return 0;


      failed:
	ERR_print_errors_fp(stderr);
      notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

      noslots:
	PKCS11_CTX_unload(ctx);

      nolib:
	PKCS11_CTX_free(ctx);
	

	printf("authentication failed.\n");
	return 1;
}
