/* libp11 example code: rawrsasign.c
 *
 * This example simply connects to your smart card
 * and demonstrate how to do a raw RSA signing operation with it.
 *
 * WARNING: Raw RSA signing *is insecure* and should not be
 * done without proper padding done elsewhere.
 * So far, PKCS11_private_encrypt() can only manage PKCS1 padding
 * and using it with no padding is usefull when padding is
 * to be done by the software.
 * This allows to use other padding schemes (like RSA-PSS)
 * with smart cards, without requiring padding to be done by
 * the smart card itself.
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 100
#define MAX_SIGSIZE 256 /* Should be adapted to the used RSA key size */

#define END(x) do { ret = (x); goto end; } while (0)

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot = NULL;
	PKCS11_CERT *certs = NULL;

	PKCS11_KEY *authkey = NULL;
	PKCS11_CERT *authcert = NULL;
	EVP_PKEY *pubkey = NULL;
	EVP_MD_CTX mctx;
	EVP_PKEY_CTX *pkeyctx = NULL;

	unsigned char *random = NULL, *signature = NULL;

	char password[20];
	int rc = 0, fd;
	unsigned int nslots, ncerts, siglen;

	static unsigned char hash[EVP_MAX_MD_SIZE];
	static unsigned char enc[MAX_SIGSIZE];
	static unsigned char pad[MAX_SIGSIZE];
	unsigned int plen = MAX_SIGSIZE;
	unsigned int elen = 0;
	unsigned int hlen = 0;
	unsigned char* p;

	X509_SIG sig;
	ASN1_TYPE parameter;
	X509_ALGOR algorithm;
	ASN1_OCTET_STRING digest;

	int ret;

	if (argc < 2) {
		fprintf(stderr, "usage: auth /usr/lib/opensc-pkcs11.so [PIN]\n");
		END(1);
	}

	ctx = PKCS11_CTX_new();

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		END(1);
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		END(1);
	}

	/* get first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	if (slot == NULL || slot->token == NULL) {
		fprintf(stderr, "no token available\n");
		END(1);
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
		struct termios old, new;

		/* Turn echoing off and fail if we can't. */
		if (tcgetattr(0, &old) != 0)
			END(1);

		new = old;
		new.c_lflag &= ~ECHO;
		if (tcsetattr(0, TCSAFLUSH, &new) != 0)
			END(1);

		/* Read the password. */
		printf("Password for token %.32s: ", slot->token->label);
		if (fgets(password, sizeof(password), stdin) == NULL)
			END(1);

		/* Restore terminal. */
		(void)tcsetattr(0, TCSAFLUSH, &old);

		/* strip tailing \n from password */
		rc = strlen(password);
		if (rc <= 0)
			END(1);
		password[rc-1]=0;
	}

loggedin:
	/* perform pkcs #11 login */
	rc = PKCS11_login(slot, 0, password);
	memset(password, 0, strlen(password));
	if (rc != 0) {
		fprintf(stderr, "PKCS11_login failed\n");
		END(1);
	}

	/* get all certs */
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rc) {
		fprintf(stderr, "PKCS11_enumerate_certs failed\n");
		END(1);
	}
	if (ncerts <= 0) {
		fprintf(stderr, "no certificates found\n");
		END(1);
	}

	/* use the first cert */
	authcert=&certs[0];

	/* get random bytes */
	random = OPENSSL_malloc(RANDOM_SIZE);
	if (random == NULL)
		END(1);

	fd = open(RANDOM_SOURCE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "fatal: cannot open RANDOM_SOURCE: %s\n",
				strerror(errno));
		END(1);
	}

	rc = read(fd, random, RANDOM_SIZE);
	if (rc < 0) {
		fprintf(stderr, "fatal: read from random source failed: %s\n",
				strerror(errno));
		close(fd);
		END(1);
	}

	if (rc < RANDOM_SIZE) {
		fprintf(stderr, "fatal: read returned less than %d<%d bytes\n",
				rc, RANDOM_SIZE);
		close(fd);
		END(1);
	}

	close(fd);

	authkey = PKCS11_find_key(authcert);
	if (authkey == NULL) {
		fprintf(stderr, "no key matching certificate available\n");
		END(1);
	}

	/* Compute the SHA1 hash of the random bytes */
	EVP_MD_CTX_init(&mctx);
	if (EVP_DigestInit(&mctx, EVP_sha1()) != 1) {
		fprintf(stderr, "fatal: EVP_DigestInit failed\n");
		END(1);
	}
	if (EVP_DigestUpdate(&mctx, random, RANDOM_SIZE) != 1) {
		fprintf(stderr, "fatal: EVP_DigestUpdate failed\n");
		END(1);
	}
	if (EVP_DigestFinal(&mctx, hash, &hlen) != 1) {
		fprintf(stderr, "fatal: EVP_DigestFinal failed\n");
		END(1);
	}

	/* Compute a PKCS #1 "block type 01" encryption-block */
	sig.algor = &algorithm;
	algorithm.algorithm = OBJ_nid2obj(NID_sha1);
	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	algorithm.parameter = &parameter;
	sig.digest = &digest;
	sig.digest->data = hash;
	sig.digest->length = hlen;
	p = enc;
	elen = i2d_X509_SIG(&sig, &p);
	p = enc;

	/* Compute PKCS #1 v1.5 padding */
	if (RSA_padding_add_PKCS1_type_1(pad, plen, p, elen) != 1) {
		fprintf(stderr, "fatal: RSA_padding_add_PKCS1_type_1 failed\n");
		END(1);
	}

	siglen = MAX_SIGSIZE;
	signature = OPENSSL_malloc(MAX_SIGSIZE);
	if (signature == NULL)
		END(1);

	/* Do a raw RSA sign operation with the smart card */
	rc = PKCS11_private_encrypt(plen, pad, signature, authkey, RSA_NO_PADDING);
	if (rc  < 0) {
		fprintf(stderr, "PKCS11_private_encrypt failed\n");
		END(1);
	}

	/* Verify the signature */
	/* As we have done a PKCS#1 complient padding, we can verify the signature
	 * with "standard code", using openssl EVP interface.
	 */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		fprintf(stderr, "could not extract public key\n");
		END(1);
	}

	EVP_MD_CTX_init(&mctx);
	if (EVP_DigestVerifyInit(&mctx, &pkeyctx, EVP_sha1(), NULL, pubkey) != 1) {
		fprintf(stderr, "fatal: EVP_DigestVerifyInit failed\n");
		END(1);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(pkeyctx, RSA_PKCS1_PADDING) <= 0) {
		fprintf(stderr, "fatal: EVP_PKEY_CTX_set_rsa_padding failed\n");
		END(1);
	}

	if (EVP_DigestVerifyUpdate(&mctx, (const void*)random, RANDOM_SIZE) <= 0) {
		fprintf(stderr, "fatal: EVP_DigestVerifyUpdate failed\n");
		END(1);
	}
	if ((rc = EVP_DigestVerifyFinal(&mctx, signature, siglen)) != 1) {
		fprintf(stderr, "fatal: EVP_DigestVerifyFinal failed : %d\n", rc);
		END(1);
	}

	printf("raw signing operation and signature verification successfull.\n");
	ret = 0;

end:
	if (ret != 0) {
		ERR_print_errors_fp(stderr);
		printf("raw signing operation failed.\n");
	}

	if (pubkey != NULL)
		EVP_PKEY_free(pubkey);
	if (random != NULL)
		OPENSSL_free(random);
	if (signature != NULL)
		OPENSSL_free(signature);

	if (slots != NULL)
		PKCS11_release_all_slots(ctx, slots, nslots);

	if ( ctx != NULL ) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	return ret;
}

/* vim: set noexpandtab: */
