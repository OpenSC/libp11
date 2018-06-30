/* libp11 example code: listkeys.c
 *
 * This examply simply connects to your smart card
 * and list the keys.
 *
 * Feel free to copy all of the code as needed.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <libp11.h>
#include <unistd.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 256

static void list_keys(const char *title,
	const PKCS11_KEY *keys, const unsigned int nkeys);
static void error_queue(const char *name);

#define CHECK_ERR(cond, txt, code) \
	do { \
		if (cond) { \
			fprintf(stderr, "%s\n", (txt)); \
			rc=(code); \
			goto end; \
		} \
	} while (0)

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx=NULL;
	PKCS11_SLOT *slots=NULL, *slot;
	PKCS11_KEY *keys;
	unsigned int nslots, nkeys;
	int rc = 0;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so [PIN]\n",
			argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading pkcs11 engine failed", 1);

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 2);

	/* get first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	CHECK_ERR(!slot || !slot->token, "no token available", 3);

	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token manufacturer: %s\n", slot->token->manufacturer);
	printf("Slot token model.......: %s\n", slot->token->model);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	/* get public keys */
	rc = PKCS11_enumerate_public_keys(slot->token, &keys, &nkeys);
	error_queue("PKCS11_enumerate_public_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_public_keys failed", 4);
	CHECK_ERR(nkeys == 0, "No public keys found", 5);
	list_keys("Public keys", keys, nkeys);

	if (slot->token->loginRequired && argc > 2) {
		/* perform pkcs #11 login */
		rc = PKCS11_login(slot, 0, argv[2]);
		error_queue("PKCS11_login");
		CHECK_ERR(rc < 0, "PKCS11_login failed", 6);
	}

	/* get private keys */
	rc = PKCS11_enumerate_keys(slot->token, &keys, &nkeys);
	error_queue("PKCS11_enumerate_keys");
	CHECK_ERR(rc < 0, "PKCS11_enumerate_keys failed", 7);
	CHECK_ERR(nkeys == 0, "No private keys found", 8);
	list_keys("Private keys", keys, nkeys);

end:
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");
	return rc;
}

static void list_keys(const char *title, const PKCS11_KEY *keys,
		const unsigned int nkeys) {
	unsigned int i;

	printf("\n%s:\n", title);
	for (i = 0; i < nkeys; i++)
		printf(" * %s key: %s\n",
			keys[i].isPrivate ? "Private" : "Public", keys[i].label);
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

/* vim: set noexpandtab: */
