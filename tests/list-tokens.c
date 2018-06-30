/*
 * Copyright (c) 2018 Frank Morgner <frankmorgner@gmail.com>
 *
 * Feel free to copy all of the code as needed.
 */

#include <libp11.h>

static void error_queue(const char *name);

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots, *slot;
	PKCS11_CERT *certs;

	int rc = 0, token_found = 0;

	unsigned int nslots;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so\n",
			argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		goto nolib;
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		goto noslots;
	}

	/* get slots with a token */
	for (slot = PKCS11_find_token(ctx, slots, nslots);
			slot != NULL;
			slot = PKCS11_find_next_token(ctx, slots, nslots, slot)) {
		if (token_found)
			printf("\n");
		else
			token_found = 1;
		printf("Slot manufacturer......: %s\n", slot->manufacturer);
		printf("Slot description.......: %s\n", slot->description);
		printf("Slot token label.......: %s\n", slot->token->label);
		printf("Slot token manufacturer: %s\n", slot->token->manufacturer);
		printf("Slot token model.......: %s\n", slot->token->model);
		printf("Slot token serialnr....: %s\n", slot->token->serialnr);
	}
	if (!token_found) {
		error_queue("PKCS11_find_token");
		fprintf(stderr, "no token available\n");
		goto notoken;
	}

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	printf("Cleanup complete\n");
	return 0;

notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

noslots:
	PKCS11_CTX_unload(ctx);

nolib:
	PKCS11_CTX_free(ctx);

	printf("listing failed.\n");
	return 1;
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

/* vim: set noexpandtab: */
