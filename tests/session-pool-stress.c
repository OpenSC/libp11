/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809L
#include "config.h"
#include <libp11.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>

#define SIGN_SUCCESSES 40
#define SIGN_ATTEMPTS 400
#define MODE_CHANGES 40
#define KEYGEN_ATTEMPTS 40

struct stress_state {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	PKCS11_SLOT *slot;
	const char *pin;
	int start;
	int sign_successes;
	int keygen_success;
	int mode_success;
};

static void wait_for_start(struct stress_state *state)
{
	pthread_mutex_lock(&state->lock);
	while (!state->start)
		pthread_cond_wait(&state->cond, &state->lock);
	pthread_mutex_unlock(&state->lock);
}

static void retry_login(struct stress_state *state)
{
	(void)PKCS11_login(state->slot, 0, state->pin);
	ERR_clear_error();
}

static void *sign_thread(void *arg)
{
	struct stress_state *state = arg;
	PKCS11_KEY *keys, *key;
	unsigned char digest[32] = {0};
	unsigned char signature[512];
	unsigned int signature_len, nkeys, i;
	int attempts;

	wait_for_start(state);
	for (attempts = 0; attempts < SIGN_ATTEMPTS &&
			state->sign_successes < SIGN_SUCCESSES; attempts++) {
		key = NULL;
		if (PKCS11_enumerate_keys(state->slot->token,
				&keys, &nkeys) == 0) {
			for (i = nkeys; i > 0; i--) {
				if (keys[i - 1].label &&
						strcmp(keys[i - 1].label,
							"stress-signing-key") == 0) {
					key = &keys[i - 1];
					break;
				}
			}
		}
		signature_len = sizeof(signature);
		if (key && PKCS11_sign(NID_sha256, digest, sizeof(digest),
				signature, &signature_len, key) == 1) {
			state->sign_successes++;
		} else {
			retry_login(state);
		}
	}
	if (state->sign_successes != SIGN_SUCCESSES)
		ERR_print_errors_fp(stderr);
	return NULL;
}

static void *keygen_thread(void *arg)
{
	struct stress_state *state = arg;
	unsigned char id[] = {0x66, 0x65, 0x05};
	int attempts;

	wait_for_start(state);
	for (attempts = 0; attempts < KEYGEN_ATTEMPTS; attempts++) {
		if (PKCS11_generate_key(state->slot->token, EVP_PKEY_RSA, 1024,
				"session-pool-stress-key", id, sizeof(id)) == 0) {
			state->keygen_success = 1;
			break;
		}
		retry_login(state);
	}
	return NULL;
}

static void *mode_thread(void *arg)
{
	struct stress_state *state = arg;
	struct timespec delay = {0, 2000000L};
	int i;

	wait_for_start(state);
	for (i = 0; i < MODE_CHANGES; i++) {
		if (PKCS11_open_session(state->slot, i & 1) != 0)
			break;
		retry_login(state);
		nanosleep(&delay, NULL);
	}
	if (i == MODE_CHANGES)
		state->mode_success = 1;
	return NULL;
}

static PKCS11_SLOT *find_token(PKCS11_CTX *ctx, PKCS11_SLOT *slots,
		unsigned int nslots, const char *label)
{
	PKCS11_SLOT *slot;

	for (slot = PKCS11_find_token(ctx, slots, nslots); slot;
			slot = PKCS11_find_next_token(ctx, slots, nslots, slot)) {
		if (slot->token && slot->token->label &&
				strcmp(slot->token->label, label) == 0)
			return slot;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct stress_state state;
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	PKCS11_KEY *keys = NULL;
	pthread_t sign_id, keygen_id, mode_id;
	unsigned char initial_digest[32] = {0};
	unsigned char initial_signature[512];
	unsigned int initial_signature_len = sizeof(initial_signature);
	unsigned int nslots = 0, nkeys = 0, i;
	int sign_created = 0, keygen_created = 0, mode_created = 0;
	int result = EXIT_FAILURE;

	if (argc != 4) {
		fprintf(stderr, "usage: %s module token-label pin\n", argv[0]);
		return EXIT_FAILURE;
	}

	ctx = PKCS11_CTX_new();
	if (!ctx || PKCS11_CTX_load(ctx, argv[1]) != 0 ||
			PKCS11_enumerate_slots(ctx, &slots, &nslots) != 0) {
		fprintf(stderr, "could not initialize the PKCS#11 context\n");
		goto out;
	}
	slot = find_token(ctx, slots, nslots, argv[2]);
	if (!slot || PKCS11_open_session(slot, 0) != 0 ||
			PKCS11_login(slot, 0, argv[3]) != 0 ||
			PKCS11_enumerate_keys(slot->token, &keys, &nkeys) != 0) {
		fprintf(stderr, "could not initialize the test token\n");
		goto out;
	}
	for (i = 0; i < nkeys; i++) {
		if (PKCS11_get_key_type(&keys[i]) == EVP_PKEY_RSA)
			break;
	}
	if (i == nkeys) {
		fprintf(stderr, "no RSA private key available\n");
		goto out;
	}
	if (PKCS11_sign(NID_sha256, initial_digest, sizeof(initial_digest),
			initial_signature, &initial_signature_len, &keys[i]) != 1) {
		fprintf(stderr, "initial RSA signing operation failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	memset(&state, 0, sizeof(state));
	state.slot = slot;
	state.pin = argv[3];
	pthread_mutex_init(&state.lock, NULL);
	pthread_cond_init(&state.cond, NULL);
	if (pthread_create(&sign_id, NULL, sign_thread, &state) != 0)
		goto threads_out;
	sign_created = 1;
	if (pthread_create(&keygen_id, NULL, keygen_thread, &state) != 0)
		goto threads_out;
	keygen_created = 1;
	if (pthread_create(&mode_id, NULL, mode_thread, &state) != 0)
		goto threads_out;
	mode_created = 1;

	pthread_mutex_lock(&state.lock);
	state.start = 1;
	pthread_cond_broadcast(&state.cond);
	pthread_mutex_unlock(&state.lock);
	pthread_join(sign_id, NULL);
	sign_created = 0;
	pthread_join(keygen_id, NULL);
	keygen_created = 0;
	pthread_join(mode_id, NULL);
	mode_created = 0;
	if (state.sign_successes == SIGN_SUCCESSES &&
			state.keygen_success && state.mode_success) {
		printf("session-pool stress test passed\n");
		result = EXIT_SUCCESS;
	} else {
		fprintf(stderr,
			"stress test incomplete: signs=%d keygen=%d modes=%d\n",
			state.sign_successes, state.keygen_success,
			state.mode_success);
	}

threads_out:
	if (sign_created || keygen_created || mode_created) {
		pthread_mutex_lock(&state.lock);
		state.start = 1;
		pthread_cond_broadcast(&state.cond);
		pthread_mutex_unlock(&state.lock);
	}
	if (sign_created)
		pthread_join(sign_id, NULL);
	if (keygen_created)
		pthread_join(keygen_id, NULL);
	if (mode_created)
		pthread_join(mode_id, NULL);
	pthread_cond_destroy(&state.cond);
	pthread_mutex_destroy(&state.lock);
out:
	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}
	return result;
}

#else /* HAVE_PTHREAD */

int main(void)
{
	fprintf(stderr, "Skipped: pthread support not available\n");
	return 77;
}

#endif /* HAVE_PTHREAD */

/* vim: set noexpandtab: */
