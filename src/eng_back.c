/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016 Michał Trojnara
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "engine.h"
#include <stdio.h>
#include <string.h>

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32
#define MAX_VALUE_LEN	200

struct st_engine_ctx {
	/* Engine configuration */
	/*
	 * The PIN used for login. Cache for the get_pin function.
	 * The memory for this PIN is always owned internally,
	 * and may be freed as necessary. Before freeing, the PIN
	 * must be whitened, to prevent security holes.
	 */
	char *pin;
	int pin_length;
	int verbose;
	char *module;
	char *init_args;

	/* Engine initialization mutex */
#if OPENSSL_VERSION_NUMBER >= 0x10100004L
	CRYPTO_RWLOCK *rwlock;
#else
	int rwlock;
#endif

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
};

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

static void dump_hex(FILE *stream, const char *val, const size_t len) {
	size_t n;

	for (n = 0; n < len; n++)
		fprintf(stream, "%02x", val[n]);
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/* Free PIN storage in secure way. */
static void destroy_pin(ENGINE_CTX *ctx)
{
	if (ctx->pin != NULL) {
		OPENSSL_cleanse(ctx->pin, ctx->pin_length);
		OPENSSL_free(ctx->pin);
		ctx->pin = NULL;
		ctx->pin_length = 0;
	}
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int get_pin(ENGINE_CTX *ctx, UI_METHOD *ui_method, void *callback_data)
{
	UI *ui;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (ui == NULL) {
		fprintf(stderr, "UI_new failed\n");
		return 0;
	}
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (ctx->pin == NULL)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	if (!UI_add_input_string(ui, "PKCS#11 token PIN: ",
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH)) {
		fprintf(stderr, "UI_add_input_string failed\n");
		UI_free(ui);
		return 0;
	}
	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

/******************************************************************************/
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *pkcs11_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));

	mod = getenv("PKCS11_MODULE_PATH");
	if (mod) {
		ctx->module = OPENSSL_strdup(mod);
	} else {
#ifdef DEFAULT_PKCS11_MODULE
		ctx->module = OPENSSL_strdup(DEFAULT_PKCS11_MODULE);
#else
		ctx->module = NULL;
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L
	ctx->rwlock = CRYPTO_THREAD_lock_new();
#else
	ctx->rwlock = CRYPTO_get_dynlock_create_callback() ?
		CRYPTO_get_new_dynlockid() : 0;
#endif

	return ctx;
}

/* Destroy the context allocated with pkcs11_new() */
int pkcs11_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		pkcs11_finish(ctx);
		destroy_pin(ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L
		CRYPTO_THREAD_lock_free(ctx->rwlock);
#else
		if (ctx->rwlock)
			CRYPTO_destroy_dynlockid(ctx->rwlock);
#endif
		OPENSSL_free(ctx);
	}
	return 1;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static void pkcs11_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list = NULL;
	unsigned int slot_count = 0;

	if (ctx->verbose)
		fprintf(stderr, "PKCS#11: Initializing the engine\n");

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);

	/* PKCS11_CTX_load() uses C_GetSlotList() via p11-kit */
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		fprintf(stderr, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	/* PKCS11_enumerate_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_enumerate_slots(pkcs11_ctx, &slot_list, &slot_count) < 0) {
		fprintf(stderr, "Failed to enumerate slots\n");
		PKCS11_CTX_unload(pkcs11_ctx);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	if (ctx->verbose)
		fprintf(stderr, "Found %u slot%s\n", slot_count,
			slot_count <= 1 ? "" : "s");

	ctx->pkcs11_ctx = pkcs11_ctx;
	ctx->slot_list = slot_list;
	ctx->slot_count = slot_count;
}

static int pkcs11_init_libp11(ENGINE_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100004L
	CRYPTO_THREAD_write_lock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_lock(ctx->rwlock);
#endif
	if (ctx->pkcs11_ctx == NULL || ctx->slot_list == NULL)
		pkcs11_init_libp11_unlocked(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L
	CRYPTO_THREAD_unlock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_unlock(ctx->rwlock);
#endif
	return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

/* Function called from ENGINE_init() */
int pkcs11_init(ENGINE_CTX *ctx)
{
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList().
	 * OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init().
	 * Double-locking a non-recursive rwlock causes the application to
	 * crash or hang, depending on the locking library implementation. */

	/* Only attempt initialization when dynamic locks are unavailable.
	 * This likely also indicates a single-threaded application,
	 * so temporarily unlocking CRYPTO_LOCK_ENGINE should be safe. */
#if OPENSSL_VERSION_NUMBER < 0x10100004L
	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL) {
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		pkcs11_init_libp11_unlocked(ctx);
		CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
		return ctx->pkcs11_ctx && ctx->slot_list ? 1 : 0;
	}
#endif
	return 1;
}

/* Finish engine operations initialized with pkcs11_init() */
int pkcs11_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		if (ctx->slot_list) {
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
			ctx->slot_list = NULL;
			ctx->slot_count = 0;
		}
		if (ctx->pkcs11_ctx) {
			/* Modules cannot be unloaded in pkcs11_finish() nor
			 * pkcs11_destroy() because of a deadlock in PKCS#11
			 * modules that internally use OpenSSL engines.
			 * A memory leak is better than a deadlock... */
			/* PKCS11_CTX_unload(ctx->pkcs11_ctx); */
			PKCS11_CTX_free(ctx->pkcs11_ctx);
			ctx->pkcs11_ctx = NULL;
		}
	}
	return 1;
}

/******************************************************************************/
/* Certificate handling                                                       */
/******************************************************************************/

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *pkcs11_load_cert(ENGINE_CTX *ctx, const char *s_slot_cert_id)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509;
	unsigned int cert_count, n, m;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	int slot_nr = -1;
	char flags[64];

	if (pkcs11_init_libp11(ctx)) /* Delayed libp11 initialization */
		return NULL;

	if (s_slot_cert_id && *s_slot_cert_id) {
		if (!strncmp(s_slot_cert_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(s_slot_cert_id, &match_tok,
				cert_id, &cert_id_len,
				tmp_pin, &tmp_pin_len, &cert_label);
			if (n && tmp_pin_len > 0 && tmp_pin[0] != 0) {
				destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				return NULL;
			}
		} else {
			n = parse_slot_id_string(s_slot_cert_id, &slot_nr,
				cert_id, &cert_id_len, &cert_label);

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				return NULL;
			}
		}
		if (ctx->verbose) {
			fprintf(stderr, "Looking in slot %d for certificate: ",
				slot_nr);
			if (cert_id_len != 0) {
				fprintf(stderr, "id=");
				dump_hex(stderr, cert_id, cert_id_len);
			}
			if (cert_id_len != 0 && cert_label != NULL)
				fprintf(stderr, " ");
			if (cert_label != NULL)
				fprintf(stderr, "label=%s", cert_label);
			fprintf(stderr, "\n");
		}
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		if (ctx->verbose) {
			fprintf(stderr, "[%lu] %-25.25s  %-16s",
				PKCS11_get_slotid_from_slot(slot),
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		fprintf(stderr, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			fprintf(stderr, "No tokens found\n");
			return NULL;
		}
	} else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Empty token found\n");
		return NULL;
	}

	if (ctx->verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	/* In several tokens certificates are marked as private. We use the pin-value */
	if (tok->loginRequired && ctx->pin) {
		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, ctx->pin)) {
			/* Login failed, so free the PIN if present */
			destroy_pin(ctx);
			fprintf(stderr, "Login failed\n");
			return NULL;
		}
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		fprintf(stderr, "Unable to enumerate certificates\n");
		return NULL;
	}

	if (ctx->verbose) {
		fprintf(stderr, "Found %u cert%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");
	}
	if ((s_slot_cert_id && *s_slot_cert_id) &&
			(cert_id_len != 0 || cert_label != NULL)) {
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_label != NULL && strcmp(k->label, cert_label) == 0)
				selected_cert = k;
			if (cert_id_len != 0 && k->id_len == cert_id_len &&
					memcmp(k->id, cert_id, cert_id_len) == 0)
				selected_cert = k;
		}
	} else {
		selected_cert = certs; /* Use the first certificate */
	}

	if (selected_cert != NULL) {
		x509 = X509_dup(selected_cert->x509);
	} else {
		fprintf(stderr, "Certificate not found.\n");
		x509 = NULL;
	}
	if (cert_label != NULL)
		OPENSSL_free(cert_label);
	return x509;
}

static int ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert != NULL)
		return 0;

	parms->cert = pkcs11_load_cert(ctx, parms->s_slot_cert_id);
	if (parms->cert == NULL)
		return 0;

	return 1;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

/*
 * Log-into the token if necesary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user inteface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int pkcs11_login(ENGINE_CTX *ctx, PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *callback_data)
{
	if (tok->loginRequired) {
		/* If the token has a secure login (i.e., an external keypad),
		 * then use a NULL pin. Otherwise, check if a PIN exists. If
		 * not, allocate and obtain a new PIN. */
		if (tok->secureLogin) {
			/* Free the PIN if it has already been
			 * assigned (i.e, cached by get_pin) */
			destroy_pin(ctx);
		} else if (ctx->pin == NULL) {
			ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
			ctx->pin_length = MAX_PIN_LENGTH;
			if (ctx->pin == NULL) {
				fprintf(stderr, "Could not allocate memory for PIN");
				return 0;
			}
			memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
			if (!get_pin(ctx, ui_method, callback_data)) {
				destroy_pin(ctx);
				fprintf(stderr, "No pin code was entered");
				return 0;
			}
		}

		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, ctx->pin)) {
			/* Login failed, so free the PIN if present */
			destroy_pin(ctx);
			fprintf(stderr, "Login failed\n");
			return 0;
		}
		/* Login successful, PIN retained in case further logins are
		 * required. This will occur on subsequent calls to the
		 * pkcs11_load_key function. Subsequent login calls should be
		 * relatively fast (the token should maintain its own login
		 * state), although there may still be a slight performance
		 * penalty. We could maintain state noting that successful
		 * login has been performed, but this state may not be updated
		 * if the token is removed and reinserted between calls. It
		 * seems safer to retain the PIN and perform a login on each
		 * call to pkcs11_load_key, even if this may not be strictly
		 * necessary. */
		/* TODO confirm that multiple login attempts do not introduce
		 * significant performance penalties */
	}
	return 1;
}

static EVP_PKEY *pkcs11_load_key(ENGINE_CTX *ctx, const char *s_slot_key_id,
		UI_METHOD * ui_method, void *callback_data, int isPrivate)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_KEY *keys, *selected_key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk;
	unsigned int cert_count, key_count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	char flags[64];
	int already_logged_in = 0;

	if (pkcs11_init_libp11(ctx)) /* Delayed libp11 initialization */
		return NULL;

	if (ctx->verbose)
		fprintf(stderr, "Loading %s key \"%s\"\n",
			(char *)(isPrivate ? "private" : "public"),
			s_slot_key_id);
	if (s_slot_key_id && *s_slot_key_id) {
		if (!strncmp(s_slot_key_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(s_slot_key_id, &match_tok,
				key_id, &key_id_len,
				tmp_pin, &tmp_pin_len, &key_label);

			if (n && tmp_pin_len > 0 && tmp_pin[0] != 0) {
				destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				return NULL;
			}
		} else {
			n = parse_slot_id_string(s_slot_key_id, &slot_nr,
				key_id, &key_id_len, &key_label);

			if (!n) {
				fprintf(stderr,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				return NULL;
			}
		}
		if (ctx->verbose) {
			fprintf(stderr, "Looking in slot %d for key: ",
				slot_nr);
			if (key_id_len != 0) {
				fprintf(stderr, "id=");
				dump_hex(stderr, key_id, key_id_len);
			}
			if (key_id_len != 0 && key_label != NULL)
				fprintf(stderr, " ");
			if (key_label != NULL)
				fprintf(stderr, "label=%s", key_label);
			fprintf(stderr, "\n");
		}
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		if (ctx->verbose) {
			fprintf(stderr, "[%lu] %-25.25s  %-16s",
				PKCS11_get_slotid_from_slot(slot),
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		fprintf(stderr, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			fprintf(stderr, "No tokens found\n");
			return NULL;
		}
	} else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Found empty token\n");
		return NULL;
	}
	/* The following check is non-critical to ensure interoperability
	 * with some other (which ones?) PKCS#11 libraries */
	if (!tok->initialized)
		fprintf(stderr, "Found uninitialized token\n");
	if (isPrivate && !tok->userPinSet && !tok->readOnly) {
		fprintf(stderr, "Found slot without user PIN\n");
		return NULL;
	}

	if (ctx->verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		fprintf(stderr, "Unable to enumerate certificates\n");
		return NULL;
	}

	if (ctx->verbose) {
		fprintf(stderr, "Found %u certificate%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *c = certs + n;
			char *dn = NULL;

			fprintf(stderr, "  %2u    id=", n + 1);
			dump_hex(stderr, c->id, c->id_len);
			fprintf(stderr, " label=%s", c->label);
			if (c->x509)
				dn = X509_NAME_oneline(X509_get_subject_name(c->x509), NULL, 0);
			if (dn) {
				fprintf(stderr, " (%s)", dn);
				OPENSSL_free(dn);
			}
			fprintf(stderr, "\n");
		}
	}

	if (isPrivate) {
		/* Check if already logged in to avoid resetting state */
		if (PKCS11_is_logged_in(slot, 0, &already_logged_in) != 0) {
			fprintf(stderr, "Unable to check if already logged in\n");
			return NULL;
		}
		/* Perform login to the token if required */
		if (!already_logged_in && !pkcs11_login(ctx, slot, tok, ui_method, callback_data)) {
			fprintf(stderr, "login to token failed, returning NULL...\n");
			return NULL;
		}
		/* Make sure there is at least one private key on the token */
		if (PKCS11_enumerate_keys(tok, &keys, &key_count)) {
			fprintf(stderr, "Unable to enumerate private keys\n");
			return NULL;
		}
	} else {
		/* Make sure there is at least one public key on the token */
		if (PKCS11_enumerate_public_keys(tok, &keys, &key_count)) {
			fprintf(stderr, "Unable to enumerate public keys\n");
			return NULL;
		}
	}
	if (key_count == 0) {
		fprintf(stderr, "No %s keys found.\n",
			(char *)(isPrivate ? "private" : "public"));
		return NULL;
	}
	if (ctx->verbose)
		fprintf(stderr, "Found %u %s key%s:\n", key_count,
			(char *)(isPrivate ? "private" : "public"),
			(key_count == 1) ? "" : "s");

	if (s_slot_key_id && *s_slot_key_id &&
			(key_id_len != 0 || key_label != NULL)) {
		for (n = 0; n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			if (ctx->verbose) {
				fprintf(stderr, "  %2u %c%c id=", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ');
				dump_hex(stderr, k->id, k->id_len);
				fprintf(stderr, " label=%s\n", k->label);
			}
			if (key_label != NULL && strcmp(k->label, key_label) == 0)
				selected_key = k;
			if (key_id_len != 0 && k->id_len == key_id_len
					&& memcmp(k->id, key_id, key_id_len) == 0)
				selected_key = k;
		}
	} else {
		selected_key = keys; /* Use the first key */
	}

	if (selected_key != NULL) {
		pk = isPrivate ?
			PKCS11_get_private_key(selected_key) :
			PKCS11_get_public_key(selected_key);
	} else {
		fprintf(stderr, "Key not found.\n");
		pk = NULL;
	}
	if (key_label != NULL)
		OPENSSL_free(key_label);
	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(ctx, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_load_public_key returned NULL\n");
		return NULL;
	}
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(ctx, s_key_id, ui_method, callback_data, 1);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_get_private_key returned NULL\n");
		return NULL;
	}
	return pk;
}

/******************************************************************************/
/* Engine ctrl request handling                                               */
/******************************************************************************/

static int ctrl_set_module(ENGINE_CTX *ctx, const char *modulename)
{
	OPENSSL_free(ctx->module);
	ctx->module = modulename ? OPENSSL_strdup(modulename) : NULL;
	return 1;
}

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
static int ctrl_set_pin(ENGINE_CTX *ctx, const char *pin)
{
	/* Pre-condition check */
	if (pin == NULL) {
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	destroy_pin(ctx);
	ctx->pin = OPENSSL_strdup(pin);
	if (ctx->pin != NULL)
		ctx->pin_length = strlen(ctx->pin);

	return ctx->pin != NULL;
}

static int ctrl_inc_verbose(ENGINE_CTX *ctx)
{
	ctx->verbose++;
	return 1;
}

static int ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

int pkcs11_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return ctrl_set_module(ctx, (const char *)p);
	case CMD_PIN:
		return ctrl_set_pin(ctx, (const char *)p);
	case CMD_VERBOSE:
		return ctrl_inc_verbose(ctx);
	case CMD_LOAD_CERT_CTRL:
		return ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return ctrl_set_init_args(ctx, (const char *)p);
	default:
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
