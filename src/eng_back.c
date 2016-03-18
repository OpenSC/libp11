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
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
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
};

/******************************************************************************/
/* pin handling                                                               */
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
	ui = UI_new();
	if (ui == NULL) {
		fprintf(stderr, "UI_new failed\n");
		return 0;
	}
	if (ui_method != NULL)
		UI_set_method(ui, ui_method);
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH * sizeof(char));
	if (ctx->pin == NULL)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH * sizeof(char));
	ctx->pin_length = MAX_PIN_LENGTH;
	if (!UI_add_input_string(ui, "PKCS#11 token PIN: ",
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 1, MAX_PIN_LENGTH)) {
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
/* initialization/cleanup                                                     */
/******************************************************************************/

ENGINE_CTX *pkcs11_new()
{
	ENGINE_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));
	ctx->pkcs11_ctx = PKCS11_CTX_new();
	return ctx;
}

int pkcs11_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		if (ctx->slot_list) {
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
		}
		if (ctx->pkcs11_ctx) {
			PKCS11_CTX_unload(ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->pkcs11_ctx);
		}
		destroy_pin(ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
		OPENSSL_free(ctx);
	}
	return 1;
}

static int pkcs11_init_ctx(ENGINE_CTX *ctx, char *mod)
{
	/* PKCS11_CTX_load() uses C_GetSlotList() via p11-kit */
	if (PKCS11_CTX_load(ctx->pkcs11_ctx, mod) < 0) {
		fprintf(stderr, "Unable to load module %s\n", mod);
		return 0;
	}
	/* PKCS11_enumerate_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_enumerate_slots(ctx->pkcs11_ctx,
			&ctx->slot_list, &ctx->slot_count) < 0) {
		fprintf(stderr, "Failed to enumerate slots\n");
		return 0;
	}
	if (ctx->verbose) {
		fprintf(stderr, "Found %u slot%s\n", ctx->slot_count,
			(ctx->slot_count <= 1) ? "" : "s");
	}
	return 1;
}

int pkcs11_init(ENGINE_CTX *ctx)
{
	char *mod = ctx->module;
	int rv;

	if (mod == NULL)
		mod = getenv("PKCS11_MODULE_PATH");
#ifdef DEFAULT_PKCS11_MODULE
	if (mod == NULL)
		mod = DEFAULT_PKCS11_MODULE;
#endif
	if (ctx->verbose) {
		fprintf(stderr, "Initializing engine\n");
	}

	PKCS11_CTX_init_args(ctx->pkcs11_ctx, ctx->init_args);

	/* HACK ALERT: This is an ugly workaround for a complex OpenSC bug */
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList() */
	/* OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init() */
	/* The workaround is to temporarily unlock the non-recursive rwlock,
	   so it does not crash or hang (depending on the implementation) */
	/* FIXME: This workaround currently does not support OpenSSL 1.1 */
#if OPENSSL_VERSION_NUMBER < 0x10100004L
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
#endif
	rv = pkcs11_init_ctx(ctx, mod);
#if OPENSSL_VERSION_NUMBER < 0x10100004L
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
#endif

	return rv;
}

/******************************************************************************/
/* certificte handling                                                        */
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
	char tmp_pin[MAX_PIN_LENGTH];
	size_t tmp_pin_len = sizeof(tmp_pin);
	int slot_nr = -1;
	char flags[64];

	if (s_slot_cert_id && *s_slot_cert_id) {
		if (!strncmp(s_slot_cert_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(s_slot_cert_id, &match_tok,
				cert_id, &cert_id_len,
				tmp_pin, &tmp_pin_len, &cert_label);
			if (n && tmp_pin_len > 0 && tmp_pin[0] != 0) {
				destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH * sizeof(char));
				if (ctx->pin != NULL) {
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
				memset(ctx->pin, 0, MAX_PIN_LENGTH * sizeof(char));
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
			if (cert_label == NULL) {
				for (n = 0; n < cert_id_len; n++)
					fprintf(stderr, "%02x", cert_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", cert_label);
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

			if (cert_label == NULL) {
				if (cert_id_len != 0 && k->id_len == cert_id_len &&
						memcmp(k->id, cert_id, cert_id_len) == 0)
					selected_cert = k;
			} else {
				if (strcmp(k->label, cert_label) == 0)
					selected_cert = k;
			}
		}
	} else {
		selected_cert = certs; /* Use the first certificate */
	}

	if (selected_cert == NULL) {
		fprintf(stderr, "Certificate not found.\n");
		return NULL;
	}

	x509 = X509_dup(selected_cert->x509);
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
/* private and public key handling                                            */
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
			ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH * sizeof(char));
			ctx->pin_length = MAX_PIN_LENGTH;
			if (ctx->pin == NULL) {
				fprintf(stderr, "Could not allocate memory for PIN");
				return 0;
			}
			memset(ctx->pin, 0, MAX_PIN_LENGTH * sizeof(char));
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
	char tmp_pin[MAX_PIN_LENGTH];
	size_t tmp_pin_len = sizeof(tmp_pin);
	char flags[64];

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
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH * sizeof(char));
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH * sizeof(char));
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
			if (key_label == NULL) {
				for (n = 0; n < key_id_len; n++)
					fprintf(stderr, "%02x", key_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", key_label);
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

			fprintf(stderr, "  %2u    %s", n + 1, c->label);
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
		/* Perform login to the token if required */
		if (!pkcs11_login(ctx, slot, tok, ui_method, callback_data)) {
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
				fprintf(stderr, "  %2u %c%c %s\n", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ', k->label);
			}
			if (key_label == NULL) {
				if (key_id_len != 0 && k->id_len == key_id_len
						&& memcmp(k->id, key_id, key_id_len) == 0) {
					selected_key = k;
				}
			} else {
				if (strcmp(k->label, key_label) == 0) {
					selected_key = k;
				}
			}
		}
	} else {
		selected_key = keys; /* Use the first key */
	}

	if (selected_key == NULL) {
		fprintf(stderr, "Key not found.\n");
		return NULL;
	}

	pk = isPrivate ?
		PKCS11_get_private_key(selected_key) :
		PKCS11_get_public_key(selected_key);
	if (key_label != NULL)
		OPENSSL_free(key_label);
	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD * ui_method, void *callback_data)
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
		UI_METHOD * ui_method, void *callback_data)
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
/* engine ctrl request handling                                               */
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
