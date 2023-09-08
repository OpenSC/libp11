/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include "p11_pthread.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32

struct st_engine_ctx {
	/* Engine configuration */
	/*
	 * The PIN used for login. Cache for the ctx_get_pin function.
	 * The memory for this PIN is always owned internally,
	 * and may be freed as necessary. Before freeing, the PIN
	 * must be whitened, to prevent security holes.
	 */
	char *pin;
	size_t pin_length;
	int forced_pin;
	int verbose;
	char *module;
	char *init_args;
	UI_METHOD *ui_method;
	void *callback_data;
	int force_login;
	pthread_mutex_t lock;

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
};

static int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin);

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...)
{
	va_list ap;

	if (level > ctx->verbose)
			return;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void dump_hex(ENGINE_CTX *ctx, int level,
		const unsigned char *val, const size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		ctx_log(ctx, level, "%02x", val[n]);
}

static void dump_expiry(ENGINE_CTX *ctx, int level,
		const PKCS11_CERT *cert)
{
	BIO *bio;
	const ASN1_TIME *exp;

	char *data = NULL;
	int len = 0;

	if (level > ctx->verbose) {
		return;
	}

	if (!cert || !cert->x509 || !(exp = X509_get0_notAfter(cert->x509))) {
		ctx_log(ctx, level, "none");
		return;
	}

	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		return;
	}

	ASN1_TIME_print(bio, exp);

	len = BIO_get_mem_data(bio, &data);

	ctx_log(ctx, level, "%.*s", len, data);

	BIO_free(bio);

	return;
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/* Free PIN storage in secure way. */
static void ctx_destroy_pin(ENGINE_CTX *ctx)
{
	if (ctx->pin) {
		OPENSSL_cleanse(ctx->pin, ctx->pin_length);
		OPENSSL_free(ctx->pin);
		ctx->pin = NULL;
		ctx->pin_length = 0;
		ctx->forced_pin = 0;
	}
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int ctx_get_pin(ENGINE_CTX *ctx, const char* token_label, UI_METHOD *ui_method, void *callback_data)
{
	UI *ui;
	char* prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (!ui) {
		ctx_log(ctx, 0, "UI_new failed\n");
		return 0;
	}
	if (callback_data)
		UI_add_user_data(ui, callback_data);

	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (!ctx->pin)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	prompt = UI_construct_prompt(ui, "PKCS#11 token PIN", token_label);
	if (!prompt) {
		return 0;
	}
	if (UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH) <= 0) {
		ctx_log(ctx, 0, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		ctx_log(ctx, 0, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

/* Return 1 if the user has already logged in */
static int slot_logged_in(ENGINE_CTX *ctx, PKCS11_SLOT *slot) {
	int logged_in = 0;

	/* Check if already logged in to avoid resetting state */
	if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0) {
		ctx_log(ctx, 0, "Unable to check if already logged in\n");
		return 0;
	}
	return logged_in;
}

/*
 * Log-into the token if necessary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user interface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int ctx_login(ENGINE_CTX *ctx, PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *callback_data)
{
	if (!(ctx->force_login || tok->loginRequired) || slot_logged_in(ctx, slot))
		return 1;

	/* If the token has a secure login (i.e., an external keypad),
	 * then use a NULL PIN. Otherwise, obtain a new PIN if needed. */
	if (tok->secureLogin && !ctx->forced_pin) {
		/* Free the PIN if it has already been
		 * assigned (i.e, cached by ctx_get_pin) */
		ctx_destroy_pin(ctx);
	} else if (!ctx->pin) {
		ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
		ctx->pin_length = MAX_PIN_LENGTH;
		if (ctx->pin == NULL) {
			ctx_log(ctx, 0, "Could not allocate memory for PIN\n");
			return 0;
		}
		memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
		if (!ctx_get_pin(ctx, tok->label, ui_method, callback_data)) {
			ctx_destroy_pin(ctx);
			ctx_log(ctx, 0, "No PIN code was entered\n");
			return 0;
		}
	}

	/* Now login in with the (possibly NULL) PIN */
	if (PKCS11_login(slot, 0, ctx->pin)) {
		/* Login failed, so free the PIN if present */
		ctx_destroy_pin(ctx);
		ctx_log(ctx, 0, "Login failed\n");
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *ctx_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));
	pthread_mutex_init(&ctx->lock, 0);

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

	return ctx;
}

/* Destroy the context allocated with ctx_new() */
int ctx_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		ctx_destroy_pin(ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
		pthread_mutex_destroy(&ctx->lock);
		OPENSSL_free(ctx);
	}
	return 1;
}

static int ctx_enumerate_slots_unlocked(ENGINE_CTX *ctx, PKCS11_CTX *pkcs11_ctx)
{
	/* PKCS11_update_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_update_slots(pkcs11_ctx, &ctx->slot_list, &ctx->slot_count) < 0) {
		ctx_log(ctx, 0, "Failed to enumerate slots\n");
		return 0;
	}
	ctx_log(ctx, 1, "Found %u slot%s\n", ctx->slot_count,
		ctx->slot_count <= 1 ? "" : "s");
	return 1;
}

static int ctx_enumerate_slots(ENGINE_CTX *ctx, PKCS11_CTX *pkcs11_ctx)
{
	int rv;

	pthread_mutex_lock(&ctx->lock);
	rv = ctx_enumerate_slots_unlocked(ctx, pkcs11_ctx);
	pthread_mutex_unlock(&ctx->lock);
	return rv;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static int ctx_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;

	if (ctx->pkcs11_ctx && ctx->slot_list)
		return 0;

	ctx_log(ctx, 1, "PKCS#11: Initializing the engine: %s\n", ctx->module);

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		ctx_log(ctx, 0, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return -1;
	}
	ctx->pkcs11_ctx = pkcs11_ctx;

	if (ctx_enumerate_slots_unlocked(ctx, pkcs11_ctx) != 1)
		return -1;

	return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

/* Function called from ENGINE_init() */
int ctx_init(ENGINE_CTX *ctx)
{
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList().
	 * OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init().
	 * Double-locking a non-recursive rwlock causes the application to
	 * crash or hang, depending on the locking library implementation. */

	(void)ctx; /* squash the unused parameter warning */
	return 1;
}

/* Finish engine operations initialized with ctx_init() */
int ctx_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		if (ctx->slot_list) {
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
			ctx->slot_list = NULL;
			ctx->slot_count = 0;
		}
		if (ctx->pkcs11_ctx) {
			PKCS11_CTX_unload(ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->pkcs11_ctx);
			ctx->pkcs11_ctx = NULL;
		}
	}
	return 1;
}

/******************************************************************************/
/* Utilities common to public, private key and certificate handling           */
/******************************************************************************/

static void *ctx_try_load_object(ENGINE_CTX *ctx,
		const char *object_typestr,
		void *(*match_func)(ENGINE_CTX *, PKCS11_TOKEN *,
				const unsigned char *, size_t, const char *),
		const char *object_uri, const int login,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL, **matched_slots = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	unsigned int n, m;
	unsigned char *obj_id = NULL;
	size_t obj_id_len = 0;
	char *obj_label = NULL;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	int slot_nr = -1;
	char flags[64];
	size_t matched_count = 0;
	void *object = NULL;

	if (object_uri && *object_uri) {
		obj_id_len = strlen(object_uri) + 1;
		obj_id = OPENSSL_malloc(obj_id_len);
		if (!strncasecmp(object_uri, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(ctx, object_uri, &match_tok,
				obj_id, &obj_id_len, tmp_pin, &tmp_pin_len, &obj_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The %s ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n",
					object_typestr);
				ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_ID);
				goto error;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				tmp_pin[tmp_pin_len] = 0;
				if (!ctx_ctrl_set_pin(ctx, tmp_pin)) {
					goto error;
				}
			}
			ctx_log(ctx, 1, "Looking in slots for %s %s login: ",
				object_typestr, login ? "with" : "without");
		} else {
			n = parse_slot_id_string(ctx, object_uri, &slot_nr,
				obj_id, &obj_id_len, &obj_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The %s ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n",
					object_typestr);
				ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_ID);
				goto error;
			}
			ctx_log(ctx, 1, "Looking in slot %d for %s %s login: ",
				slot_nr, object_typestr, login ? "with" : "without");
		}
		if (obj_id_len != 0) {
			ctx_log(ctx, 1, "id=");
			dump_hex(ctx, 1, obj_id, obj_id_len);
		}
		if (obj_id_len != 0 && obj_label)
			ctx_log(ctx, 1, " ");
		if (obj_label)
			ctx_log(ctx, 1, "label=%s", obj_label);
		ctx_log(ctx, 1, "\n");
	}

	matched_slots = (PKCS11_SLOT **)calloc(ctx->slot_count,
		sizeof(PKCS11_SLOT *));
	if (!matched_slots) {
		ctx_log(ctx, 0, "Could not allocate memory for matched slots\n");
		goto error;
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
				(!match_tok->label ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(!match_tok->manufacturer ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(!match_tok->serialnr ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(!match_tok->model ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		ctx_log(ctx, 1, "- [%lu] %-25.25s  %-36s",
			PKCS11_get_slotid_from_slot(slot),
			slot->description, flags);
		if (slot->token) {
			ctx_log(ctx, 1, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");
		}
		ctx_log(ctx, 1, "\n");

		/* Ignore slots without tokens or with uninitialized token */
		if (found_slot && found_slot->token && found_slot->token->initialized) {
			matched_slots[matched_count] = found_slot;
			matched_count++;
		}
		found_slot = NULL;
	}

	if (matched_count == 0) {
		if (match_tok) {
			ctx_log(ctx, 0, "No matching initialized token was found for %s\n",
				object_typestr);
			goto error;
		}

		/* If the legacy slot ID format was used */
		if (slot_nr != -1) {
			ctx_log(ctx, 0, "The %s was not found on slot %d\n", object_typestr, slot_nr);
			goto error;
		} else {
			found_slot = PKCS11_find_token(ctx->pkcs11_ctx,
								ctx->slot_list, ctx->slot_count);
			/* Ignore if the the token is not initialized */
			if (found_slot && found_slot->token &&
					found_slot->token->initialized) {
				matched_slots[matched_count] = found_slot;
				matched_count++;
			} else {
				ctx_log(ctx, 0, "No tokens found\n");
				goto error;
			}
		}
	}

	for (n = 0; n < matched_count; n++) {
		slot = matched_slots[n];
		tok = slot->token;
		if (!tok) {
			ctx_log(ctx, 0, "Empty slot found\n");
			break;
		}

		ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
		ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

		/* In several tokens certificates are marked as private */
		if (login) {
			/* Only try to login if login is required */
			if (tok->loginRequired || ctx->force_login) {
				/* Only try to login if a single slot matched to avoiding trying
				 * the PIN against all matching slots */
				if (matched_count == 1) {
					if (!ctx_login(ctx, slot, tok,
							ui_method, callback_data)) {
						ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
						goto error;
					}
				} else {
					ctx_log(ctx, 0, "Multiple matching slots (%lu); will not try to"
						" login\n", matched_count);
					for (m = 0; m < matched_count; m++){
						slot = matched_slots[m];
						ctx_log(ctx, 0, "- [%u] %s: %s\n", m + 1,
								slot->description? slot->description:
								"(no description)",
								(slot->token && slot->token->label)?
								slot->token->label: "no label");
					}
					goto error;
				}
			}
		}

		object = match_func(ctx, tok, obj_id, obj_id_len, obj_label);
		if (object)
			break;
	}

error:
	/* Free the searched token data */
	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}

	if (obj_label)
		OPENSSL_free(obj_label);
	if (matched_slots)
		free(matched_slots);
	if (obj_id)
		OPENSSL_free(obj_id);
	return object;
}

static void *ctx_load_object(ENGINE_CTX *ctx,
		const char *object_typestr,
		void *(*match_func)(ENGINE_CTX *, PKCS11_TOKEN *,
				const unsigned char *, size_t, const char *),
		const char *object_uri, UI_METHOD *ui_method, void *callback_data)
{
	void *obj = NULL;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ctx_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	if (!ctx->force_login) {
		ERR_clear_error();
		obj = ctx_try_load_object(ctx, object_typestr, match_func,
			object_uri, 0, ui_method, callback_data);
	}

	if (!obj) {
		/* Try again with login */
		ERR_clear_error();
		obj = ctx_try_load_object(ctx, object_typestr, match_func,
			object_uri, 1, ui_method, callback_data);
		if (!obj) {
			ctx_log(ctx, 0, "The %s was not found at: %s\n",
				object_typestr, object_uri);
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	return obj;
}

/******************************************************************************/
/* Certificate handling                                                       */
/******************************************************************************/

static PKCS11_CERT *cert_cmp(PKCS11_CERT *a, PKCS11_CERT *b, time_t *ptime)
{
	const ASN1_TIME *a_time, *b_time;
	int pday, psec;

	/* the best certificate exists */
	if (!a || !a->x509) {
		return b;
	}
	if (!b || !b->x509) {
		return a;
	}

	a_time = X509_get0_notAfter(a->x509);
	b_time = X509_get0_notAfter(b->x509);

	/* the best certificate expires last */
	if (ASN1_TIME_diff(&pday, &psec, a_time, b_time)) {
		if (pday < 0 || psec < 0) {
			return a;
		} else if (pday > 0 || psec > 0) {
			return b;
		}
	}

	/* deterministic tie break */
	if (X509_cmp(a->x509, b->x509) < 1) {
		return b;
	} else {
		return a;
	}
}

static void *match_cert(ENGINE_CTX *ctx, PKCS11_TOKEN *tok,
		const unsigned char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_CERT *certs, *selected_cert = NULL;
	PKCS11_CERT cert_template = {0};
	unsigned int m, cert_count;
	const char *which;

	errno = 0;
	cert_template.label = obj_label ? OPENSSL_strdup(obj_label) : NULL;
	if (errno != 0) {
		ctx_log(ctx, 0, "%s", strerror(errno));
		goto cleanup;
	}
	if (obj_id_len) {
		cert_template.id = OPENSSL_malloc(obj_id_len);
		if (!cert_template.id) {
			ctx_log(ctx, 0, "Could not allocate memory for ID\n");
			goto cleanup;
		}
		memcpy(cert_template.id, obj_id, obj_id_len);
		cert_template.id_len = obj_id_len;
	}

	if (PKCS11_enumerate_certs_ext(tok, &cert_template, &certs, &cert_count)) {
		ctx_log(ctx, 0, "Unable to enumerate certificates\n");
		goto cleanup;
	}
	if (cert_count == 0)
		goto cleanup;

	ctx_log(ctx, 1, "Found %u certificate%s:\n", cert_count, cert_count == 1 ? "" : "s");
	if (obj_id_len != 0 || obj_label) {
		which = "longest expiry matching";
		for (m = 0; m < cert_count; m++) {
			PKCS11_CERT *k = certs + m;

			ctx_log(ctx, 1, "  %2u    id=", m + 1);
			dump_hex(ctx, 1, k->id, k->id_len);
			ctx_log(ctx, 1, " label=%s expiry=", k->label ? k->label : "(null)");
			dump_expiry(ctx, 1, k);
			ctx_log(ctx, 1, "\n");

			if (obj_label && obj_id_len != 0) {
				if (k->label && strcmp(k->label, obj_label) == 0 &&
						k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_cert = cert_cmp(selected_cert, k, NULL);
				}
			} else if (obj_label && !obj_id_len) {
				if (k->label && strcmp(k->label, obj_label) == 0) {
					selected_cert = cert_cmp(selected_cert, k, NULL);
				}
			} else if (obj_id_len && !obj_label) {
				if (k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_cert = cert_cmp(selected_cert, k, NULL);
				}
			}
		}
	} else {
		which = "first (with id present)";
		for (m = 0; m < cert_count; m++) {
			PKCS11_CERT *k = certs + m;

			ctx_log(ctx, 1, "  %2u    id=", m + 1);
			dump_hex(ctx, 1, k->id, k->id_len);
			ctx_log(ctx, 1, " label=%s expiry=", k->label ? k->label : "(null)");
			dump_expiry(ctx, 1, k);
			ctx_log(ctx, 1, "\n");

			if (!selected_cert && k->id && *k->id) {
				selected_cert = k; /* Use the first certificate with nonempty id */
			}
		}
		if (!selected_cert) {
			which = "first";
			selected_cert = certs; /* Use the first certificate */
		}
	}

	if (selected_cert) {
		ctx_log(ctx, 1, "Returning %s certificate: id=", which);
		dump_hex(ctx, 1, selected_cert->id, selected_cert->id_len);
		ctx_log(ctx, 1, " label=%s expiry=", selected_cert->label ? selected_cert->label : "(null)");
		dump_expiry(ctx, 1, selected_cert);
		ctx_log(ctx, 1, "\n");
	} else {
		ctx_log(ctx, 1, "No matching certificate returned.\n");
	}

cleanup:
	OPENSSL_free(cert_template.label);
	OPENSSL_free(cert_template.id);
	return selected_cert;
}

static int ctx_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;
	PKCS11_CERT *cert;

	if (!parms) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (parms->cert) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_INVALID_PARAMETER);
		return 0;
	}

	cert = ctx_load_object(ctx, "certificate", match_cert, parms->s_slot_cert_id,
		ctx->ui_method, ctx->callback_data);
	if (!cert) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	parms->cert = X509_dup(cert->x509);
	return 1;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

static void *match_key(ENGINE_CTX *ctx, const char *key_type,
		PKCS11_KEY *keys, unsigned int key_count,
		const unsigned char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_KEY *selected_key = NULL;
	unsigned int m;
	const char *which;

	if (key_count == 0)
		return NULL;

	ctx_log(ctx, 1, "Found %u %s key%s:\n", key_count, key_type,
		key_count == 1 ? "" : "s");

	if (obj_id_len != 0 || obj_label) {
		which = "last matching";
		for (m = 0; m < key_count; m++) {
			PKCS11_KEY *k = keys + m;

			ctx_log(ctx, 1, "  %2u %c%c id=", m + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ');
			dump_hex(ctx, 1, k->id, k->id_len);
			ctx_log(ctx, 1, " label=%s\n", k->label ? k->label : "(null)");

			if (obj_label && obj_id_len != 0) {
				if (k->label && strcmp(k->label, obj_label) == 0 &&
						k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_key = k;
				}
			} else if (obj_label && !obj_id_len) {
				if (k->label && strcmp(k->label, obj_label) == 0) {
					selected_key = k;
				}
			} else if (obj_id_len && !obj_label) {
				if (k->id_len == obj_id_len &&
						memcmp(k->id, obj_id, obj_id_len) == 0) {
					selected_key = k;
				}
			}
		}
	} else {
		which = "first";
		selected_key = keys; /* Use the first key */
	}

	if (selected_key) {
		ctx_log(ctx, 1, "Returning %s %s key: id=", which, key_type);
		dump_hex(ctx, 1, selected_key->id, selected_key->id_len);
		ctx_log(ctx, 1, " label=%s\n", selected_key->label ? selected_key->label : "(null)");
	} else {
		ctx_log(ctx, 1, "No matching %s key returned.\n", key_type);
	}

	return selected_key;
}

static void *match_key_int(ENGINE_CTX *ctx, PKCS11_TOKEN *tok,
		const unsigned int isPrivate, const unsigned char *obj_id, size_t obj_id_len, const char *obj_label)
{
	PKCS11_KEY *keys;
	PKCS11_KEY key_template = {0};
	unsigned int key_count;
	void *ret = NULL;

	key_template.isPrivate = isPrivate;
	errno = 0;
	key_template.label = obj_label ? OPENSSL_strdup(obj_label) : NULL;
	if (errno != 0) {
		ctx_log(ctx, 0, "%s", strerror(errno));
		goto cleanup;
	}
	if (obj_id_len) {
		key_template.id = OPENSSL_malloc(obj_id_len);
		if (!key_template.id) {
			ctx_log(ctx, 0, "Could not allocate memory for ID\n");
			goto cleanup;
		}
		memcpy(key_template.id, obj_id, obj_id_len);
		key_template.id_len = obj_id_len;
	}

	/* Make sure there is at least one private key on the token */
	if (key_template.isPrivate != 0 && PKCS11_enumerate_keys_ext(tok, (const PKCS11_KEY *) &key_template, &keys, &key_count)) {
		ctx_log(ctx, 0, "Unable to enumerate private keys\n");
		goto cleanup;
	}
	else if (key_template.isPrivate == 0 && PKCS11_enumerate_public_keys_ext(tok, (const PKCS11_KEY *) &key_template, &keys, &key_count)) {
		ctx_log(ctx, 0, "Unable to enumerate public keys\n");
		goto cleanup;
	}
	ret = match_key(ctx, key_template.isPrivate ? "private" : "public", keys, key_count, obj_id, obj_id_len, obj_label);
cleanup:
	OPENSSL_free(key_template.label);
	OPENSSL_free(key_template.id);
	return ret;
}

static void *match_public_key(ENGINE_CTX *ctx, PKCS11_TOKEN *tok,
		const unsigned char *obj_id, size_t obj_id_len, const char *obj_label)
{
	return match_key_int(ctx, tok, 0, obj_id, obj_id_len, obj_label);
}

static void *match_private_key(ENGINE_CTX *ctx, PKCS11_TOKEN *tok,
		const unsigned char *obj_id, size_t obj_id_len, const char *obj_label)
{
	return match_key_int(ctx, tok, 1, obj_id, obj_id_len, obj_label);
}

EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_KEY *key;

	key = ctx_load_object(ctx, "public key", match_public_key, s_key_id,
		ui_method, callback_data);
	if (!key) {
		ctx_log(ctx, 0, "PKCS11_load_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return PKCS11_get_public_key(key);
}

EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_KEY *key;

	key = ctx_load_object(ctx, "private key", match_private_key, s_key_id,
		ui_method, callback_data);
	if (!key) {
		ctx_log(ctx, 0, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return PKCS11_get_private_key(key);
}

/******************************************************************************/
/* Engine ctrl request handling                                               */
/******************************************************************************/

static int ctx_ctrl_set_module(ENGINE_CTX *ctx, const char *modulename)
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
static int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin)
{
	/* Pre-condition check */
	if (!pin) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_PASSED_NULL_PARAMETER);
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_strdup(pin);
	if (!ctx->pin) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_MALLOC_FAILURE);
		errno = ENOMEM;
		return 0;
	}
	ctx->pin_length = strlen(ctx->pin);
	ctx->forced_pin = 1;
	return 1;
}

static int ctx_ctrl_inc_verbose(ENGINE_CTX *ctx)
{
	ctx->verbose++;
	return 1;
}

static int ctx_ctrl_set_quiet(ENGINE_CTX *ctx)
{
	ctx->verbose = -1;
	return 1;
}

static int ctx_ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

static int ctx_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method)
{
	ctx->ui_method = ui_method;
	if (ctx->pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data)
{
	ctx->callback_data = callback_data;
	if (ctx->pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_force_login(ENGINE_CTX *ctx)
{
	ctx->force_login = 1;
	return 1;
}

int ctx_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return ctx_ctrl_set_module(ctx, (const char *)p);
	case CMD_PIN:
		return ctx_ctrl_set_pin(ctx, (const char *)p);
	case CMD_VERBOSE:
		return ctx_ctrl_inc_verbose(ctx);
	case CMD_QUIET:
		return ctx_ctrl_set_quiet(ctx);
	case CMD_LOAD_CERT_CTRL:
		return ctx_ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return ctx_ctrl_set_init_args(ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case CMD_SET_USER_INTERFACE:
		return ctx_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		return ctx_ctrl_set_callback_data(ctx, p);
	case CMD_FORCE_LOGIN:
		return ctx_ctrl_force_login(ctx);
	case CMD_RE_ENUMERATE:
		return ctx_enumerate_slots(ctx, ctx->pkcs11_ctx);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
