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
#include "util.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (!ctx) {
		vfprintf(stderr, format, args);
	} else if (ctx->vlog) {
		/* Log messages through a custom logging function */
		const char *prefix = "pkcs11: ";
		char *vlog_format = OPENSSL_malloc(strlen(prefix) + strlen(format) + 1);

		if (!vlog_format) {
			va_end(args);
			return;
		}
		/* Copy and concatenate strings */
		strcpy(vlog_format, prefix);
		strcat(vlog_format, format);

		ctx->vlog(level, (const char *)vlog_format, args);
		OPENSSL_free(vlog_format);
	} else if (level <= ctx->debug_level) {
		if (level <= 4) { /* LOG_WARNING */
			vfprintf(stderr, format, args);
		} else {
			vprintf(format, args);
		}
	}

	va_end(args);
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
static int ctx_get_pin(ENGINE_CTX *ctx, const char *token_label, UI_METHOD *ui_method, void *callback_data)
{
	UI *ui;
	char *prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (!ui) {
		ctx_log(ctx, LOG_ERR, "UI_new failed\n");
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
		ctx_log(ctx, LOG_ERR, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		ctx_log(ctx, LOG_ERR, "UI_process failed\n");
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
		ctx_log(ctx, LOG_WARNING, "Unable to check if already logged in\n");
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
			ctx_log(ctx, LOG_ERR, "Could not allocate memory for PIN\n");
			return 0;
		}
		memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
		if (!ctx_get_pin(ctx, tok->label, ui_method, callback_data)) {
			ctx_destroy_pin(ctx);
			ctx_log(ctx, LOG_ERR, "No PIN code was entered\n");
			return 0;
		}
	}

	/* Now login in with the (possibly NULL) PIN */
	if (PKCS11_login(slot, 0, ctx->pin)) {
		/* Login failed, so free the PIN if present */
		ctx_destroy_pin(ctx);
		ctx_log(ctx, LOG_ERR, "Login failed\n");
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
	ctx->debug_level = LOG_NOTICE;

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

static int ctx_enumerate_slots_unlocked(ENGINE_CTX *ctx)
{
	/* PKCS11_update_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_update_slots(ctx->pkcs11_ctx, &ctx->slot_list, &ctx->slot_count) < 0) {
		ctx_log(ctx, LOG_INFO, "Failed to enumerate slots\n");
		return 0;
	}
	ctx_log(ctx, LOG_NOTICE, "Found %u slot%s\n", ctx->slot_count,
		ctx->slot_count <= 1 ? "" : "s");
	return 1;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static int ctx_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;

	if (ctx->pkcs11_ctx && ctx->slot_list)
		return 0;

	ctx_log(ctx, LOG_NOTICE, "PKCS#11: Initializing the engine: %s\n", ctx->module);

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_set_vlog_a_method(pkcs11_ctx, ctx->vlog);
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		ctx_log(ctx, LOG_ERR, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return -1;
	}
	ctx->pkcs11_ctx = pkcs11_ctx;

	if (ctx_enumerate_slots_unlocked(ctx) != 1)
		return -1;

	return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

static int ctx_init_libp11(ENGINE_CTX *ctx)
{
	int rv;

	pthread_mutex_lock(&ctx->lock);
	rv = ctx_init_libp11_unlocked(ctx);
	pthread_mutex_unlock(&ctx->lock);
	return rv;
}

static int ctx_enumerate_slots(ENGINE_CTX *ctx)
{
	int rv;

	if (!ctx->pkcs11_ctx)
		ctx_init_libp11(ctx);
	if (!ctx->pkcs11_ctx)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	rv = ctx_enumerate_slots_unlocked(ctx);
	pthread_mutex_unlock(&ctx->lock);
	return rv;
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
/* Engine load public/private key                                             */
/******************************************************************************/

EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ctx_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	evp_pkey = util_get_pubkey_from_uri(ctx, s_key_id, ui_method, callback_data);

	pthread_mutex_unlock(&ctx->lock);

	if (!evp_pkey) {
		ctx_log(ctx, LOG_ERR, "PKCS11_get_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return evp_pkey;
}

EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ctx_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	evp_pkey = util_get_privkey_from_uri(ctx, s_key_id, ui_method, callback_data);

	pthread_mutex_unlock(&ctx->lock);

	if (!evp_pkey) {
		ctx_log(ctx, LOG_ERR, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return evp_pkey;
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
int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin)
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

static int ctx_ctrl_set_debug_level(ENGINE_CTX *ctx, int level)
{
	ctx->debug_level = level;
	return 1;
}

static int ctx_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (!parms) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (parms->cert) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_INVALID_PARAMETER);
		return 0;
	}

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ctx_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return 0;
	}

	parms->cert = util_get_cert_from_uri(ctx, parms->s_slot_cert_id,
		ctx->ui_method, ctx->callback_data);

	pthread_mutex_unlock(&ctx->lock);

	if (!parms->cert) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
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

static int ctx_ctrl_set_vlog(ENGINE_CTX *ctx, void *cb)
{
	struct {
		PKCS11_VLOG_A_CB vlog;
	} *vlog_callback = cb;

	ctx->vlog = vlog_callback->vlog;

	if (ctx->pkcs11_ctx) /* already initialized */
		PKCS11_set_vlog_a_method(ctx->pkcs11_ctx, ctx->vlog); /* update */

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
		return ctx_ctrl_set_debug_level(ctx, 7);
	case CMD_QUIET:
		return ctx_ctrl_set_debug_level(ctx, 0);
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
		return ctx_enumerate_slots(ctx);
	case CMD_VLOG_A:
		return ctx_ctrl_set_vlog(ctx, p);
	case CMD_DEBUG_LEVEL:
		return ctx_ctrl_set_debug_level(ctx, (int)i);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
