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
#include "p11_pthread.h"
#include <stdio.h>
#include <string.h>

struct engine_ctx_st {
	UTIL_CTX *util_ctx;
	pthread_mutex_t lock;

	/* Logging */
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */

	/* PIN UI */
	UI_METHOD *ui_method;
	void *callback_data;
};

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void ENGINE_CTX_log(ENGINE_CTX *ctx, int level, const char *format, ...)
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

static int ENGINE_CTX_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method)
{
	PKCS11_CTX *pkcs11_ctx = UTIL_CTX_get_libp11_ctx(ctx->util_ctx);

	ctx->ui_method = ui_method;
	if (pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ENGINE_CTX_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data)
{
	PKCS11_CTX *pkcs11_ctx = UTIL_CTX_get_libp11_ctx(ctx->util_ctx);

	ctx->callback_data = callback_data;
	if (pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);
	return 1;
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static char *get_pin_callback(void *param, const char *token_label)
{
	ENGINE_CTX *ctx;
	UI *ui;
	char *prompt = NULL;
	char *pin = NULL;

	ctx = param;
	ui = UI_new_method(ctx->ui_method);
	if (!ui) {
		ENGINE_CTX_log(ctx, LOG_ERR, "UI_new failed\n");
		goto cleanup;
	}
	if (ctx->callback_data)
		UI_add_user_data(ui, ctx->callback_data);

	pin = OPENSSL_zalloc(MAX_PIN_LENGTH+1);
	if (!pin)
		goto cleanup;
	prompt = UI_construct_prompt(ui, "PKCS#11 token PIN", token_label);
	if (!prompt)
		goto cleanup;
	if (UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, pin, 4, MAX_PIN_LENGTH) <= 0) {
		ENGINE_CTX_log(ctx, LOG_ERR, "UI_dup_input_string failed\n");
		goto cleanup;
	}
	if (UI_process(ui)) {
		ENGINE_CTX_log(ctx, LOG_ERR, "UI_process failed\n");
		goto cleanup;
	}

cleanup:
	UI_free(ui);
	OPENSSL_free(prompt);
	return pin;
}

/******************************************************************************/
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *ENGINE_CTX_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_zalloc(sizeof(ENGINE_CTX));
	if (!ctx)
		return NULL;
	ctx->util_ctx = UTIL_CTX_new(get_pin_callback, ctx);
	if (!ctx->util_ctx) {
		OPENSSL_free(ctx);
		return NULL;
	}
	pthread_mutex_init(&ctx->lock, 0);

	mod = getenv("PKCS11_MODULE_PATH");
	if (mod) {
		UTIL_CTX_set_module(ctx->util_ctx, mod);
	} else {
#ifdef DEFAULT_PKCS11_MODULE
		UTIL_CTX_set_module(ctx->util_ctx, DEFAULT_PKCS11_MODULE);
#else
		UTIL_CTX_set_module(ctx->util_ctx, NULL);
#endif
	}
	ctx->debug_level = LOG_NOTICE;

	return ctx;
}

/* Destroy the context allocated with ENGINE_CTX_new() */
int ENGINE_CTX_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		UTIL_CTX_free(ctx->util_ctx);
		pthread_mutex_destroy(&ctx->lock);
		OPENSSL_free(ctx);
	}
	return 1;
}

static int ENGINE_CTX_enumerate_slots(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;
	int rv;

	pthread_mutex_lock(&ctx->lock);

	pkcs11_ctx = UTIL_CTX_init_libp11(ctx->util_ctx);
	if (!pkcs11_ctx) {
		pthread_mutex_unlock(&ctx->lock);
		return -1;
	}
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	rv = UTIL_CTX_enumerate_slots(ctx->util_ctx);

	pthread_mutex_unlock(&ctx->lock);
	return rv;
}

/* Function called from ENGINE_init() */
int ENGINE_CTX_init(ENGINE_CTX *ctx)
{
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList().
	 * OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init().
	 * Double-locking a non-recursive rwlock causes the application to
	 * crash or hang, depending on the locking library implementation. */

	(void)ctx; /* squash the unused parameter warning */
	return 1;
}

/* Finish engine operations initialized with ENGINE_CTX_init() */
int ENGINE_CTX_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		UTIL_CTX_free_libp11(ctx->util_ctx);
	}
	return 1;
}

/******************************************************************************/
/* Engine load public/private key                                             */
/******************************************************************************/

EVP_PKEY *ENGINE_CTX_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_CTX *pkcs11_ctx;
	UI_METHOD *orig_ui_method;
	void *orig_callback_data;
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	pkcs11_ctx = UTIL_CTX_init_libp11(ctx->util_ctx);
	if (!pkcs11_ctx) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	orig_ui_method = ctx->ui_method;
	orig_callback_data = ctx->callback_data;
	ctx->ui_method = ui_method;
	ctx->callback_data = callback_data;
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	evp_pkey = UTIL_CTX_get_pubkey_from_uri(ctx->util_ctx, s_key_id);

	ctx->ui_method = orig_ui_method;
	ctx->callback_data = orig_callback_data;
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	pthread_mutex_unlock(&ctx->lock);

	if (!evp_pkey) {
		ENGINE_CTX_log(ctx, LOG_ERR, "PKCS11_get_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return evp_pkey;
}

EVP_PKEY *ENGINE_CTX_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_CTX *pkcs11_ctx;
	UI_METHOD *orig_ui_method;
	void *orig_callback_data;
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	pkcs11_ctx = UTIL_CTX_init_libp11(ctx->util_ctx);
	if (!pkcs11_ctx) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	orig_ui_method = ctx->ui_method;
	orig_callback_data = ctx->callback_data;
	ctx->ui_method = ui_method;
	ctx->callback_data = callback_data;
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	evp_pkey = UTIL_CTX_get_privkey_from_uri(ctx->util_ctx, s_key_id);

	ctx->ui_method = orig_ui_method;
	ctx->callback_data = orig_callback_data;
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	pthread_mutex_unlock(&ctx->lock);

	if (!evp_pkey) {
		ENGINE_CTX_log(ctx, LOG_ERR, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return evp_pkey;
}

/******************************************************************************/
/* Engine ctrl request handling                                               */
/******************************************************************************/

static int ENGINE_CTX_ctrl_set_debug_level(ENGINE_CTX *ctx, int level)
{
	ctx->debug_level = level;
	UTIL_CTX_set_debug_level(ctx->util_ctx, level);
	return 1;
}

static int ENGINE_CTX_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;
	PKCS11_CTX *pkcs11_ctx;

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
	pkcs11_ctx = UTIL_CTX_init_libp11(ctx->util_ctx);
	if (!pkcs11_ctx) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return 0;
	}

	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	parms->cert = UTIL_CTX_get_cert_from_uri(ctx->util_ctx, parms->s_slot_cert_id);

	pthread_mutex_unlock(&ctx->lock);

	if (!parms->cert) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	return 1;
}

static int ENGINE_CTX_ctrl_set_vlog(ENGINE_CTX *ctx, void *cb)
{
	struct {
		PKCS11_VLOG_A_CB vlog;
	} *vlog_callback = cb;

	ctx->vlog = vlog_callback->vlog;
	UTIL_CTX_set_vlog_a(ctx->util_ctx, vlog_callback->vlog);

	return 1;
}

int ENGINE_CTX_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return UTIL_CTX_set_module(ctx->util_ctx, (const char *)p);
	case CMD_PIN:
		return UTIL_CTX_set_pin(ctx->util_ctx, (const char *)p, 1);
	case CMD_VERBOSE:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, 7);
	case CMD_QUIET:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, 0);
	case CMD_LOAD_CERT_CTRL:
		return ENGINE_CTX_ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return UTIL_CTX_set_init_args(ctx->util_ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case CMD_SET_USER_INTERFACE:
		return ENGINE_CTX_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		return ENGINE_CTX_ctrl_set_callback_data(ctx, p);
	case CMD_FORCE_LOGIN:
		UTIL_CTX_set_force_login(ctx->util_ctx, 1);
		return 1;
	case CMD_RE_ENUMERATE:
		return ENGINE_CTX_enumerate_slots(ctx);
	case CMD_VLOG_A:
		return ENGINE_CTX_ctrl_set_vlog(ctx, p);
	case CMD_DEBUG_LEVEL:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, (int)i);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
