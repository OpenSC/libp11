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
	/* Engine configuration */
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */
	char *module;
	char *init_args;
	pthread_mutex_t lock;

	UTIL_CTX *util_ctx;
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
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *ENGINE_CTX_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));
	ctx->util_ctx = UTIL_CTX_new();
	if (!ctx->util_ctx)
		return NULL;
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

/* Destroy the context allocated with ENGINE_CTX_new() */
int ENGINE_CTX_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		UTIL_CTX_free(ctx->util_ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
		pthread_mutex_destroy(&ctx->lock);
		OPENSSL_free(ctx);
	}
	return 1;
}

static int ENGINE_CTX_enumerate_slots_unlocked(ENGINE_CTX *ctx)
{
	/* PKCS11_update_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_update_slots(ctx->util_ctx->pkcs11_ctx, &ctx->util_ctx->slot_list, &ctx->util_ctx->slot_count) < 0) {
		ENGINE_CTX_log(ctx, LOG_INFO, "Failed to enumerate slots\n");
		return 0;
	}
	ENGINE_CTX_log(ctx, LOG_NOTICE, "Found %u slot%s\n", ctx->util_ctx->slot_count,
		ctx->util_ctx->slot_count <= 1 ? "" : "s");
	return 1;
}

/* Initialize libp11 data: ctx->util_ctx->pkcs11_ctx and ctx->util_ctx->slot_list */
static int ENGINE_CTX_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;

	if (ctx->util_ctx->pkcs11_ctx && ctx->util_ctx->slot_list)
		return 0;

	ENGINE_CTX_log(ctx, LOG_NOTICE, "PKCS#11: Initializing the engine: %s\n", ctx->module);

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_set_vlog_a_method(pkcs11_ctx, ctx->vlog);
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(pkcs11_ctx, ctx->util_ctx->ui_method, ctx->util_ctx->callback_data);
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		ENGINE_CTX_log(ctx, LOG_ERR, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return -1;
	}
	ctx->util_ctx->pkcs11_ctx = pkcs11_ctx;

	if (ENGINE_CTX_enumerate_slots_unlocked(ctx) != 1)
		return -1;

	return ctx->util_ctx->pkcs11_ctx && ctx->util_ctx->slot_list ? 0 : -1;
}

static int ENGINE_CTX_init_libp11(ENGINE_CTX *ctx)
{
	int rv;

	pthread_mutex_lock(&ctx->lock);
	rv = ENGINE_CTX_init_libp11_unlocked(ctx);
	pthread_mutex_unlock(&ctx->lock);
	return rv;
}

static int ENGINE_CTX_enumerate_slots(ENGINE_CTX *ctx)
{
	int rv;

	if (!ctx->util_ctx->pkcs11_ctx)
		ENGINE_CTX_init_libp11(ctx);
	if (!ctx->util_ctx->pkcs11_ctx)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	rv = ENGINE_CTX_enumerate_slots_unlocked(ctx);
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
		if (ctx->util_ctx->slot_list) {
			PKCS11_release_all_slots(ctx->util_ctx->pkcs11_ctx,
				ctx->util_ctx->slot_list, ctx->util_ctx->slot_count);
			ctx->util_ctx->slot_list = NULL;
			ctx->util_ctx->slot_count = 0;
		}
		if (ctx->util_ctx->pkcs11_ctx) {
			PKCS11_CTX_unload(ctx->util_ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->util_ctx->pkcs11_ctx);
			ctx->util_ctx->pkcs11_ctx = NULL;
		}
	}
	return 1;
}

/******************************************************************************/
/* Engine load public/private key                                             */
/******************************************************************************/

EVP_PKEY *ENGINE_CTX_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ENGINE_CTX_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	ctx->util_ctx->ui_method = ui_method;
	ctx->util_ctx->callback_data = callback_data;
	evp_pkey = UTIL_CTX_get_pubkey_from_uri(ctx->util_ctx, s_key_id);

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
	EVP_PKEY *evp_pkey;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ENGINE_CTX_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	ctx->util_ctx->ui_method = ui_method;
	ctx->util_ctx->callback_data = callback_data;
	evp_pkey = UTIL_CTX_get_privkey_from_uri(ctx->util_ctx, s_key_id);

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

static int ENGINE_CTX_ctrl_set_module(ENGINE_CTX *ctx, const char *modulename)
{
	OPENSSL_free(ctx->module);
	ctx->module = modulename ? OPENSSL_strdup(modulename) : NULL;
	return 1;
}

static int ENGINE_CTX_ctrl_set_debug_level(ENGINE_CTX *ctx, int level)
{
	ctx->debug_level = level;
	return 1;
}

static int ENGINE_CTX_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
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
	if (ENGINE_CTX_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return 0;
	}

	parms->cert = UTIL_CTX_get_cert_from_uri(ctx->util_ctx, parms->s_slot_cert_id);
	pthread_mutex_unlock(&ctx->lock);

	if (!parms->cert) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	return 1;
}

static int ENGINE_CTX_ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

static int ENGINE_CTX_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method)
{
	ctx->util_ctx->ui_method = ui_method;
	if (ctx->util_ctx->pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->util_ctx->pkcs11_ctx,
			ctx->util_ctx->ui_method, ctx->util_ctx->callback_data);
	return 1;
}

static int ENGINE_CTX_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data)
{
	ctx->util_ctx->callback_data = callback_data;
	if (ctx->util_ctx->pkcs11_ctx) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->util_ctx->pkcs11_ctx,
			ctx->util_ctx->ui_method, ctx->util_ctx->callback_data);
	return 1;
}

static int ENGINE_CTX_ctrl_force_login(ENGINE_CTX *ctx)
{
	ctx->util_ctx->force_login = 1;
	return 1;
}

static int ENGINE_CTX_ctrl_set_vlog(ENGINE_CTX *ctx, void *cb)
{
	struct {
		PKCS11_VLOG_A_CB vlog;
	} *vlog_callback = cb;

	ctx->vlog = vlog_callback->vlog;
	ctx->util_ctx->vlog = vlog_callback->vlog;

	if (ctx->util_ctx->pkcs11_ctx) /* already initialized */
		PKCS11_set_vlog_a_method(ctx->util_ctx->pkcs11_ctx, ctx->vlog); /* update */

	return 1;
}

int ENGINE_CTX_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return ENGINE_CTX_ctrl_set_module(ctx, (const char *)p);
	case CMD_PIN:
		return UTIL_CTX_set_pin(ctx->util_ctx, (const char *)p);
	case CMD_VERBOSE:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, 7);
	case CMD_QUIET:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, 0);
	case CMD_LOAD_CERT_CTRL:
		return ENGINE_CTX_ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return ENGINE_CTX_ctrl_set_init_args(ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case CMD_SET_USER_INTERFACE:
		return ENGINE_CTX_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		return ENGINE_CTX_ctrl_set_callback_data(ctx, p);
	case CMD_FORCE_LOGIN:
		return ENGINE_CTX_ctrl_force_login(ctx);
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
