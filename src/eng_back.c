/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

struct engine_ctx_st {
	/* UI */
	int ui_method_provided;
	UI_METHOD *ui_method;
	void *ui_data;

	/* Logging */
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */

	/* Current operations */
	UTIL_CTX *util_ctx;
};

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

ENGINE_CTX *ENGINE_CTX_new(void)
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));
	ctx->util_ctx = UTIL_CTX_new();
	if (!ctx->util_ctx) {
		OPENSSL_free(ctx);
		return NULL;
	}

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

	/* UI */
	ctx->ui_method_provided = 0;
	ctx->ui_method = NULL;
	ctx->ui_data = NULL;

	/* Logging */
	ctx->debug_level = LOG_NOTICE;

	return ctx;
}

/* Destroy the context allocated with ENGINE_CTX_new() */
int ENGINE_CTX_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		UTIL_CTX_free(ctx->util_ctx);
		OPENSSL_free(ctx);
	}
	return 1;
}

static int ENGINE_CTX_enumerate_slots(ENGINE_CTX *ctx)
{
	return UTIL_CTX_enumerate_slots(ctx->util_ctx);
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

EVP_PKEY *ENGINE_CTX_load_pubkey(ENGINE_CTX *ctx, const char *uri,
		UI_METHOD *ui_method, void *ui_data)
{
	EVP_PKEY *evp_pkey;

	evp_pkey = UTIL_CTX_get_pubkey_from_uri(ctx->util_ctx, uri,
		ui_method, ui_data);

	if (!evp_pkey) {
		ENGINE_CTX_log(ctx, LOG_ERR, "PKCS11_get_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return evp_pkey;
}

EVP_PKEY *ENGINE_CTX_load_privkey(ENGINE_CTX *ctx, const char *uri,
		UI_METHOD *ui_method, void *ui_data)
{
	EVP_PKEY *evp_pkey;

	if (!ctx->ui_method_provided) { /* Cache ui_method, but not ui_data */
		ctx->ui_method = ui_method;
		UTIL_CTX_set_ui_method(ctx->util_ctx, ctx->ui_method, ctx->ui_data);
	}

	evp_pkey = UTIL_CTX_get_privkey_from_uri(ctx->util_ctx, uri,
		ui_method, ui_data);

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
	X509 *cert;

	if (!parms) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (parms->cert) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_INVALID_PARAMETER);
		return 0;
	}

	cert = UTIL_CTX_get_cert_from_uri(ctx->util_ctx, parms->s_slot_cert_id,
		ctx->ui_method, ctx->ui_data);

	if (!cert) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	parms->cert = cert;
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

int ENGINE_CTX_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)(void))
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return UTIL_CTX_set_module(ctx->util_ctx, (const char *)p);
	case CMD_PIN:
		return UTIL_CTX_set_pin(ctx->util_ctx, (const char *)p);
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
		ctx->ui_method_provided = 1;
		ctx->ui_method = p;
		return UTIL_CTX_set_ui_method(ctx->util_ctx, ctx->ui_method, ctx->ui_data);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		ctx->ui_data = p;
		return UTIL_CTX_set_ui_method(ctx->util_ctx, ctx->ui_method, ctx->ui_data);
	case CMD_FORCE_LOGIN:
		UTIL_CTX_set_force_login(ctx->util_ctx, 1);
		return 1;
	case CMD_RE_ENUMERATE:
		return ENGINE_CTX_enumerate_slots(ctx);
	case CMD_VLOG_A:
		return ENGINE_CTX_ctrl_set_vlog(ctx, p);
	case CMD_DEBUG_LEVEL:
		return ENGINE_CTX_ctrl_set_debug_level(ctx, (int)i);
	case CMD_KEYGEN:
		return UTIL_CTX_keygen(ctx->util_ctx, p);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
