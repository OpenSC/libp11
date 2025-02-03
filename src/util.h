/*
 * Copyright (c) 2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef _UTIL_LIBP11_H
#define _UTIL_LIBP11_H

#include "libp11.h"
#include <openssl/ui.h>
#include <openssl/x509.h>

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   256

#ifdef _WIN32
#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7
#else
#include <syslog.h>
#include "config.h"
#endif

typedef struct engine_ctx_st ENGINE_CTX; /* opaque */

/* defined in util_uri.c */

typedef struct util_ctx_st UTIL_CTX;

struct util_ctx_st {
	/* Configuration */
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */
	UI_METHOD *ui_method;
	void *callback_data;

	/*
	 * The PIN used for login. Cache for the ctx_get_pin function.
	 * The memory for this PIN is always owned internally,
	 * and may be freed as necessary. Before freeing, the PIN
	 * must be whitened, to prevent security holes.
	 */
	char *pin;
	size_t pin_length;
	int forced_pin;
	int force_login;

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
};

UTIL_CTX *UTIL_CTX_new();

void UTIL_CTX_free(UTIL_CTX *ctx);

void UTIL_CTX_log(UTIL_CTX *ctx, int level, const char *format, ...);

int UTIL_CTX_set_pin(UTIL_CTX *ctx, const char *pin);

X509 *UTIL_CTX_get_cert_from_uri(UTIL_CTX *ctx, const char *object_uri);

EVP_PKEY *UTIL_CTX_get_pubkey_from_uri(UTIL_CTX *ctx, const char *s_key_id);

EVP_PKEY *UTIL_CTX_get_privkey_from_uri(UTIL_CTX *ctx, const char *s_key_id);

#endif /* _UTIL_LIBP11_H */

/* vim: set noexpandtab: */
