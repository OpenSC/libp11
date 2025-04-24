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

#if defined(_WIN32) || defined(_WIN64)
#define strcasecmp _stricmp
#endif

/* defined in util_uri.c */
typedef struct util_ctx_st UTIL_CTX; /* opaque */

UTIL_CTX *UTIL_CTX_new(void);
void UTIL_CTX_free(UTIL_CTX *ctx);
int UTIL_CTX_set_module(UTIL_CTX *ctx, const char *module);
int UTIL_CTX_set_init_args(UTIL_CTX *ctx, const char *init_args);
int UTIL_CTX_set_ui_method(UTIL_CTX *ctx, UI_METHOD *ui_method, void *ui_data);
int UTIL_CTX_enumerate_slots(UTIL_CTX *ctx);
void UTIL_CTX_free_libp11(UTIL_CTX *ctx);

void UTIL_CTX_set_vlog_a(UTIL_CTX *ctx, PKCS11_VLOG_A_CB vlog);
void UTIL_CTX_set_debug_level(UTIL_CTX *ctx, int debug_level);
void UTIL_CTX_log(UTIL_CTX *ctx, int level, const char *format, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 3, 4)))
#endif
	;

int UTIL_CTX_set_pin(UTIL_CTX *ctx, const char *pin);
void UTIL_CTX_set_force_login(UTIL_CTX *ctx, int force_login);

X509 *UTIL_CTX_get_cert_from_uri(UTIL_CTX *ctx, const char *uri,
	UI_METHOD *ui_method, void *ui_data);
EVP_PKEY *UTIL_CTX_get_pubkey_from_uri(UTIL_CTX *ctx, const char *uri,
	UI_METHOD *ui_method, void *ui_data);
EVP_PKEY *UTIL_CTX_get_privkey_from_uri(UTIL_CTX *ctx, const char *uri,
	UI_METHOD *ui_method, void *ui_data);

int UTIL_CTX_keygen(UTIL_CTX *ctx, PKCS11_KGEN_ATTRS *kg_attrs);

#endif /* _UTIL_LIBP11_H */

/* vim: set noexpandtab: */
