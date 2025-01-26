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

#include <openssl/x509.h>

typedef struct st_engine_ctx ENGINE_CTX; /* opaque */

/* defined in util_uri.c */

X509 *util_get_cert_from_uri(ENGINE_CTX *ctx, const char *object_uri,
	UI_METHOD *ui_method, void *callback_data);

EVP_PKEY *util_get_pubkey_from_uri(ENGINE_CTX *ctx, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data);

EVP_PKEY *util_get_privkey_from_uri(ENGINE_CTX *ctx, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data);

/* TODO: move the following code back to eng_back.c as soon as
 * all references to those fields are removed from util_uri.c */
#include "engine.h"
#include "p11_pthread.h"
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
	int debug_level;                             /* level of debug output */
	void (*vlog)(int, const char *, va_list); /* for the logging callback */
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

/* vim: set noexpandtab: */
