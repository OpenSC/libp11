/* crypto/engine/hw_pkcs11.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 * Copied/modified by Kevin Stefanik (kstef@mtppi.org) for the OpenSC
 * project 2003.
 * Copyright (c) 2016 Michał Trojnara
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
 * Portions Copyright (c) 2003 Kevin Stefanik (kstef@mtppi.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "engine.h"
#include <stdio.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/dso.h>
#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif

#define PKCS11_ENGINE_ID "pkcs11"
#define PKCS11_ENGINE_NAME "pkcs11 engine"

static int pkcs11_idx = -1;

/* The definitions for control commands specific to this engine */

/* need to add function to pass in reader id? or user reader:key as key id string? */

static const ENGINE_CMD_DEFN engine_cmd_defns[] = {
	{CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs11' engine shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_MODULE_PATH,
		"MODULE_PATH",
		"Specifies the path to the PKCS#11 module shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_PIN,
		"PIN",
		"Specifies the pin code",
		ENGINE_CMD_FLAG_STRING},
	{CMD_VERBOSE,
		"VERBOSE",
		"Print additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_QUIET,
		"QUIET",
		"Remove additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_LOAD_CERT_CTRL,
		"LOAD_CERT_CTRL",
		"Get the certificate from card",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_INIT_ARGS,
		"INIT_ARGS",
		"Specifies additional initialization arguments to the PKCS#11 module",
		ENGINE_CMD_FLAG_STRING},
	{CMD_PIN_GET_CALLBACK,
		"PIN_GET_CALLBACK",
		"Specifies a funtion pointer that returns the pin code for a given slot",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_PIN_DONE_CALLBACK,
		"PIN_DONE_CALLBACK",
		"Specifies a funtion pointer that returns a password that libp11 is done using",
		ENGINE_CMD_FLAG_INTERNAL},
	{0, NULL, NULL, 0}
};

static ENGINE_CTX *get_ctx(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	if (pkcs11_idx < 0) {
		pkcs11_idx = ENGINE_get_ex_new_index(0, "pkcs11", NULL, NULL, 0);
		if (pkcs11_idx < 0)
			return NULL;
		ctx = NULL;
	} else {
		ctx = ENGINE_get_ex_data(engine, pkcs11_idx);
	}
	if (ctx == NULL) {
		ctx = pkcs11_new();
		ENGINE_set_ex_data(engine, pkcs11_idx, ctx);
	}
	return ctx;
}

/* Destructor */
static int engine_destroy(ENGINE *engine)
{
	(void)engine;

	return 1;
}

static int engine_init(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return pkcs11_init(ctx);
}

static int engine_finish(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	rv = pkcs11_finish(ctx);
	ENGINE_set_ex_data(engine, pkcs11_idx, NULL);
	return rv;
}

static EVP_PKEY *load_pubkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return pkcs11_load_public_key(ctx, s_key_id, ui_method, callback_data);
}

static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return pkcs11_load_private_key(ctx, s_key_id, ui_method, callback_data);
}

static int engine_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return pkcs11_engine_ctrl(ctx, cmd, i, p, f);
}

/* This internal function is used by ENGINE_pkcs11() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, PKCS11_ENGINE_ID) ||
			!ENGINE_set_destroy_function(e, engine_destroy) ||
			!ENGINE_set_init_function(e, engine_init) ||
			!ENGINE_set_finish_function(e, engine_finish) ||
			!ENGINE_set_ctrl_function(e, engine_ctrl) ||
			!ENGINE_set_cmd_defns(e, engine_cmd_defns) ||
			!ENGINE_set_name(e, PKCS11_ENGINE_NAME) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, PKCS11_get_rsa_method()) ||
#endif
#if OPENSSL_VERSION_NUMBER  >= 0x10100002L
#ifndef OPENSSL_NO_EC
			/* PKCS11_get_ec_key_method combines ECDSA and ECDH */
			!ENGINE_set_EC(e, PKCS11_get_ec_key_method()) ||
#endif /* OPENSSL_NO_EC */
#else /* OPENSSL_VERSION_NUMBER */
#ifndef OPENSSL_NO_ECDSA
			!ENGINE_set_ECDSA(e, PKCS11_get_ecdsa_method()) ||
#endif
#ifndef OPENSSL_NO_ECDH
			!ENGINE_set_ECDH(e, PKCS11_get_ecdh_method()) ||
#endif
#endif /* OPENSSL_VERSION_NUMBER */
			!ENGINE_set_load_pubkey_function(e, load_pubkey) ||
			!ENGINE_set_load_privkey_function(e, load_privkey)) {
		return 0;
	} else {
		return 1;
	}
}

static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, PKCS11_ENGINE_ID) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

/* vim: set noexpandtab: */
