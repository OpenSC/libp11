/*
 * Copyright 1999-2001 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 * Portions Copyright (c) 2003 Kevin Stefanik (kstef@mtppi.org)
 * Copied/modified by Kevin Stefanik (kstef@mtppi.org) for the OpenSC
 * project 2003.
 * Copyright (c) 2016-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "engine.h"
#include <stdio.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
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
		"Specifies the PIN",
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
	{CMD_SET_USER_INTERFACE,
		"SET_USER_INTERFACE",
		"Set the global user interface (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_SET_CALLBACK_DATA,
		"SET_CALLBACK_DATA",
		"Set the global user interface extra data (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_FORCE_LOGIN,
		"FORCE_LOGIN",
		"Force login to the PKCS#11 module",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_RE_ENUMERATE,
		"RE_ENUMERATE",
		"re enumerate slots",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_VLOG_A,
		"VLOG_A",
		"Set the logging callback",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_DEBUG_LEVEL,
		"DEBUG_LEVEL",
		"Set the debug level: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice (default), 6=info, 7=debug",
		ENGINE_CMD_FLAG_NUMERIC},
	{CMD_KEYGEN,
		"KEYGEN",
		"Generate asymmetric key pair",
		ENGINE_CMD_FLAG_INTERNAL},
	{0, NULL, NULL, 0}
};

static int bind_helper_methods(ENGINE *e);

static ENGINE_CTX *ENGINE_CTX_get(ENGINE *engine)
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
	if (!ctx) {
		ctx = ENGINE_CTX_new();
		ENGINE_set_ex_data(engine, pkcs11_idx, ctx);
	}
	return ctx;
}

/* Destroy the context allocated with ENGINE_CTX_new() */
static int engine_destroy(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;

	rv &= ENGINE_CTX_destroy(ctx);
	ENGINE_set_ex_data(engine, pkcs11_idx, NULL);
	ERR_unload_ENG_strings();
	return rv;
}

static int engine_init(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;
	return ENGINE_CTX_init(ctx);
}

/* Finish engine operations initialized with ENGINE_CTX_init() */
static int engine_finish(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;

	rv &= ENGINE_CTX_finish(ctx);

	return rv;
}

static EVP_PKEY *load_pubkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *ui_data)
{
	ENGINE_CTX *ctx;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;
	bind_helper_methods(engine);
	return ENGINE_CTX_load_pubkey(ctx, s_key_id, ui_method, ui_data);
}

static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *ui_data)
{
	ENGINE_CTX *ctx;
	EVP_PKEY *pkey;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;
	bind_helper_methods(engine);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 * A workaround for an OpenSSL bug affecting the handling of foreign
	 * EVP_PKEY objects: https://github.com/openssl/openssl/pull/23063
	 * Affected OpenSSL versions:
	 *  - 3.0.12 (0x300000c0L) - 3.0.13 (0x300000d0L)
	 *  - 3.1.4 (0x30100040L) - 3.1.5 (0x30100050L)
	 *  - 3.2.0 (0x30200000L) - 3.2.1 (0x30200010L)
	 * This workaround may disrupt rare deployments
	 * that use foreign keys from multiple engines.
	 */
	{
		unsigned long ver = OpenSSL_version_num();

		if ((ver >= 0x300000c0L && ver <= 0x300000d0L) ||
				(ver >= 0x30100040L && ver <= 0x30100050L) ||
				(ver >= 0x30200000L && ver <= 0x30200010L)) {
			if (ENGINE_set_default_string(engine, "PKEY_CRYPTO")) {
				ENGINE_CTX_log(ctx, LOG_NOTICE, "Workaround for %s enabled\n",
					OpenSSL_version(OPENSSL_VERSION));
			} else {
				ENGINE_CTX_log(ctx, LOG_WARNING, "Failed to set PKEY_CRYPTO default engine\n");
			}
		}
	}
#endif
	pkey = ENGINE_CTX_load_privkey(ctx, s_key_id, ui_method, ui_data);
#ifdef EVP_F_EVP_PKEY_SET1_ENGINE
	/* EVP_PKEY_set1_engine() is required for OpenSSL 1.1.x,
	 * but otherwise setting pkey->engine breaks OpenSSL 1.0.2 */
	if (pkey && !EVP_PKEY_set1_engine(pkey, engine)) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
#endif /* EVP_F_EVP_PKEY_SET1_ENGINE */
	return pkey;
}

static int engine_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f) (void))
{
	ENGINE_CTX *ctx;

	ctx = ENGINE_CTX_get(engine);
	if (!ctx)
		return 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	bind_helper_methods(engine);
#endif
	return ENGINE_CTX_ctrl(ctx, cmd, i, p, f);
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
			!ENGINE_set_load_pubkey_function(e, load_pubkey) ||
			!ENGINE_set_load_privkey_function(e, load_privkey)) {
		return 0;
	} else {
		ERR_load_ENG_strings();
		return 1;
	}
}

/*
 * With OpenSSL 3.x, engines might be used because defined in openssl.cnf
 * which will cause problems
 * only add engine routines after a call to load keys
 */

static int bind_helper_methods(ENGINE *e)
{
	if (
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, PKCS11_get_rsa_method()) ||
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
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
			!ENGINE_set_pkey_meths(e, PKCS11_pkey_meths)) {
		return 0;
	} else {
		return 1;
	}
}

static int bind_fn(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, PKCS11_ENGINE_ID) != 0)) {
		ENGINE_CTX_log(NULL, LOG_ERR, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		ENGINE_CTX_log(NULL, LOG_ERR, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

/* vim: set noexpandtab: */
