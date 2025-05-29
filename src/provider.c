/*
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * This file contains the implementation of a PKCS#11 provider.
 * It is responsible for retrieving keys and certificates
 * using OpenSSL and a hardware security module (HSM) or token.
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

#ifndef _WIN32
#include "config.h"
#endif /* _WIN32 */

#include "util.h"

#include <ctype.h> /* isdigit() */

#if defined(_WIN32) && !defined(strncasecmp)
#define strncasecmp _strnicmp
#endif

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/store.h>

#define PKCS11_PROVIDER_NAME "libp11 PKCS#11 provider"

/* provider entry point (fixed name, exported) */
static OSSL_provider_init_fn provider_init;

#define PROVIDER_FN(name) static OSSL_FUNC_##name##_fn name
PROVIDER_FN(provider_teardown);
PROVIDER_FN(provider_gettable_params);
PROVIDER_FN(provider_get_params);
PROVIDER_FN(provider_query_operation);
PROVIDER_FN(provider_get_reason_strings);
PROVIDER_FN(store_open);
PROVIDER_FN(store_settable_ctx_params);
PROVIDER_FN(store_set_ctx_params);
PROVIDER_FN(store_load);
PROVIDER_FN(store_eof);
PROVIDER_FN(store_close);
#undef PROVIDER_FN

#ifndef OSSL_DISPATCH_END
#define OSSL_DISPATCH_END { 0, NULL }
#endif /* OSSL_DISPATCH_END */

static const OSSL_DISPATCH provider_functions[] = {
	{OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown},
	{OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params},
	{OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
	{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query_operation},
	{OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))provider_get_reason_strings},
	OSSL_DISPATCH_END
};

static const OSSL_DISPATCH store_functions[] = {
	{OSSL_FUNC_STORE_OPEN, (void (*)(void))store_open},
	{OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))store_settable_ctx_params},
	{OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))store_set_ctx_params},
	{OSSL_FUNC_STORE_LOAD, (void (*)(void))store_load},
	{OSSL_FUNC_STORE_EOF, (void (*)(void))store_eof},
	{OSSL_FUNC_STORE_CLOSE, (void (*)(void))store_close},
	OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM p11_storemgmt[] = {
	{"PKCS11", "provider=pkcs11", store_functions, "PKCS#11 storage functions"},
	{NULL, NULL, NULL, NULL}
};

typedef struct {
	char *pkcs11_module;
	char *pin;
	char *debug_level;
	char *force_login;
	char *init_args;
} PROVIDER_PARAMS;

typedef struct {
	/* provider configuration */
	const OSSL_CORE_HANDLE *handle;
	UTIL_CTX *util_ctx;
	PROVIDER_PARAMS params;
	int initialized;

	/* default core params */
	const char *openssl_version;
	char *provider_name;

	/* custom core params */
	char *pkcs11_module;
	char *init_args;
	char *pin;
	int debug_level;
	int force_login;
	char *p_debug_level;
	char *p_force_login;

	/* function offered by libcrypto to the provider */
	OSSL_FUNC_core_get_params_fn *core_get_params;
	OSSL_FUNC_core_new_error_fn *core_new_error;
	OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
	OSSL_FUNC_core_vset_error_fn *core_vset_error;
} PROVIDER_CTX;

typedef struct {
	PROVIDER_CTX *prov_ctx;
	char *uri;
	int expected_type;
	int types_tried;
} P11_STORE_CTX;

typedef struct {
	enum {
		is_expl_passphrase = 1, /* Explicit passphrase given by user */
		is_pem_password,        /* pem_password_cb given by user */
		is_ossl_passphrase,     /* OSSL_PASSPHRASE_CALLBACK given by user */
		is_ui_method            /* UI_METHOD given by user */
	} type;
	/* UI method data (only relevant if type == is_ui_method) */
	UI_METHOD *ui_method;
	void *ui_method_data;
} PASSPHRASE_DATA;

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

static void PROVIDER_CTX_log(PROVIDER_CTX *prov_ctx, int level, int reason, int line, const char *file, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (!prov_ctx) {
		vfprintf(stderr, format, args);
	} else if (level <= prov_ctx->debug_level) {
		if (level <= 3) { /* LOG_ERR */
			prov_ctx->core_new_error(prov_ctx->handle);
			prov_ctx->core_set_error_debug(prov_ctx->handle, OPENSSL_FILE, line, file);
			prov_ctx->core_vset_error(prov_ctx->handle, reason, format, args);
		} else if (level == 4) { /* LOG_WARNING */
			vfprintf(stderr, format, args);
		} else {
			vprintf(format, args);
		}
	}
	va_end(args);
}

/*
 * Updates the provider context with environment variable values.
 */
static void PROVIDER_CTX_get_environment_parameters(PROVIDER_CTX *prov_ctx)
{
	char *str;

	str = getenv("PKCS11_MODULE_PATH");
	if (str != NULL && str[0] != '\0') {
		OPENSSL_free(prov_ctx->pkcs11_module);
		prov_ctx->pkcs11_module = OPENSSL_strdup(str);
	}
	str = getenv("PKCS11_PIN");
	if (str != NULL && str[0] != '\0') {
		OPENSSL_free(prov_ctx->pin);
		prov_ctx->pin = OPENSSL_strdup(str);
	}
	str = getenv("PKCS11_DEBUG_LEVEL");
	if (str != NULL && str[0] != '\0') {
		OPENSSL_free(prov_ctx->p_debug_level);
		prov_ctx->p_debug_level = OPENSSL_strdup(str);
	}
	str = getenv("PKCS11_FORCE_LOGIN");
	if (str != NULL && str[0] != '\0') {
		OPENSSL_free(prov_ctx->p_force_login);
		prov_ctx->p_force_login = OPENSSL_strdup(str);
	}
}

/*
 * Retrieves provider-specific parameters. The parameters are returned by
 * reference, not as copies, and so the elements of the param array must have
 * OSSL_PARAM_UTF8_PTR as their data_type.
 */
static int PROVIDER_CTX_get_specific_parameters(PROVIDER_CTX *prov_ctx)
{
	int rv;
	PROVIDER_PARAMS params = {0};
	OSSL_PARAM specific_params[] = {
		{"pkcs11_module", OSSL_PARAM_UTF8_PTR, &params.pkcs11_module, 0, 0},
		{"pin", OSSL_PARAM_UTF8_PTR, &params.pin, 0, 0},
		{"debug_level", OSSL_PARAM_UTF8_PTR, &params.debug_level, 0, 0},
		{"force_login", OSSL_PARAM_UTF8_PTR, &params.force_login, 0, 0},
		{"init_args", OSSL_PARAM_UTF8_PTR, &params.init_args, 0, 0},
		OSSL_PARAM_END
	};

	if (!prov_ctx || !prov_ctx->handle || !prov_ctx->core_get_params)
		return 0;

	/* Retrieve provider-specific settings */
	rv = prov_ctx->core_get_params(prov_ctx->handle, specific_params);

	if (params.pkcs11_module && (!prov_ctx->params.pkcs11_module
		|| strcmp(params.pkcs11_module, prov_ctx->params.pkcs11_module))) {
		OPENSSL_free(prov_ctx->pkcs11_module);
		prov_ctx->pkcs11_module = OPENSSL_strdup(params.pkcs11_module);
	}
#ifdef DEFAULT_PKCS11_MODULE
	if (!prov_ctx->pkcs11_module) {
		prov_ctx->pkcs11_module = OPENSSL_strdup(DEFAULT_PKCS11_MODULE);
	}
#endif
	if (params.pin && (!prov_ctx->params.pin || strcmp(params.pin, prov_ctx->params.pin))) {
		OPENSSL_free(prov_ctx->pin);
		prov_ctx->pin = OPENSSL_strdup(params.pin);
	}
	if (params.debug_level && (!prov_ctx->params.debug_level
		|| strcmp(params.debug_level, prov_ctx->params.debug_level))) {
		OPENSSL_free(prov_ctx->p_debug_level);
		prov_ctx->p_debug_level = OPENSSL_strdup(params.debug_level);
	}
	if (params.force_login && (!prov_ctx->params.force_login
		|| strcmp(params.force_login, prov_ctx->params.force_login))) {
		OPENSSL_free(prov_ctx->p_force_login);
		prov_ctx->p_force_login = OPENSSL_strdup(params.force_login);
	}
	if (params.init_args && (!prov_ctx->params.init_args
		|| strcmp(params.init_args, prov_ctx->params.init_args))) {
		OPENSSL_free(prov_ctx->init_args);
		prov_ctx->init_args = OPENSSL_strdup(params.init_args);
	}
	return rv;
}

/*
 * Sets provider context parameters in the utility context.
 */
static int PROVIDER_CTX_set_parameters(PROVIDER_CTX *prov_ctx)
{
	/* Check required parameter */
	if (!prov_ctx->util_ctx) {
		return 0;
	}
	/* Get parameters from environment */
	PROVIDER_CTX_get_environment_parameters(prov_ctx);

	/* Overwrite provider-specific settings */
	if (!PROVIDER_CTX_get_specific_parameters(prov_ctx)) {
		return 0;
	}

	if (prov_ctx->p_debug_level && *prov_ctx->p_debug_level != '\0') {
		prov_ctx->debug_level = atoi(prov_ctx->p_debug_level);
	}
	UTIL_CTX_set_debug_level(prov_ctx->util_ctx, prov_ctx->debug_level);
	(void)UTIL_CTX_set_module(prov_ctx->util_ctx, prov_ctx->pkcs11_module);
	(void)UTIL_CTX_set_init_args(prov_ctx->util_ctx, prov_ctx->init_args);
	if (!UTIL_CTX_set_pin(prov_ctx->util_ctx, (const char *)prov_ctx->pin)) {
		return 0;
	}
	if (prov_ctx->p_force_login && *prov_ctx->p_force_login != '\0') {
		if (isdigit(*prov_ctx->p_force_login)) {
			prov_ctx->force_login = (atoi(prov_ctx->p_force_login) != 0);
		} else {
			prov_ctx->force_login = (strcasecmp("true", prov_ctx->p_force_login) == 0
				|| strcasecmp("yes", prov_ctx->p_force_login) == 0);
		}
	}
	if (prov_ctx->force_login) {
		UTIL_CTX_set_force_login(prov_ctx->util_ctx, 1);
	}
	return 1;
}

/******************************************************************************/
/* Provider init helper functions                                             */
/******************************************************************************/

static PROVIDER_CTX *PROVIDER_CTX_new(void)
{
	PROVIDER_CTX *prov_ctx = OPENSSL_zalloc(sizeof(PROVIDER_CTX));

	if (!prov_ctx)
		return NULL;

	prov_ctx->util_ctx = UTIL_CTX_new();
	if (!prov_ctx->util_ctx) {
		OPENSSL_free(prov_ctx);
		return NULL;
	}
	prov_ctx->initialized = 0;
	memset(&prov_ctx->params, 0, sizeof(PROVIDER_PARAMS));
	/* Logging */
	prov_ctx->debug_level = LOG_NOTICE;

	return prov_ctx;
}

/*
 * Frees all resources associated with a provider context.
 */
static void PROVIDER_CTX_destroy(PROVIDER_CTX *prov_ctx)
{
	UTIL_CTX_free_libp11(prov_ctx->util_ctx);
	UTIL_CTX_free(prov_ctx->util_ctx);
	OPENSSL_free(prov_ctx->provider_name);
	OPENSSL_free(prov_ctx->pkcs11_module);
	OPENSSL_free(prov_ctx->pin);
	OPENSSL_free(prov_ctx->p_debug_level);
	OPENSSL_free(prov_ctx->p_force_login);
	OPENSSL_free(prov_ctx->init_args);
	OPENSSL_free(prov_ctx);
}

/*
 * Retrieves function pointers provided by the OpenSSL core.
 */
static void PROVIDER_CTX_get_core_functions(PROVIDER_CTX *prov_ctx, const OSSL_DISPATCH *in)
{
	for (; in->function_id != 0; in++) {
		switch (in->function_id) {
		case OSSL_FUNC_CORE_GET_PARAMS:
			prov_ctx->core_get_params = OSSL_FUNC_core_get_params(in);
			break;
		case OSSL_FUNC_CORE_NEW_ERROR:
			prov_ctx->core_new_error = OSSL_FUNC_core_new_error(in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			prov_ctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			prov_ctx->core_vset_error = OSSL_FUNC_core_vset_error(in);
			break;
		default:
			/* Just ignore anything we don't understand */
			break;
		}
	}
}

/*
 * Retrieves parameters provided by the core and deep copy of global configuration
 * parameters associated with provider. The parameters are returned by
 * reference, not as copies, and so the elements of the param array must have
 * OSSL_PARAM_UTF8_PTR as their data_type.
 */
static int PROVIDER_CTX_get_core_parameters(PROVIDER_CTX *prov_ctx)
{
	int rv;
	OSSL_PARAM core_params[] = {
		{OSSL_PROV_PARAM_CORE_VERSION, OSSL_PARAM_UTF8_PTR, &prov_ctx->openssl_version, 0, 0},
		{OSSL_PROV_PARAM_CORE_PROV_NAME, OSSL_PARAM_UTF8_PTR, &prov_ctx->provider_name, 0, 0},
		{"pkcs11_module", OSSL_PARAM_UTF8_PTR, &prov_ctx->params.pkcs11_module, 0, 0},
		{"pin", OSSL_PARAM_UTF8_PTR, &prov_ctx->params.pin, 0, 0},
		{"debug_level", OSSL_PARAM_UTF8_PTR, &prov_ctx->params.debug_level, 0, 0},
		{"force_login", OSSL_PARAM_UTF8_PTR, &prov_ctx->params.force_login, 0, 0},
		{"init_args", OSSL_PARAM_UTF8_PTR, &prov_ctx->params.init_args, 0, 0},
		OSSL_PARAM_END
	};

	if (!prov_ctx || !prov_ctx->handle || !prov_ctx->core_get_params)
		return 0;

	/* Retrieve core default parameters */
	rv = prov_ctx->core_get_params(prov_ctx->handle, core_params);

	if (prov_ctx->provider_name) {
		char *buffer = OPENSSL_zalloc(strlen(PKCS11_PROVIDER_NAME) + strlen(prov_ctx->provider_name) + 4);

		if (buffer) {
			sprintf(buffer, "%s (%s)", PKCS11_PROVIDER_NAME, prov_ctx->provider_name);
			prov_ctx->provider_name = buffer;
		}
	}
	if (!prov_ctx->provider_name) {
		prov_ctx->provider_name = OPENSSL_strdup(PKCS11_PROVIDER_NAME);
	}
	/*
	 * Duplicate string parameters in the provider context.
	 * Ensures that dynamically allocated copies of the original strings
	 * are created using OPENSSL_strdup().
	 * This prevents unintended modifications to the original input strings
	 * and ensures proper memory management within the provider context.
	 */
	if (prov_ctx->params.pkcs11_module) {
		prov_ctx->pkcs11_module = OPENSSL_strdup(prov_ctx->params.pkcs11_module);
	}
	if (prov_ctx->params.pin) {
		prov_ctx->pin = OPENSSL_strdup(prov_ctx->params.pin);
	}
	if (prov_ctx->params.debug_level) {
		prov_ctx->p_debug_level = OPENSSL_strdup(prov_ctx->params.debug_level);
	}
	if (prov_ctx->params.force_login) {
		prov_ctx->p_force_login = OPENSSL_strdup(prov_ctx->params.force_login);
	}
	if (prov_ctx->params.init_args) {
		prov_ctx->init_args = OPENSSL_strdup(prov_ctx->params.init_args);
	}
	return rv;
}

/******************************************************************************/
/* Load and initialize a provider                                             */
/******************************************************************************/

/*
 * This is the only directly exposed function of the provider.
 * When OpenSSL loads the library, this function gets called.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
	const OSSL_DISPATCH **out, void **ctx)
{
	return provider_init(handle, in, out, ctx);
}

static int provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
	const OSSL_DISPATCH **out, void **ctx)
{
	PROVIDER_CTX *prov_ctx = NULL;

	/*  Create a context */
	prov_ctx = PROVIDER_CTX_new();
	if (!prov_ctx)
		goto err;

	/* Save core handle */
	prov_ctx->handle = handle;

	/* Get all core functions and check existence of required ones */
	PROVIDER_CTX_get_core_functions(prov_ctx, in);

	/* Get core default parameters */
	if (!PROVIDER_CTX_get_core_parameters(prov_ctx))
		goto err;

	/* Init successful */
	*out = provider_functions;
	*ctx = prov_ctx;

	return 1;

err:
	provider_teardown(prov_ctx);
	return 0;
}


/******************************************************************************/
/* Provider functions                                                         */
/******************************************************************************/

/*
 * Cleans of provider related stuff.
 */
static void provider_teardown(void *ctx)
{
	PROVIDER_CTX *prov_ctx = (PROVIDER_CTX *)ctx;

	if (!prov_ctx)
		return;

	PROVIDER_CTX_destroy(prov_ctx);
	ERR_clear_error();
}

/*
 * Returns a constant array of descriptor OSSL_PARAM, for parameters that
 * provider_get_params() can handle.
 */
static const OSSL_PARAM *provider_gettable_params(void *ctx)
{
	static const OSSL_PARAM gettable_params[] = {
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
		OSSL_PARAM_END
	};

	if (!ctx)
		return NULL;

	return gettable_params;
}

/*
 * Process the OSSL_PARAM array params, setting the values of the parameters it
 * understands. OSSL_PROVIDER_get_params() is used to get these parameter values
 * from the provider.
 */
static int provider_get_params(void *ctx, OSSL_PARAM params[])
{
	PROVIDER_CTX *prov_ctx = (PROVIDER_CTX *)ctx;
	OSSL_PARAM *p;

	if (!prov_ctx || !params)
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, prov_ctx->provider_name))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, prov_ctx->openssl_version))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;

	return 1;
}

/*
 * Returns the defined operations based on the operation_id value. Possible
 * list of operations are defined by OpenSSL3. This library defines only a
 * subset.
 */
static const OSSL_ALGORITHM *provider_query_operation(void *ctx,
		int operation_id, int *no_store)
{
	(void)ctx;
	*no_store = 0;
	if (operation_id == OSSL_OP_STORE) {
		return p11_storemgmt;
	}
	return NULL;
}

/*
 * Returns a constant reason_strings[] array that provides reason strings for
 * reason codes the provider may use when reporting errors using core_put_error().
 */
static const OSSL_ITEM *provider_get_reason_strings(void *ctx)
{
	static const OSSL_ITEM reason_strings[] = {
		{1, "Memory allocation failed"},
		{2, "Failed to set provider parameters"},
		{3, "Failed to retrieve OSSL_STORE_PARAM_EXPECT"},
		{4, "Failed to encode X.509 certificate"},
		{5, "No object available for OSSL_STORE_INFO"},
		{0, NULL} /* Sentinel value */
	};

	(void)ctx;
	return reason_strings;
}


/******************************************************************************/
/* Store functions                                                            */
/******************************************************************************/

/*
 * Creates a provider-side context with data based on the given URI.
 */
static void *store_open(void *ctx, const char *uri)
{
	P11_STORE_CTX *store_ctx;
	PROVIDER_CTX *prov_ctx = (PROVIDER_CTX *)ctx;

	if (!uri || strncasecmp(uri, "pkcs11:", 7) != 0) {
		return NULL; /* This provider doesn't handle this URI */
	}
	if (!prov_ctx->initialized) {
		/* Set parameters into the util_ctx */
		if (!PROVIDER_CTX_set_parameters(prov_ctx)) {
			PROVIDER_CTX_log(prov_ctx, LOG_ERR, 2, OPENSSL_LINE, OPENSSL_FUNC, NULL);
			return NULL;
		}
	}
	prov_ctx->initialized = 1;

	store_ctx = OPENSSL_zalloc(sizeof(P11_STORE_CTX));
	if (!store_ctx) {
		PROVIDER_CTX_log(prov_ctx, LOG_ERR, 1, OPENSSL_LINE, OPENSSL_FUNC, NULL);
		return NULL;
	}
	store_ctx->prov_ctx = prov_ctx;
	store_ctx->uri = OPENSSL_strdup(uri);
	store_ctx->types_tried = 0;
	return store_ctx;
}

/*
 * Returns a constant array of descriptor OSSL_PARAM(3), for parameters that
 * p11_store_set_ctx_params() can handle.
 */
static const OSSL_PARAM *store_settable_ctx_params(void *ctx)
{
	static const OSSL_PARAM settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
		OSSL_PARAM_END
	};

	(void)(ctx);
	return settable_ctx_params;
}

/*
 * Sets additional parameters, such as what kind of data to expect.
 */
static int store_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *param;
	P11_STORE_CTX *store_ctx = (P11_STORE_CTX *)ctx;

	if (!store_ctx)
		return 0;

	/* passing NULL for params returns true */
	if (!params || !params->key)
		return 1;

	param = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
	if (param != NULL && !OSSL_PARAM_get_int(param, &store_ctx->expected_type)) {
		PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 3, OPENSSL_LINE, OPENSSL_FUNC, NULL);
		return 0;
	}

	return 1;
}

/*
 * Loads the next object from the URI opened by store_open(),
 * creates an object abstraction for it (see provider-object(7)),
 * and calls object_cb with it as well as object_cbarg.
 * object_cb will then interpret the object abstraction and do what it can
 * to wrap it or decode it into an OpenSSL structure.
 * In case a passphrase needs to be prompted to unlock an object, pw_cb should be called.
 * If no expected_type is provided, the store now sequentially attempts to fetch
 * a private key, then a public key, and finally a certificate. This ensures that
 * all object types are considered when expected_type is not explicitly defined.
 */
static int store_load(void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg,
		OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	P11_STORE_CTX *store_ctx;
	UI_METHOD *ui_method;
	void *ui_data;
	PASSPHRASE_DATA *pass_data = (PASSPHRASE_DATA *)pw_cbarg;
	struct ossl_load_result_data_st {
		OSSL_STORE_INFO *v; /* to be filled in */
		OSSL_STORE_CTX *store_ctx;
	} *cbdata = object_cbarg;

	(void)pw_cb;

	store_ctx = (P11_STORE_CTX *)ctx;
	if (!store_ctx)
		return 0;

	if (pass_data && pass_data->type == is_ui_method) {
		ui_method = pass_data->ui_method;
		ui_data = pass_data->ui_method_data;
	} else {
		/* using the current default UI method */
		ui_method = NULL;
		ui_data = NULL;
		PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_WARNING, 0, 0, 0,
			"No custom UI method provided, using the default UI method.\n");
	}

	/* try fetching a private key */
	if (store_ctx->types_tried == 0) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type == OSSL_STORE_INFO_PKEY) {
			EVP_PKEY *key = UTIL_CTX_get_privkey_from_uri(store_ctx->prov_ctx->util_ctx,
				store_ctx->uri, ui_method, ui_data);

			UTIL_CTX_set_ui_method(store_ctx->prov_ctx->util_ctx, ui_method, NULL);
			if (key != NULL) {
				/* Workaround for EVP_PKEY without key management, needed since
				 * ossl_store_handle_load_result() doesn't support this case. */
				cbdata->v = OSSL_STORE_INFO_new_PKEY(key);
				return 1;
			}
		}
	}
	/* try fetching a public key */
	if (store_ctx->types_tried == 1) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type == OSSL_STORE_INFO_PUBKEY) {
			EVP_PKEY *key = UTIL_CTX_get_pubkey_from_uri(store_ctx->prov_ctx->util_ctx,
				store_ctx->uri, ui_method, ui_data);

			if (key != NULL) {
				cbdata->v = OSSL_STORE_INFO_new_PUBKEY(key);
				return 1;
			}
		}
	}
	/* try fetching a certificate  */
	if (store_ctx->types_tried == 2) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type ==  OSSL_STORE_INFO_CERT) {
			X509 *cert = UTIL_CTX_get_cert_from_uri(store_ctx->prov_ctx->util_ctx,
				store_ctx->uri, ui_method, ui_data);

			if (cert != NULL) {
				/* If we have a data type, it should be a PEM name */
				const char *data_type = "PEM_STRING_X509";
				int object_type = OSSL_OBJECT_CERT;
				unsigned char *tmp, *data = NULL;
				OSSL_PARAM params[4], *p = params;
				int len = i2d_X509(cert, NULL);

				if (len < 0) {
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 4, OPENSSL_LINE, OPENSSL_FUNC, store_ctx->uri);
					X509_free(cert);
					return 0;
				}
				tmp = data = OPENSSL_malloc((size_t)len);
				if (!tmp) {
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 1, OPENSSL_LINE, OPENSSL_FUNC, store_ctx->uri);
					X509_free(cert);
					return 0;
				}
				i2d_X509(cert, &tmp);
				X509_free(cert);

				*p++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, data, (size_t)len);
				*p = OSSL_PARAM_construct_end();

				if (!object_cb(params, object_cbarg)) {
					/* callback failed */
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 5, OPENSSL_LINE, OPENSSL_FUNC, store_ctx->uri);
					OPENSSL_free(data);
					return 0;
				}
				OPENSSL_free(data);
				return 1;
			}
		}
	}
	return 0;
}

/*
 * Indicates whether all expected objects from the URI have been processed.
 * The expected sequence is: a private key, a public key, and a certificate.
 * Once the counter reaches 3, all objects have been handled, making further
 * loading attempts unnecessary.
 */
static int store_eof(void *ctx)
{
	P11_STORE_CTX *store_ctx = (P11_STORE_CTX *)ctx;

	if (!store_ctx)
		return 0;

	return store_ctx->types_tried >= 3;
}

/*
 * Frees the provider side context.
 */
static int store_close(void *ctx)
{
	P11_STORE_CTX *store_ctx = (P11_STORE_CTX *)ctx;

	if (!store_ctx)
		return 0;

	OPENSSL_free(store_ctx->uri);
	OPENSSL_free(store_ctx);
	return 1;
}

/* vim: set noexpandtab: */
