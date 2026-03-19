/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
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

#include "provider_helpers.h"
#include <ctype.h> /* isdigit() */

#if defined(__GNUC__) || defined(__clang__)
#define DISABLE_OSSL3_DEPRECATED_BEGIN \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#define DISABLE_OSSL3_DEPRECATED_END \
	_Pragma("GCC diagnostic pop")
#else
#define DISABLE_OSSL3_DEPRECATED_BEGIN
#define DISABLE_OSSL3_DEPRECATED_END
#endif

#define PKCS11_PROVIDER_NAME "libp11 PKCS#11 provider"

typedef struct {
	char *pkcs11_module;
	char *pin;
	char *debug_level;
	char *force_login;
	char *init_args;
} PROVIDER_PARAMS;

struct provider_ctx {
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
};

typedef struct p11_pub_key_st {
	unsigned char *pub; /* set via keymgmt_import() */
	size_t pub_len;
} P11_PUB_KEY;

typedef struct p11_rsa_pub_st {
	unsigned char *n;
	size_t n_len;
	unsigned char *e;
	size_t e_len;
} P11_RSA_PUB;

typedef struct p11_ec_pub_st {
	char *group_name;
	unsigned char *pub;
	size_t pub_len;
} P11_EC_PUB;

typedef struct p11_eddsa_pub_st {
	unsigned char *pub; /* optional raw 32/57-byte public key */
	size_t pub_len;
} P11_EDDSA_PUB;

typedef union p11_pubdata_u {
	P11_RSA_PUB rsa;
	P11_EC_PUB ec;
	P11_EDDSA_PUB eddsa;
} P11_PUBDATA;

struct p11_keydata_st {
	PROVIDER_CTX *prov_ctx;
	int refcnt;
	CRYPTO_RWLOCK *lock;
	int type; /* EVP_PKEY_RSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_ED448 */
	const char *name; /* "RSA", "EC", "ED25519", "ED448" */
	int is_private;
	EVP_PKEY *pkey; /* optional cache */
	size_t keysize; /* bytes: RSA modulus, EC field/order bytes, EdDSA key bytes */
	size_t sigsize; /* bytes if fixed-size signature (RSA/EdDSA), else 0 */
	OSSL_PARAM *params; /* owned by this struct; free with OSSL_PARAM_free() */
	P11_PUB_KEY *pubkey; /* optional raw public key */
	P11_PUBDATA pubdata; /* data for keymgmt_export() */
};

struct p11_store_ctx_st {
	PROVIDER_CTX *prov_ctx;
	char *uri;
	int expected_type;
	int types_tried;
};

struct p11_signature_ctx {
	PROVIDER_CTX *prov_ctx;
	char *propq;
	P11_KEYDATA *keydata;
	char *mdname;      /* digest name (RSA/ECDSA); NULL for EdDSA */
	EVP_MD_CTX *mdctx; /* digest state for DigestSignUpdate/Final */
	int pad_mode;      /* RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING */
	int pss_saltlen;   /* RSA_PSS_SALTLEN_* or >=0 explicit */
	char *mgf1_mdname; /* optional, default = mdname */
};

struct p11_asym_cipher_ctx {
	PROVIDER_CTX *prov_ctx;
	P11_KEYDATA *keydata;
	int pad_mode;      /* RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING */
	char *oaep_mdname; /* optional, default = SHA1 in many PKCS#11/OpenSSL flows */
	char *mgf1_mdname; /* optional, default = oaep_mdname */
	unsigned char *oaep_label;
	size_t oaep_labellen;
};

/* Internal helper functions */
static void PROVIDER_CTX_get_environment_parameters(PROVIDER_CTX *prov_ctx);
static int PROVIDER_CTX_get_specific_parameters(PROVIDER_CTX *prov_ctx);

static EVP_PKEY *pubkey_from_params_default(P11_KEYDATA *keydata);
static EVP_PKEY *p11_keydata_get_evp_pkey(P11_KEYDATA *keydata);
static int p11_keydata_set_pub(P11_KEYDATA *keydata, const void *buf, size_t len);
static OSSL_PARAM *public_params_from_evp_pkey(EVP_PKEY *pkey);
static int p11_keydata_init_from_params(P11_KEYDATA *keydata);
static int p11_keydata_replace_params(P11_KEYDATA *keydata, OSSL_PARAM *params);
static int algorithm_from_ossl_param(const OSSL_PARAM *params);
static int params_contains_private_key(const OSSL_PARAM *params);
static int param_blob_equal(const OSSL_PARAM *a, const OSSL_PARAM *b);
static int rsa_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
#ifndef OPENSSL_NO_EC
static int p11_dup_param_utf8(const OSSL_PARAM *p, char **out);
static int ec_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
static int ec_point_equal_by_value(const char *group_name,
	const unsigned char *a, size_t alen, const unsigned char *b, size_t blen);
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ECX
static int eddsa_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
static int octet_equal(const OSSL_PARAM *a, const OSSL_PARAM *b);
#endif /* OPENSSL_NO_ECX */
static void p11_keydata_clear_pubdata(P11_KEYDATA *keydata);
static int p11_dup_param_blob(const OSSL_PARAM *p, unsigned char **out, size_t *out_len);


/******************************************************************************/
/* Provider helper API                                                        */
/******************************************************************************/

#ifdef __GNUC__
	__attribute__((format(printf, 6, 7)))
#endif
void PROVIDER_CTX_log(PROVIDER_CTX *prov_ctx, int level, int reason, int line, const char *file, const char *format, ...)
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

/* Allocate and initialize provider context. */
PROVIDER_CTX *PROVIDER_CTX_new(void)
{
	PROVIDER_CTX *prov_ctx = OPENSSL_zalloc(sizeof(PROVIDER_CTX));

	if (!prov_ctx)
		return NULL;

	prov_ctx->util_ctx = UTIL_CTX_new(PKCS11_FLAG_NO_METHODS);
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

/* Free all resources associated with a provider context. */
void PROVIDER_CTX_destroy(PROVIDER_CTX *prov_ctx)
{
	if (!prov_ctx)
		return;

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

/* Retrieve and store core function pointers from dispatch table. */
void PROVIDER_CTX_get_core_functions(PROVIDER_CTX *prov_ctx, const OSSL_DISPATCH *in)
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
 * Retrieve parameters provided by the core and deep copy of global configuration
 * parameters associated with provider. The parameters are returned by
 * reference, not as copies, and so the elements of the param array must have
 * OSSL_PARAM_UTF8_PTR as their data_type.
 */
int PROVIDER_CTX_get_core_parameters(PROVIDER_CTX *prov_ctx)
{
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
	if (!prov_ctx->core_get_params(prov_ctx->handle, core_params))
		return 0;

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
	return 1;
}

/* Set provider core handle. */
void PROVIDER_CTX_set_handle(PROVIDER_CTX *prov_ctx, const OSSL_CORE_HANDLE *handle)
{
	prov_ctx->handle = handle;
}

/* Set provider name. */
int PROVIDER_CTX_set_provider_name(OSSL_PARAM *p, PROVIDER_CTX *prov_ctx)
{
	return OSSL_PARAM_set_utf8_ptr(p, prov_ctx->provider_name);
}

/* Set openssl version .*/
int PROVIDER_CTX_set_openssl_version(OSSL_PARAM *p, PROVIDER_CTX *prov_ctx)
{
	return OSSL_PARAM_set_utf8_ptr(p, prov_ctx->openssl_version);
}

/* Set provider context parameters in the utility context. */
int PROVIDER_CTX_set_parameters(PROVIDER_CTX *prov_ctx)
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

/* Return whether provider context is initialized. */
int PROVIDER_CTX_is_initialized(PROVIDER_CTX *prov_ctx)
{
	return prov_ctx->initialized;
}

/* Mark provider context as initialized. */
void PROVIDER_CTX_initialize(PROVIDER_CTX *prov_ctx)
{
	prov_ctx->initialized = 1;
}

/* Retrieve X509 certificate from URI using provider utility context. */
X509 *PROVIDER_CTX_get_cert_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data)
{
	return UTIL_CTX_get_cert_from_uri(prov_ctx->util_ctx, uri, ui_method, ui_data);
}

/* Retrieve public key from URI using provider utility context. */
EVP_PKEY *PROVIDER_CTX_get_pubkey_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data)
{
	return UTIL_CTX_get_pubkey_from_uri(prov_ctx->util_ctx, uri, ui_method, ui_data);
}

/* Retrieve private key from URI using provider utility context. */
EVP_PKEY *PROVIDER_CTX_get_privkey_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data)
{
	return UTIL_CTX_get_privkey_from_uri(prov_ctx->util_ctx, uri, ui_method, ui_data);
}

/* Set UI method and associated data for provider operations. */
int PROVIDER_CTX_set_ui_method(PROVIDER_CTX *prov_ctx, UI_METHOD *ui_method, void *ui_data)
{
	return UTIL_CTX_set_ui_method(prov_ctx->util_ctx, ui_method, ui_data);
}


/******************************************************************************/
/* KEYMGMT helper functions                                                  */
/******************************************************************************/

/* Create and initialize P11_KEYDATA structure with refcount and lock. */
P11_KEYDATA *p11_keydata_new(PROVIDER_CTX *ctx)
{
	P11_KEYDATA *keydata = OPENSSL_zalloc(sizeof(P11_KEYDATA));
	if (keydata == NULL)
		return NULL;

	keydata->refcnt = 1;
	keydata->lock = CRYPTO_THREAD_lock_new();
	if (keydata->lock == NULL) {
		OPENSSL_free(keydata);
		return NULL;
	}
	keydata->prov_ctx = ctx;
	return keydata;
}

/* Increment the reference count of a P11_KEY. */
int p11_keydata_up_ref(P11_KEYDATA *keydata)
{
	if (keydata == NULL || keydata->lock == NULL)
		return 0;

	if (!CRYPTO_THREAD_write_lock(keydata->lock))
		return 0;

	keydata->refcnt++;

	CRYPTO_THREAD_unlock(keydata->lock);
	return 1;
}

/* Decrement refcount and free the key when it reaches zero. */
void p11_keydata_free(P11_KEYDATA *keydata)
{
	int ref = 0;

	if (keydata == NULL)
		return;

	if (!CRYPTO_THREAD_write_lock(keydata->lock))
		return;

	ref = --keydata->refcnt;
	CRYPTO_THREAD_unlock(keydata->lock);

	if (ref > 0)
		return;

	OSSL_PARAM_free(keydata->params);
	EVP_PKEY_free(keydata->pkey);

	switch (keydata->type) {
	case EVP_PKEY_RSA:
		OPENSSL_free(keydata->pubdata.rsa.n);
		OPENSSL_free(keydata->pubdata.rsa.e);
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		OPENSSL_free(keydata->pubdata.ec.group_name);
		OPENSSL_free(keydata->pubdata.ec.pub);
		break;
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		OPENSSL_free(keydata->pubdata.eddsa.pub);
		break;
#endif /* OPENSSL_NO_ECX */
	default:
		break;
	}

	if (keydata->pubkey != NULL) {
		OPENSSL_free(keydata->pubkey->pub);
		OPENSSL_free(keydata->pubkey);
	}

	CRYPTO_THREAD_lock_free(keydata->lock);
	OPENSSL_free(keydata);
}

/* Create keydata object from EVP_PKEY and initialize key metadata. */
P11_KEYDATA *p11_keydata_from_evp_pkey(PROVIDER_CTX *ctx, EVP_PKEY *pkey, int is_private)
{
	P11_KEYDATA *keydata = NULL;

	if (pkey == NULL)
		return NULL;

	keydata = p11_keydata_new(ctx);
	if (keydata == NULL)
		goto err;

	keydata->type = EVP_PKEY_base_id(pkey);
	keydata->is_private = is_private;

	/* optional, params may be unavailable for some private keys */
	keydata->params = public_params_from_evp_pkey(pkey);
	if (keydata->params != NULL && p11_keydata_init_from_params(keydata) != 1)
		goto err;

	/* take our own reference before storing the pointer */
	if (EVP_PKEY_up_ref(pkey) != 1)
		goto err;

	keydata->pkey = pkey;
	return keydata;

err:
	p11_keydata_free(keydata);
	return NULL;
}

/* Return key name associated with keydata. */
const char *p11_keydata_get_name(P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return NULL;

	return keydata->name;
}

/* Get stored raw public key data. */
int p11_keydata_get_pub(const P11_KEYDATA *keydata, unsigned char **buf, size_t *len)
{
	const P11_PUB_KEY *pubkey;

	if (keydata == NULL || buf == NULL || len == NULL)
		return 0;

	pubkey = keydata->pubkey;
	if (pubkey == NULL || pubkey->pub == NULL || pubkey->pub_len == 0)
		return 0;

	*buf = pubkey->pub;
	*len = pubkey->pub_len;
	return 1;
}

/* Return whether keydata represents a private key. */
int p11_keydata_is_private(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return 0;

	return keydata->is_private;
}

#if OPENSSL_VERSION_NUMBER >= 0x30600000L
/* Map security bits to security category level. */
int p11_keydata_get_security_category(const P11_KEYDATA *keydata)
{
	int secbits = p11_keydata_get_security_bits(keydata);

	if (secbits >= 256)
		return 5;
	if (secbits >= 192)
		return 4;
	if (secbits >= 128)
		return 3;
	if (secbits >= 112)
		return 2;
	if (secbits >= 80)
		return 1;
	return 0;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */

/* Return estimated security strength in bits based on key type and size. */
int p11_keydata_get_security_bits(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return 0;

	switch (keydata->type) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		/* rough mapping for common RSA sizes */
		switch ((int)(keydata->keysize * 8)) {
		case 1024:
			return 80;
		case 2048:
			return 112;
		case 3072:
			return 128;
		case 4096:
			return 152;
		default:
			return 0;
		}
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		switch ((int)(keydata->keysize * 8)) {
		case 256:
			return 128;
		case 384:
			return 192;
		case 521:
		case 528: /* if keysize rounded to 66 bytes */
			return 256;
		default:
			return 0;
		}
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_ED25519:
		return 128;

	case EVP_PKEY_ED448:
		return 224;
#endif /* OPENSSL_NO_ECX */
	default:
		return 0;
	}
}

/* Return key size in bits. */
int p11_keydata_get_bits(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return 0;

	return (int)(keydata->keysize * 8);
}

/* Return maximum signature or operation size in bytes. */
size_t p11_keydata_get_sigsize(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return 0;

	return keydata->sigsize;
}

/*
 * Return key type identifier:
 * EVP_PKEY_RSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_ED448
 */
int p11_keydata_get_type(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return 0;

	return keydata->type;
}

/* Return stored OSSL_PARAM array associated with key object. */
OSSL_PARAM *p11_keydata_get_params(const P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return NULL;

	return keydata->params;
}

/* Duplicate and set key parameters, extracting and storing public key data if present. */
int p11_keydata_set_params(P11_KEYDATA *key, const OSSL_PARAM *params)
{
	const OSSL_PARAM *p;
	const void *pub = NULL;
	size_t publen = 0;
	OSSL_PARAM *dup;

	if (key == NULL || params == NULL)
		return 0;

	dup = OSSL_PARAM_dup(params);
	if (dup == NULL)
		return 0;

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
	if (p != NULL) {

		if (!OSSL_PARAM_get_octet_string_ptr(p, &pub, &publen) ||
			pub == NULL || publen == 0 ||
			!p11_keydata_set_pub(key, pub, publen)) {
			OSSL_PARAM_free(dup);
			return 0;
		}
	}
	return p11_keydata_replace_params(key, dup);
}

/* Compare two keys by public parameters, based on the key type. */
int p11_public_equal(const P11_KEYDATA *k1, const P11_KEYDATA *k2)
{
	if (k1 == NULL || k2 == NULL || k1->params == NULL || k2->params == NULL)
		return 0;

	if (k1->type != k2->type)
		return 0;

	switch (k1->type) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		return rsa_public_match_params(k1->params, k2->params);
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return ec_public_match_params(k1->params, k2->params);
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		return eddsa_public_match_params(k1->params, k2->params);
#endif /* OPENSSL_NO_ECX */
	default:
		return 0;
	}
}

/* Parse RSA padding mode from OSSL_PARAM (integer or string). */
int pad_mode_from_param(const OSSL_PARAM *p, int *pad_mode)
{
	if (p == NULL || pad_mode == NULL)
		return 0;

	if (p->data_type == OSSL_PARAM_INTEGER) {
		return OSSL_PARAM_get_int(p, pad_mode);
	}

	if (p->data_type == OSSL_PARAM_UTF8_STRING) {
		const char *s = NULL;

		if (!OSSL_PARAM_get_utf8_string_ptr(p, &s) || s == NULL)
			return 0;

		if (OPENSSL_strcasecmp(s, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
			*pad_mode = RSA_PKCS1_PADDING;
		else if (OPENSSL_strcasecmp(s, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
			*pad_mode = RSA_NO_PADDING;
		else if (OPENSSL_strcasecmp(s, OSSL_PKEY_RSA_PAD_MODE_X931) == 0)
			*pad_mode = RSA_X931_PADDING;
		else if (OPENSSL_strcasecmp(s, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
			*pad_mode = RSA_PKCS1_PSS_PADDING;
		else if (OPENSSL_strcasecmp(s, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
			*pad_mode = RSA_PKCS1_OAEP_PADDING;
		else
			return 0;

		return 1;
	}

	return 0;
}

int export_rsa_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg)
{
	OSSL_PARAM params[3];

	if (keydata->pubdata.rsa.n == NULL || keydata->pubdata.rsa.n_len == 0 ||
		keydata->pubdata.rsa.e == NULL || keydata->pubdata.rsa.e_len == 0)
		return 0;

	params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
		keydata->pubdata.rsa.n, keydata->pubdata.rsa.n_len);
	params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
		keydata->pubdata.rsa.e, keydata->pubdata.rsa.e_len);
	params[2] = OSSL_PARAM_construct_end();

	return param_cb(params, cbarg);
}

int export_ec_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg)
{
	OSSL_PARAM params[3];

	if (keydata->pubdata.ec.group_name == NULL ||
		keydata->pubdata.ec.pub == NULL || keydata->pubdata.ec.pub_len == 0)
		return 0;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
		keydata->pubdata.ec.group_name, 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
		keydata->pubdata.ec.pub, keydata->pubdata.ec.pub_len);
	params[2] = OSSL_PARAM_construct_end();

	return param_cb(params, cbarg);
}

int export_eddsa_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg)
{
	OSSL_PARAM params[2];
	unsigned char *pub = NULL;
	size_t pub_len = 0;

	if (keydata->pubdata.eddsa.pub != NULL && keydata->pubdata.eddsa.pub_len != 0)
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			keydata->pubdata.eddsa.pub, keydata->pubdata.eddsa.pub_len);
	else if (p11_keydata_get_pub(keydata, &pub, &pub_len) && pub != NULL && pub_len != 0)
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			pub, pub_len);
	else
		return 0;

	params[1] = OSSL_PARAM_construct_end();

	return param_cb(params, cbarg);
}


/******************************************************************************/
/* SIGNATURE helper functions                                                 */
/******************************************************************************/

/* Allocate and initialize signature context structure. */
P11_SIGNATURE_CTX *p11_signature_ctx_new(PROVIDER_CTX *ctx, const char *propq)
{
	P11_SIGNATURE_CTX *sig_ctx;

	sig_ctx = OPENSSL_zalloc(sizeof(P11_SIGNATURE_CTX));
	if (!sig_ctx)
		return NULL;

	if (propq != NULL) {
		sig_ctx->propq = OPENSSL_strdup(propq);
		if (sig_ctx->propq == NULL) {
			OPENSSL_free(sig_ctx);
			return NULL;
		}
	}
	/* prov_ctx is shared, not owned */
	sig_ctx->prov_ctx = ctx;
	return sig_ctx;
}

/* Release signature context and associated resources. */
void p11_signature_ctx_free(P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return;

	p11_keydata_free(sig_ctx->keydata);
	EVP_MD_CTX_free(sig_ctx->mdctx);
	OPENSSL_free(sig_ctx->mdname);
	OPENSSL_free(sig_ctx->mgf1_mdname);
	OPENSSL_free(sig_ctx->propq);
	OPENSSL_free(sig_ctx);
}

/*
 * Duplicate signature context. This must be a real duplicate, not just another
 * reference to the same mutable object.
 */
P11_SIGNATURE_CTX *p11_signature_dupctx(P11_SIGNATURE_CTX *sig_ctx)
{
	P11_SIGNATURE_CTX *dst;

	if (sig_ctx == NULL)
		return NULL;

	dst = p11_signature_ctx_new(sig_ctx->prov_ctx, sig_ctx->propq);
	if (dst == NULL)
		return NULL;

	if (sig_ctx->mdname != NULL) {
		dst->mdname = OPENSSL_strdup(sig_ctx->mdname);
		if (dst->mdname == NULL)
			goto err;
	}

	/* copy simple scalar state */
	dst->pad_mode = sig_ctx->pad_mode;
	dst->pss_saltlen = sig_ctx->pss_saltlen;

	/* share keydata by reference */
	if (sig_ctx->keydata != NULL) {
		if (!p11_keydata_up_ref(sig_ctx->keydata))
			goto err;
		dst->keydata = sig_ctx->keydata;
	}

	/* duplicate digest state so EVP_DigestVerifyFinal() on the duplicate
	 * does not mutate the original context */
	if (sig_ctx->mdctx != NULL) {
		dst->mdctx = EVP_MD_CTX_new();
		if (dst->mdctx == NULL)
			goto err;
		if (EVP_MD_CTX_copy_ex(dst->mdctx, sig_ctx->mdctx) <= 0)
			goto err;
	}

	return dst;

err:
	p11_signature_ctx_free(dst);
	return NULL;
}

/* Initialize signature context with key and reset operation defaults. */
int p11_signature_ctx_init(P11_SIGNATURE_CTX *sig_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[])
{
	(void)params; /* unused */

	if (sig_ctx == NULL || keydata == NULL)
		return 0;

	/* replace previous key if present */
	if (sig_ctx->keydata != NULL) {
		p11_keydata_free(sig_ctx->keydata);
		sig_ctx->keydata = NULL;
	}

	if (!p11_keydata_up_ref(keydata))
		return 0;

	sig_ctx->keydata = keydata;

	/* (re)set defaults (important when params don't include them) */
	sig_ctx->pad_mode = RSA_PKCS1_PADDING;
	sig_ctx->pss_saltlen = RSA_PSS_SALTLEN_AUTO; /* -2 */

	OPENSSL_free(sig_ctx->mdname);
	sig_ctx->mdname = NULL;

	OPENSSL_free(sig_ctx->mgf1_mdname);
	sig_ctx->mgf1_mdname = NULL;
	return 1;
}

/* Initialize or reset digest context for signature operation. */
int p11_signature_ctx_init_digest(P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return 0;

	OPENSSL_free(sig_ctx->mdname);
	sig_ctx->mdname = NULL;

	if (sig_ctx->mdctx != NULL)
		EVP_MD_CTX_reset(sig_ctx->mdctx);

	if (sig_ctx->mdctx == NULL) {
		sig_ctx->mdctx = EVP_MD_CTX_new();
		if (sig_ctx->mdctx == NULL)
			return 0;
	}
	return 1;
}

/*
 * Verify signature against precomputed input using a temporary public key copy
 * in the default provider.
 */
int p11_signature_ctx_verify(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pub = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *sig_md = NULL;
	const char *mgf1_name = NULL;
	int ok = 0;

	if (sig_ctx == NULL || sig_ctx->keydata == NULL || sig == NULL || tbs == NULL)
		return 0;

	pub = pubkey_from_params_default(sig_ctx->keydata);
	if (pub == NULL)
		return 0;

	switch (sig_ctx->keydata->type) {
#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		mdctx = EVP_MD_CTX_new();
		if (mdctx == NULL)
			goto end;

		if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub) <= 0)
			goto end;

		ok = EVP_DigestVerify(mdctx, sig, siglen, tbs, tbslen);
		ok = (ok == 1);
		break;
#endif /* OPENSSL_NO_ECX */
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		pctx = EVP_PKEY_CTX_new(pub, NULL);
		if (pctx == NULL)
			goto end;

		if (EVP_PKEY_verify_init(pctx) <= 0)
			goto end;

		if (EVP_PKEY_CTX_set_rsa_padding(pctx, sig_ctx->pad_mode) <= 0)
			goto end;

		switch (sig_ctx->pad_mode) {
		case RSA_PKCS1_PSS_PADDING:
			if (sig_ctx->mdname == NULL)
				goto end;

			sig_md = EVP_get_digestbyname(sig_ctx->mdname);
			if (sig_md == NULL)
				goto end;

			if (EVP_PKEY_CTX_set_signature_md(pctx, sig_md) <= 0)
				goto end;

			mgf1_name = (sig_ctx->mgf1_mdname != NULL)
				? sig_ctx->mgf1_mdname : sig_ctx->mdname;

			if (mgf1_name != NULL) {
				const EVP_MD *mgf1_md = EVP_get_digestbyname(mgf1_name);

				if (mgf1_md == NULL)
					goto end;

				if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md) <= 0)
					goto end;
			}

			if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
				(int)sig_ctx->pss_saltlen) <= 0)
				goto end;
			break;

		case RSA_PKCS1_PADDING:
		case RSA_NO_PADDING: /* not covered by tests */
		case RSA_X931_PADDING: /* not covered by tests */
			break;
		}
		ok = EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen);
		ok = (ok == 1);
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		pctx = EVP_PKEY_CTX_new(pub, NULL);
		if (pctx == NULL)
			goto end;

		if (EVP_PKEY_verify_init(pctx) <= 0)
			goto end;

		ok = EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen);
		ok = (ok == 1);
		break;
#endif /* OPENSSL_NO_EC */
	default:
		break;
	}

end:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pub);
	return ok;
}

/* Return EVP_PKEY associated with signature context. */
EVP_PKEY *p11_signature_ctx_get_evp_pkey(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return NULL;

	return p11_keydata_get_evp_pkey(sig_ctx->keydata);
}

/* Return maximum signature size for current key. */
size_t p11_signature_ctx_get_sigsize(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return 0;

	return p11_keydata_get_sigsize(sig_ctx->keydata);
}

/* Return key type used in signature context. */
int p11_signature_ctx_get_type(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return 0;

	return p11_keydata_get_type(sig_ctx->keydata);
}

/* Set digest algorithm name for signature context. */
int p11_signature_ctx_set_mdname(P11_SIGNATURE_CTX *sig_ctx, const char *mdname)
{
	char *name;

	if (sig_ctx == NULL)
		return 0;

	OPENSSL_free(sig_ctx->mdname);
	sig_ctx->mdname = NULL;

	if (mdname == NULL)
		return 1;

	name = OPENSSL_strdup(mdname);
	if (name == NULL)
		return 0;

	sig_ctx->mdname = name;
	return 1;
}

/* Return digest algorithm name used by signature context. */
const char *p11_signature_ctx_get_mdname(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return NULL;

	return sig_ctx->mdname;
}

/* Set padding mode for signature operations. */
int p11_signature_ctx_set_pad_mode(P11_SIGNATURE_CTX *sig_ctx, int pad_mode)
{
	if (sig_ctx == NULL)
		return 0;

	sig_ctx->pad_mode = pad_mode;
	return 1;
}

/* Return padding mode used for signature operations. */
int p11_signature_ctx_get_pad_mode(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return 0;

	return sig_ctx->pad_mode;
}

/* Set RSA-PSS salt length for signature operations. */
int p11_signature_ctx_set_pss_saltlen(P11_SIGNATURE_CTX *sig_ctx, int saltlen)
{
	if (sig_ctx == NULL)
		return 0;

	sig_ctx->pss_saltlen = saltlen;
	return 1;
}

/* Return RSA-PSS salt length used for signature operations. */
int p11_signature_ctx_get_pss_saltlen(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return RSA_PSS_SALTLEN_AUTO; /* -2 */

	return sig_ctx->pss_saltlen;
}

/* Set MGF1 digest algorithm name for RSA-PSS operations. */
int p11_signature_ctx_set_mgf1_mdname(P11_SIGNATURE_CTX *sig_ctx, const char *mdname)
{
	char *dup = NULL;

	if (sig_ctx == NULL)
		return 0;

	if (mdname != NULL) {
		dup = OPENSSL_strdup(mdname);
		if (dup == NULL)
			return 0;
	}

	OPENSSL_free(sig_ctx->mgf1_mdname);
	sig_ctx->mgf1_mdname = dup;
	return 1;
}

/* Return MGF1 digest algorithm name used for RSA-PSS operations. */
const char *p11_signature_ctx_get_mgf1_mdname(const P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return NULL;

	return sig_ctx->mgf1_mdname;
}

/* Return digest context used for signature operations. */
EVP_MD_CTX *p11_signature_ctx_get_mdctx(P11_SIGNATURE_CTX *sig_ctx)
{
	if (sig_ctx == NULL)
		return NULL;

	return sig_ctx->mdctx;
}

/* Convert RSA padding mode to its string representation. */
const char *p11_signature_pad_mode_to_string(int pad_mode)
{
	switch (pad_mode) {
	case RSA_PKCS1_PADDING:
		return OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
	case RSA_PKCS1_PSS_PADDING:
		return OSSL_PKEY_RSA_PAD_MODE_PSS;
	case RSA_NO_PADDING:
		return OSSL_PKEY_RSA_PAD_MODE_NONE;
	default:
		return NULL;
	}
}

/* Convert RSA-PSS salt length value to its string representation. */
const char *p11_signature_pss_saltlen_to_string(int saltlen)
{
	switch (saltlen) {
	case RSA_PSS_SALTLEN_DIGEST:
		return OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST; /* "digest" */
	case RSA_PSS_SALTLEN_AUTO:
		return OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO; /* "auto" */
	case RSA_PSS_SALTLEN_MAX:
		return OSSL_PKEY_RSA_PSS_SALT_LEN_MAX; /* "max" */
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
	case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
		return OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX; /* "auto-digestmax" */
#endif /* RSA_PSS_SALTLEN_AUTO_DIGEST_MAX */
	default:
		return NULL;
	}
}


/******************************************************************************/
/* ASYM CIPHER helper functions                                               */
/******************************************************************************/

/* Allocate and initialize asymmetric cipher context structure. */
P11_ASYM_CIPHER_CTX *p11_asym_cipher_ctx_new(PROVIDER_CTX *ctx)
{
	P11_ASYM_CIPHER_CTX *asym_ctx;

	asym_ctx = OPENSSL_zalloc(sizeof(P11_ASYM_CIPHER_CTX));
	if (!asym_ctx)
		return NULL;

	asym_ctx->prov_ctx = ctx;
	return asym_ctx;
}

/* Release asymmetric cipher context and associated resources. */
void p11_asym_cipher_ctx_free(P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return;

	p11_keydata_free(asym_ctx->keydata);
	OPENSSL_free(asym_ctx->oaep_mdname);
	OPENSSL_free(asym_ctx->mgf1_mdname);
	OPENSSL_free(asym_ctx->oaep_label);
	OPENSSL_free(asym_ctx);
}

/*
 * Duplicate asymmetric cipher context. This must be a real duplicate, not just
 * another reference to the same mutable object.
 */
P11_ASYM_CIPHER_CTX *p11_asym_cipher_dupctx(P11_ASYM_CIPHER_CTX *asym_ctx)
{
	P11_ASYM_CIPHER_CTX *dst = NULL;

	if (asym_ctx == NULL)
		return NULL;

	dst = p11_asym_cipher_ctx_new(asym_ctx->prov_ctx);
	if (dst == NULL)
		return NULL;

	/* copy simple scalar state */
	dst->pad_mode = asym_ctx->pad_mode;
	dst->oaep_labellen = asym_ctx->oaep_labellen;

	/* share keydata by reference */
	if (asym_ctx->keydata != NULL) {
		if (!p11_keydata_up_ref(asym_ctx->keydata))
			goto err;
		dst->keydata = asym_ctx->keydata;
	}

	/* deep-copy OAEP/MGF1 parameters (mutable per-context state) */
	if (asym_ctx->oaep_mdname != NULL) {
		dst->oaep_mdname = OPENSSL_strdup(asym_ctx->oaep_mdname);
		if (dst->oaep_mdname == NULL)
			goto err;
	}

	if (asym_ctx->mgf1_mdname != NULL) {
		dst->mgf1_mdname = OPENSSL_strdup(asym_ctx->mgf1_mdname);
		if (dst->mgf1_mdname == NULL)
			goto err;
	}

	if (asym_ctx->oaep_label != NULL && asym_ctx->oaep_labellen > 0) {
		dst->oaep_label = OPENSSL_memdup(asym_ctx->oaep_label,
			asym_ctx->oaep_labellen);
		if (dst->oaep_label == NULL)
			goto err;
	}

	return dst;

err:
	p11_asym_cipher_ctx_free(dst);
	return NULL;
}

/* Initialize asymmetric cipher context with key and reset OAEP defaults. */
int p11_asym_cipher_ctx_init(P11_ASYM_CIPHER_CTX *asym_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[])
{
	(void)params; /* unused */

	if (asym_ctx == NULL || keydata == NULL)
		return 0;

	/* replace previous key */
	if (asym_ctx->keydata != NULL) {
		p11_keydata_free(asym_ctx->keydata);
		asym_ctx->keydata = NULL;
	}

	if (!p11_keydata_up_ref(keydata))
		return 0;

	asym_ctx->keydata = keydata;

	/* defaults (important when params don't include them) */
	asym_ctx->pad_mode = RSA_PKCS1_OAEP_PADDING;

	OPENSSL_free(asym_ctx->oaep_mdname);
	asym_ctx->oaep_mdname = NULL; /* default = SHA1 */

	OPENSSL_free(asym_ctx->mgf1_mdname);
	asym_ctx->mgf1_mdname = NULL; /* default = oaep_mdname */

	OPENSSL_free(asym_ctx->oaep_label);
	asym_ctx->oaep_label = NULL;
	asym_ctx->oaep_labellen = 0;

	return 1;
}

/* Encrypt input data using a temporary public key copy in the default provider */
int p11_asym_cipher_ctx_encrypt(P11_ASYM_CIPHER_CTX *asym_ctx,
	unsigned char *out, size_t *outlen,
	size_t outsize, const unsigned char *in, size_t inlen)
{
	EVP_PKEY *pub = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t tmplen = 0;
	int ok = 0;

	if (asym_ctx == NULL || asym_ctx->keydata == NULL || outlen == NULL || in == NULL)
		return 0;

	if (asym_ctx->keydata->type != EVP_PKEY_RSA)
		return 0;

	pub = pubkey_from_params_default(asym_ctx->keydata);
	if (pub == NULL)
		return 0;

	pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, "provider=default");
	if (pctx == NULL)
		goto end;

	if (EVP_PKEY_encrypt_init(pctx) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_padding(pctx, asym_ctx->pad_mode) <= 0)
		goto end;

	if (asym_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
		const EVP_MD *oaep_md = NULL;
		const EVP_MD *mgf1_md = NULL;

		oaep_md = EVP_get_digestbyname(
			asym_ctx->oaep_mdname != NULL ? asym_ctx->oaep_mdname : "SHA1");
		if (oaep_md == NULL)
			goto end;

		if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, oaep_md) <= 0)
			goto end;

		mgf1_md = EVP_get_digestbyname(
			asym_ctx->mgf1_mdname != NULL ? asym_ctx->mgf1_mdname :
			(asym_ctx->oaep_mdname != NULL ? asym_ctx->oaep_mdname : "SHA1"));
		if (mgf1_md == NULL)
			goto end;

		if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md) <= 0)
			goto end;

		if (asym_ctx->oaep_label != NULL && asym_ctx->oaep_labellen > 0) {
			unsigned char *label;

			label = OPENSSL_memdup(asym_ctx->oaep_label, asym_ctx->oaep_labellen);
			if (label == NULL)
				goto end;

			if (EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label,
				(int)asym_ctx->oaep_labellen) <= 0) {
				OPENSSL_free(label);
				goto end;
			}
			/* ownership transferred to pctx */
			label = NULL;
		}
	}

	/* length query */
	if (out == NULL) {
		if (EVP_PKEY_encrypt(pctx, NULL, &tmplen, in, inlen) <= 0)
			goto end;
		*outlen = tmplen;
		ok = 1;
		goto end;
	}

	tmplen = outsize;
	if (EVP_PKEY_encrypt(pctx, out, &tmplen, in, inlen) <= 0)
		goto end;

	*outlen = tmplen;
	ok = 1;

end:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pub);
	return ok;
}

/* Return EVP_PKEY associated with asymmetric cipher context. */
EVP_PKEY *p11_asym_cipher_ctx_get_evp_pkey(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return NULL;

	return p11_keydata_get_evp_pkey(asym_ctx->keydata);
}

/* Return maximum output size for asymmetric cipher operation. */
size_t p11_asym_cipher_ctx_get_outsize(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return 0;

	/*
	 * For RSA decrypt the plaintext is at most modulus size.
	 * This is a safe upper bound for output buffer sizing.
	 */
	return p11_keydata_get_sigsize(asym_ctx->keydata);
}

/* Return key type used in asymmetric cipher context. */
int p11_asym_cipher_ctx_get_type(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return 0;

	return p11_keydata_get_type(asym_ctx->keydata);
}

/* Set OAEP digest algorithm name for asymmetric cipher operations. */
int p11_asym_cipher_ctx_set_oaep_mdname(P11_ASYM_CIPHER_CTX *asym_ctx, const char *mdname)
{
	char *dup = NULL;

	if (asym_ctx == NULL)
		return 0;

	if (mdname != NULL) {
		dup = OPENSSL_strdup(mdname);
		if (dup == NULL)
			return 0;
	}

	OPENSSL_free(asym_ctx->oaep_mdname);
	asym_ctx->oaep_mdname = dup;
	return 1;
}

/* Return OAEP digest algorithm name used in asymmetric cipher context. */
const char *p11_asym_cipher_ctx_get_oaep_mdname(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return NULL;

	return asym_ctx->oaep_mdname;
}

/* Set padding mode for asymmetric cipher operations. */
int p11_asym_cipher_ctx_set_pad_mode(P11_ASYM_CIPHER_CTX *asym_ctx, int pad_mode)
{
	if (asym_ctx == NULL)
		return 0;

	asym_ctx->pad_mode = pad_mode;
	return 1;
}

/* Return padding mode used in asymmetric cipher context. */
int p11_asym_cipher_ctx_get_pad_mode(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return 0;

	return asym_ctx->pad_mode;
}

/* Set MGF1 digest algorithm name for asymmetric cipher operations. */
int p11_asym_cipher_ctx_set_mgf1_mdname(P11_ASYM_CIPHER_CTX *asym_ctx, const char *mdname)
{
	char *dup = NULL;

	if (asym_ctx == NULL)
		return 0;

	if (mdname != NULL) {
		dup = OPENSSL_strdup(mdname);
		if (dup == NULL)
			return 0;
	}

	OPENSSL_free(asym_ctx->mgf1_mdname);
	asym_ctx->mgf1_mdname = dup;
	return 1;
}

/* Return MGF1 digest algorithm name used in asymmetric cipher context. */
const char *p11_asym_cipher_ctx_get_mgf1_mdname(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return NULL;

	return asym_ctx->mgf1_mdname;
}

/* Return OAEP label used in asymmetric cipher context. */
unsigned char *p11_asym_cipher_ctx_get_oaep_label(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return NULL;

	return asym_ctx->oaep_label;
}

/* Set OAEP label for asymmetric cipher operations. */
int p11_asym_cipher_ctx_set_oaep_label(P11_ASYM_CIPHER_CTX *asym_ctx,
	const unsigned char *label, size_t labellen)
{
	unsigned char *dup = NULL;

	if (asym_ctx == NULL)
		return 0;

	if (labellen > 0) {
		if (label == NULL)
			return 0;

		dup = OPENSSL_memdup(label, labellen);
		if (dup == NULL)
			return 0;
	}

	OPENSSL_free(asym_ctx->oaep_label);
	asym_ctx->oaep_label = dup;
	asym_ctx->oaep_labellen = labellen;
	return 1;
}

/* Return OAEP label length used in asymmetric cipher context. */
size_t p11_asym_cipher_ctx_get_oaep_labellen(const P11_ASYM_CIPHER_CTX *asym_ctx)
{
	if (asym_ctx == NULL)
		return 0;

	return asym_ctx->oaep_labellen;
}


/******************************************************************************/
/* Internal helper functions                                                  */
/******************************************************************************/

/* Update the provider context with environment variable values */
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
 * Retrieve provider-specific parameters. The parameters are returned by
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

/* Build public EVP_PKEY (default provider) from OSSL_PARAM[] */
static EVP_PKEY *pubkey_from_params_default(P11_KEYDATA *keydata)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	if (keydata == NULL || keydata->name == NULL || keydata->params == NULL)
		return NULL;

	/* Force default provider to avoid recursion into pkcs11 provider */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, keydata->name, "provider=default");
	if (pctx == NULL)
		return NULL;

	if (EVP_PKEY_fromdata_init(pctx) <= 0)
		goto err;

	if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY,
		(OSSL_PARAM *)keydata->params) <= 0)
		goto err;

	EVP_PKEY_CTX_free(pctx);
	return pkey;

err:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);
	return NULL;
}

/* Return EVP_PKEY stored in keydata. */
static EVP_PKEY *p11_keydata_get_evp_pkey(P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return NULL;

	return keydata->pkey;
}

/* Set and store raw public key data. */
static int p11_keydata_set_pub(P11_KEYDATA *keydata, const void *buf, size_t len)
{
	P11_PUB_KEY *pubkey;
	unsigned char *copy;

	if (keydata == NULL || buf == NULL || len == 0)
		return 0;

	copy = OPENSSL_memdup(buf, len);
	if (copy == NULL)
		return 0;

	pubkey = keydata->pubkey;
	if (pubkey == NULL) {
		pubkey = OPENSSL_zalloc(sizeof(P11_PUB_KEY));
		if (pubkey == NULL) {
			OPENSSL_free(copy);
			return 0;
		}
		keydata->pubkey = pubkey;
	}

	OPENSSL_free(pubkey->pub);
	pubkey->pub = copy;
	pubkey->pub_len = len;
	return 1;
}

/* Build OSSL_PARAM list with public-key parameters extracted from an EVP_PKEY. */
static OSSL_PARAM *public_params_from_evp_pkey(EVP_PKEY *pkey)
{
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	BIGNUM *n = NULL, *e = NULL;
	unsigned char *pub = NULL;
	int nid;

	if (pkey == NULL)
		return NULL;

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		return NULL;

	nid = EVP_PKEY_base_id(pkey);

	switch (nid) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
			!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e))
			goto err;

		if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
			!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
			goto err;
		break;

#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
	{
		char group[128];
		size_t grouplen = 0;
		size_t publen = 0;

		if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
			group, sizeof(group), &grouplen))
			goto err;

		if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
			group, 0))
			goto err;

#if OPENSSL_VERSION_NUMBER < 0x30000100L
		/*
		 * OpenSSL < 3.0.16 lacks a NULL check for 'point' in the
		 * EC_POINT_point2oct() path, which may lead to invalid memory
		 * access. Fixed upstream in 3.0.16:
		 * https://github.com/openssl/openssl/commit/8ac42a5f418cbe2797bc423b694ac5af605b5c7a
		 */
		{
			const EC_POINT *point = NULL;

			DISABLE_OSSL3_DEPRECATED_BEGIN
			{
				const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);

				if (eckey != NULL)
					point = EC_KEY_get0_public_key(eckey);
			}
			DISABLE_OSSL3_DEPRECATED_END

			if (point != NULL) {
#endif
				if (EVP_PKEY_get_octet_string_param(pkey,
					OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &publen)) {
					pub = OPENSSL_malloc(publen);
					if (pub == NULL)
						goto err;

					if (!EVP_PKEY_get_octet_string_param(pkey,
						OSSL_PKEY_PARAM_PUB_KEY, pub, publen, &publen))
						goto err;
#if OPENSSL_VERSION_NUMBER < 0x30000100L
				}
			}
#endif
			if (!OSSL_PARAM_BLD_push_octet_string(bld,
				OSSL_PKEY_PARAM_PUB_KEY, pub, publen))
				goto err;
			}
		break;
	}
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
	{
		size_t publen = 0;
		const char *name = (nid == EVP_PKEY_ED25519) ? "ED25519" : "ED448";

		if (!OSSL_PARAM_BLD_push_utf8_string(bld,
			OSSL_PKEY_PARAM_GROUP_NAME, name, 0))
			goto err;

		/* Token-backed private keys may not expose the associated public
		 * key through EVP_PKEY. In that case, keep the group name only. */
		if (EVP_PKEY_get_raw_public_key(pkey, NULL, &publen)) {
			pub = OPENSSL_malloc(publen);
			if (pub == NULL)
				goto err;

			if (!EVP_PKEY_get_raw_public_key(pkey, pub, &publen))
				goto err;

			if (!OSSL_PARAM_BLD_push_octet_string(bld,
				OSSL_PKEY_PARAM_PUB_KEY, pub, publen))
				goto err;
		}
		break;
	}
#endif /* OPENSSL_NO_ECX */
	default:
		goto err; /* unsupported key type */
	}

	params = OSSL_PARAM_BLD_to_param(bld);

err:
	OSSL_PARAM_BLD_free(bld);
	BN_free(n);
	BN_free(e);
	OPENSSL_free(pub);
	return params;
}

/* Initialize key type and size metadata from stored key parameters. */
static int p11_keydata_init_from_params(P11_KEYDATA *keydata)
{
	const OSSL_PARAM *p;

	if (keydata == NULL || keydata->params == NULL)
		return 0;

	p11_keydata_clear_pubdata(keydata);

	keydata->type = 0;
	keydata->name = NULL;
	keydata->keysize = 0;
	keydata->sigsize = 0;

	/* RSA */
	p = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_RSA_N);
	if (p != NULL && p->data_type == OSSL_PARAM_UNSIGNED_INTEGER &&
		p->data != NULL && p->data_size > 0) {
		const OSSL_PARAM *pe;

		pe = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_RSA_E);
		if (pe == NULL || pe->data_type != OSSL_PARAM_UNSIGNED_INTEGER ||
			pe->data == NULL || pe->data_size == 0)
			return 0;

		if (!p11_dup_param_blob(p, &keydata->pubdata.rsa.n,
				&keydata->pubdata.rsa.n_len))
			goto err;

		if (!p11_dup_param_blob(pe, &keydata->pubdata.rsa.e,
				&keydata->pubdata.rsa.e_len))
			goto err;

		keydata->type = EVP_PKEY_RSA;
		keydata->name = "RSA";
		keydata->keysize = p->data_size;
		keydata->sigsize = p->data_size; /* RSA signature == modulus size */
		return 1;
	}

	p = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_GROUP_NAME);

	/* Ed25519 / Ed448 and classic EC can be identified from GROUP_NAME alone */
	if (p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
		const char *group_name = NULL;

		if (!OSSL_PARAM_get_utf8_string_ptr(p, &group_name) || group_name == NULL)
			return 0;

#ifndef OPENSSL_NO_ECX
		if (OPENSSL_strcasecmp(group_name, "ED25519") == 0) {
			const OSSL_PARAM *ppub;

			ppub = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_PUB_KEY);
			if (ppub != NULL && ppub->data_type == OSSL_PARAM_OCTET_STRING &&
				ppub->data != NULL && ppub->data_size == 32) {
				if (!p11_dup_param_blob(ppub, &keydata->pubdata.eddsa.pub,
					&keydata->pubdata.eddsa.pub_len))
					goto err;
			}
			keydata->type = EVP_PKEY_ED25519;
			keydata->name = "ED25519";
			keydata->keysize = 32;
			keydata->sigsize = 64;
			return 1;
		}

		if (OPENSSL_strcasecmp(group_name, "ED448") == 0) {
			const OSSL_PARAM *ppub;

			ppub = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_PUB_KEY);
			if (ppub != NULL && ppub->data_type == OSSL_PARAM_OCTET_STRING &&
				ppub->data != NULL && ppub->data_size == 57) {
				if (!p11_dup_param_blob(ppub, &keydata->pubdata.eddsa.pub,
					&keydata->pubdata.eddsa.pub_len))
					goto err;
			}
			keydata->type = EVP_PKEY_ED448;
			keydata->name = "ED448";
			keydata->keysize = 57;
			keydata->sigsize = 114;
			return 1;
		}
#endif /* OPENSSL_NO_ECX */

#ifndef OPENSSL_NO_EC
		/* classic EC */
		{
			const OSSL_PARAM *ppub;
			int nid = NID_undef;
			EC_GROUP *grp = NULL;
			BN_CTX *bnctx = NULL;
			BIGNUM *order = NULL;
			size_t order_bytes = 0;

			nid = OBJ_sn2nid(group_name);
			if (nid == NID_undef)
				nid = OBJ_ln2nid(group_name);
			if (nid == NID_undef)
				return 0;

			grp = EC_GROUP_new_by_curve_name(nid);
			bnctx = BN_CTX_new();
			order = BN_new();
			if (grp == NULL || bnctx == NULL || order == NULL)
				goto ec_err;

			if (EC_GROUP_get_order(grp, order, bnctx) != 1)
				goto ec_err;

			order_bytes = (size_t)BN_num_bytes(order);
			if (order_bytes == 0)
				goto ec_err;

			if (!p11_dup_param_utf8(p, &keydata->pubdata.ec.group_name))
				goto ec_err;

			ppub = OSSL_PARAM_locate_const(keydata->params, OSSL_PKEY_PARAM_PUB_KEY);
			if (ppub != NULL && ppub->data_type == OSSL_PARAM_OCTET_STRING &&
				ppub->data != NULL && ppub->data_size > 0) {
				if (!p11_dup_param_blob(ppub, &keydata->pubdata.ec.pub,
					&keydata->pubdata.ec.pub_len))
					goto ec_err;
			}
			keydata->type = EVP_PKEY_EC;
			keydata->name = "EC";

			/* good approximation for "key size" */
			keydata->keysize = order_bytes;

			/* safe upper bound for DER-encoded ECDSA signatures */
			keydata->sigsize = (2 * (order_bytes + 3)) +
				((2 * (order_bytes + 3) < 128) ? 2 : 3);

			BN_free(order);
			BN_CTX_free(bnctx);
			EC_GROUP_free(grp);
			return 1;

ec_err:
			BN_free(order);
			BN_CTX_free(bnctx);
			EC_GROUP_free(grp);
			goto err;
		}
#endif /* OPENSSL_NO_EC */
	}
	return 0;

err:
	p11_keydata_clear_pubdata(keydata);
	keydata->type = 0;
	keydata->name = NULL;
	keydata->keysize = 0;
	keydata->sigsize = 0;
	return 0;
}

/* Replace existing parameter set in key object with new OSSL_PARAM array. */
static int p11_keydata_replace_params(P11_KEYDATA *keydata, OSSL_PARAM *params)
{
	if (keydata == NULL || params == NULL)
		return 0;

	OSSL_PARAM_free(keydata->params);
	keydata->params = params;
	keydata->type = algorithm_from_ossl_param(params);
	keydata->is_private = params_contains_private_key(params);

	return 1;
}

/* Detect key algorithm type from OSSL_PARAM key attributes. */
static int algorithm_from_ossl_param(const OSSL_PARAM *params)
{
#ifndef OPENSSL_NO_ECX
	const OSSL_PARAM *p;

	/* Ed25519 / Ed448 (EdDSA): most reliable is raw key size */
	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
	if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING) {
		if (p->data_size == 32)
			return EVP_PKEY_ED25519;
		if (p->data_size == 57)
			return EVP_PKEY_ED448;
	}
#endif /* OPENSSL_NO_ECX */

	/* RSA */
	if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N) ||
		OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) {
		return EVP_PKEY_RSA;
	}

#ifndef OPENSSL_NO_EC
	/* EC (classic ECDSA/ECDH) */
	if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING) ||
		OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT)) {
		return EVP_PKEY_EC;
	}
#endif /* OPENSSL_NO_EC */

	return 0;
}

/*
 * Covers:
 *  - EC/EdDSA: OSSL_PKEY_PARAM_PRIV_KEY
 *  - RSA:     OSSL_PKEY_PARAM_RSA_D (private exponent)
 * Return 1 if params contain private key material, 0 otherwise.
 */
static int params_contains_private_key(const OSSL_PARAM *params)
{
	const OSSL_PARAM *p;

	/* Generic private key bytes (EC / EdDSA / etc.) */
	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
	if (p != NULL && p->data != NULL && p->data_size > 0)
		return 1;

	/* RSA private exponent */
	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
	if (p != NULL && p->data != NULL && p->data_size > 0)
		return 1;

	return 0;
}

/*
 * BN params built via OSSL_PARAM_BLD_push_BN use a canonical binary form,
 * so a raw byte comparison is sufficient.
 */
static int param_blob_equal(const OSSL_PARAM *a, const OSSL_PARAM *b)
{
	if (a == NULL || b == NULL)
		return 0;
	if (a->data_type != b->data_type)
		return 0;
	if (a->data == NULL || b->data == NULL)
		return 0;
	if (a->data_size != b->data_size)
		return 0;
	return CRYPTO_memcmp(a->data, b->data, a->data_size) == 0;
}

/* Compare two RSA public keys by matching modulus (n) and public exponent (e). */
static int rsa_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2)
{
	const OSSL_PARAM *n1 = OSSL_PARAM_locate_const(p1, OSSL_PKEY_PARAM_RSA_N);
	const OSSL_PARAM *e1 = OSSL_PARAM_locate_const(p1, OSSL_PKEY_PARAM_RSA_E);
	const OSSL_PARAM *n2 = OSSL_PARAM_locate_const(p2, OSSL_PKEY_PARAM_RSA_N);
	const OSSL_PARAM *e2 = OSSL_PARAM_locate_const(p2, OSSL_PKEY_PARAM_RSA_E);

	return (n1 && e1 && n2 && e2 && param_blob_equal(n1, n2) && param_blob_equal(e1, e2));
}

#ifndef OPENSSL_NO_EC
static int p11_dup_param_utf8(const OSSL_PARAM *p, char **out)
{
	const char *s = NULL;

	if (p == NULL || out == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
		return 0;

	if (!OSSL_PARAM_get_utf8_string_ptr(p, &s) || s == NULL)
		return 0;

	*out = OPENSSL_strdup(s);
	return (*out != NULL);
}

/* Match EC public keys by curve name and public point value. */
static int ec_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2)
{
	const char *group1 = NULL, *group2 = NULL;
	const OSSL_PARAM *g1 = OSSL_PARAM_locate_const(p1, OSSL_PKEY_PARAM_GROUP_NAME);
	const OSSL_PARAM *g2 = OSSL_PARAM_locate_const(p2, OSSL_PKEY_PARAM_GROUP_NAME);
	const OSSL_PARAM *k1 = OSSL_PARAM_locate_const(p1, OSSL_PKEY_PARAM_PUB_KEY);
	const OSSL_PARAM *k2 = OSSL_PARAM_locate_const(p2, OSSL_PKEY_PARAM_PUB_KEY);

	if (g1 == NULL || g2 == NULL || k1 == NULL || k2 == NULL)
		return 0;

	/* GROUP_NAME */
	if (g1->data_type != OSSL_PARAM_UTF8_STRING ||
		g2->data_type != OSSL_PARAM_UTF8_STRING)
		return 0;

	if (!OSSL_PARAM_get_utf8_string_ptr(g1, &group1) ||
		!OSSL_PARAM_get_utf8_string_ptr(g2, &group2) ||
		group1 == NULL || group2 == NULL)
		return 0;

	if (OPENSSL_strcasecmp(group1, group2) != 0)
		return 0;

	/* PUB_KEY */
	if (k1->data_type != OSSL_PARAM_OCTET_STRING ||
		k2->data_type != OSSL_PARAM_OCTET_STRING ||
		k1->data == NULL || k2->data == NULL)
		return 0;

	return ec_point_equal_by_value(group1,
		(const unsigned char *)k1->data, k1->data_size,
		(const unsigned char *)k2->data, k2->data_size);
}

/* Compare two EC public points by value on the given curve. */
static int ec_point_equal_by_value(const char *group_name,
	const unsigned char *a, size_t alen, const unsigned char *b, size_t blen)
{
	int ok = 0;
	int nid = NID_undef;
	EC_GROUP *grp = NULL;
	EC_POINT *pa = NULL, *pb = NULL;
	BN_CTX *bnctx = NULL;

	if (group_name == NULL || a == NULL || b == NULL)
		return 0;

	nid = OBJ_sn2nid(group_name);
	if (nid == NID_undef)
		nid = OBJ_ln2nid(group_name);
	if (nid == NID_undef)
		return 0;

	grp = EC_GROUP_new_by_curve_name(nid);
	if (grp == NULL)
		goto err;

	pa = EC_POINT_new(grp);
	pb = EC_POINT_new(grp);
	bnctx = BN_CTX_new();
	if (pa == NULL || pb == NULL || bnctx == NULL)
		goto err;

	if (EC_POINT_oct2point(grp, pa, a, alen, bnctx) != 1)
		goto err;
	if (EC_POINT_oct2point(grp, pb, b, blen, bnctx) != 1)
		goto err;

	ok = (EC_POINT_cmp(grp, pa, pb, bnctx) == 0);

err:
	BN_CTX_free(bnctx);
	EC_POINT_free(pa);
	EC_POINT_free(pb);
	EC_GROUP_free(grp);
	return ok;
}
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_ECX
/* Compare EdDSA public keys by raw public key bytes. */
static int eddsa_public_match_params(const OSSL_PARAM *p1, const OSSL_PARAM *p2)
{
	const OSSL_PARAM *k1 = OSSL_PARAM_locate_const(p1, OSSL_PKEY_PARAM_PUB_KEY);
	const OSSL_PARAM *k2 = OSSL_PARAM_locate_const(p2, OSSL_PKEY_PARAM_PUB_KEY);

	return (k1 && k2 && octet_equal(k1, k2));
}

/* Compare two OSSL_PARAM octet strings for equality. */
static int octet_equal(const OSSL_PARAM *a, const OSSL_PARAM *b)
{
	if (a == NULL || b == NULL)
		return 0;
	if (a->data_type != OSSL_PARAM_OCTET_STRING ||
		b->data_type != OSSL_PARAM_OCTET_STRING)
		return 0;
	if (a->data == NULL || b->data == NULL)
		return 0;
	if (a->data_size != b->data_size)
		return 0;
    return CRYPTO_memcmp(a->data, b->data, a->data_size) == 0;
}
#endif /* OPENSSL_NO_ECX */

static void p11_keydata_clear_pubdata(P11_KEYDATA *keydata)
{
	if (keydata == NULL)
		return;

	OPENSSL_free(keydata->pubdata.rsa.n);
	OPENSSL_free(keydata->pubdata.rsa.e);
	OPENSSL_free(keydata->pubdata.ec.group_name);
	OPENSSL_free(keydata->pubdata.ec.pub);
	OPENSSL_free(keydata->pubdata.eddsa.pub);
	memset(&keydata->pubdata, 0, sizeof(keydata->pubdata));
}

static int p11_dup_param_blob(const OSSL_PARAM *p, unsigned char **out, size_t *out_len)
{
	if (p == NULL || out == NULL || out_len == NULL ||
		p->data == NULL || p->data_size == 0)
		return 0;

	*out = OPENSSL_memdup(p->data, p->data_size);
	if (*out == NULL)
		return 0;

	*out_len = p->data_size;
	return 1;
}


/* vim: set noexpandtab: */
