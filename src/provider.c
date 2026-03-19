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

#include "provider_helpers.h"

#if defined(_WIN32) && !defined(strncasecmp)
#define strncasecmp _strnicmp
#endif

#include <openssl/params.h>
#include <openssl/store.h>

#define FIPS_PROPQ "provider=pkcs11prov,fips=yes"

typedef struct {
	PROVIDER_CTX *prov_ctx;
	char *propq;
	char *uri;
	int expected_type;
	int types_tried;
} P11_STORE_CTX;

/* provider entry point (fixed name, exported) */
static OSSL_provider_init_fn provider_init;

#define PROVIDER_FN(name) static OSSL_FUNC_##name##_fn name
PROVIDER_FN(provider_teardown);
PROVIDER_FN(provider_gettable_params);
PROVIDER_FN(provider_get_params);
PROVIDER_FN(provider_query_operation);
PROVIDER_FN(provider_get_reason_strings);

PROVIDER_FN(keymgmt_new);
PROVIDER_FN(keymgmt_load);
PROVIDER_FN(keymgmt_free);
PROVIDER_FN(keymgmt_has);
PROVIDER_FN(keymgmt_match);
PROVIDER_FN(keymgmt_query_operation_name);
PROVIDER_FN(keymgmt_import);
PROVIDER_FN(keymgmt_import_types);
PROVIDER_FN(keymgmt_export);
PROVIDER_FN(keymgmt_export_types);
PROVIDER_FN(keymgmt_get_params);
PROVIDER_FN(keymgmt_gettable_params);
PROVIDER_FN(keymgmt_dup);

PROVIDER_FN(signature_newctx);
PROVIDER_FN(signature_freectx);
PROVIDER_FN(signature_dupctx);
PROVIDER_FN(signature_sign_init);
PROVIDER_FN(signature_sign);
PROVIDER_FN(signature_verify_init);
PROVIDER_FN(signature_verify);
PROVIDER_FN(signature_digest_sign_init);
PROVIDER_FN(signature_digest_sign_update);
PROVIDER_FN(signature_digest_sign_final);
PROVIDER_FN(signature_digest_sign);
PROVIDER_FN(signature_digest_verify_init);
PROVIDER_FN(signature_digest_verify_update);
PROVIDER_FN(signature_digest_verify_final);
PROVIDER_FN(signature_digest_verify);
PROVIDER_FN(signature_get_ctx_params);
PROVIDER_FN(signature_gettable_ctx_params);
PROVIDER_FN(signature_set_ctx_params);
PROVIDER_FN(signature_settable_ctx_params);

PROVIDER_FN(asym_cipher_newctx);
PROVIDER_FN(asym_cipher_freectx);
PROVIDER_FN(asym_cipher_dupctx);
PROVIDER_FN(asym_cipher_encrypt_init);
PROVIDER_FN(asym_cipher_encrypt);
PROVIDER_FN(asym_cipher_decrypt_init);
PROVIDER_FN(asym_cipher_decrypt);
PROVIDER_FN(asym_cipher_get_ctx_params);
PROVIDER_FN(asym_cipher_gettable_ctx_params);
PROVIDER_FN(asym_cipher_set_ctx_params);
PROVIDER_FN(asym_cipher_settable_ctx_params);

PROVIDER_FN(store_open);
PROVIDER_FN(store_set_ctx_params);
PROVIDER_FN(store_settable_ctx_params);
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

static const OSSL_DISPATCH keymgmt_functions[] = {
	{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new},
	{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load},
	{OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free},
	{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has},
	{OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match},
	{OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))keymgmt_query_operation_name},
	{OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))keymgmt_import},
	{OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keymgmt_import_types},
	{OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))keymgmt_export},
	{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))keymgmt_export_types},
	{OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keymgmt_get_params},
	{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keymgmt_gettable_params},
	{OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))keymgmt_dup},
	OSSL_DISPATCH_END
};

static const OSSL_DISPATCH signature_functions[] = {
	{OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))signature_newctx},
	{OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))signature_freectx},
	{OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))signature_dupctx},
	{OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))signature_sign_init},
	{OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))signature_sign},
	{OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))signature_verify_init},
	{OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))signature_verify},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))signature_digest_sign_init},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))signature_digest_sign_update},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))signature_digest_sign_final},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))signature_digest_sign},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))signature_digest_verify_init},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))signature_digest_verify_update},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))signature_digest_verify_final},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))signature_digest_verify},
	{OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))signature_get_ctx_params},
	{OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))signature_gettable_ctx_params},
	{OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))signature_set_ctx_params},
	{OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))signature_settable_ctx_params},
	OSSL_DISPATCH_END
};

static const OSSL_DISPATCH asym_cipher_functions[] = {
	{OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))asym_cipher_newctx},
	{OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))asym_cipher_freectx},
	{OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))asym_cipher_dupctx},
	{OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))asym_cipher_encrypt_init},
	{OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))asym_cipher_encrypt},
	{OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))asym_cipher_decrypt_init},
	{OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))asym_cipher_decrypt},
	{OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))asym_cipher_get_ctx_params},
	{OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))asym_cipher_gettable_ctx_params},
	{OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))asym_cipher_set_ctx_params},
	{OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))asym_cipher_settable_ctx_params},
	OSSL_DISPATCH_END
};

static const OSSL_DISPATCH store_functions[] = {
	{OSSL_FUNC_STORE_OPEN, (void (*)(void))store_open},
	{OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))store_set_ctx_params},
	{OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))store_settable_ctx_params},
	{OSSL_FUNC_STORE_LOAD, (void (*)(void))store_load},
	{OSSL_FUNC_STORE_EOF, (void (*)(void))store_eof},
	{OSSL_FUNC_STORE_CLOSE, (void (*)(void))store_close},
	OSSL_DISPATCH_END
};

/* Keymgmt algorithms: must be real key types (e.g. RSA, EC), not provider names */
static const OSSL_ALGORITHM p11_keymgmts[] = {
	{"RSA:rsaEncryption", FIPS_PROPQ, keymgmt_functions, "PKCS#11 RSA keymgm functions"},
	{"EC:id-ecPublicKey", FIPS_PROPQ, keymgmt_functions, "PKCS#11 EC keymgm functions"},
	{"ED25519", FIPS_PROPQ, keymgmt_functions, "PKCS#11 Ed25519 keymgm functions"},
	{"ED448", FIPS_PROPQ, keymgmt_functions, "PKCS#11 Ed448 keymgm functions"},
	{NULL, NULL, NULL, NULL}
};

const OSSL_ALGORITHM p11_signatures[] = {
	{"PKCS11", FIPS_PROPQ, signature_functions, "PKCS#11 signature functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_asym_cipher[] = {
	{"PKCS11", FIPS_PROPQ, asym_cipher_functions, "PKCS#11 asym_cipher functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_storemgmt[] = {
	{"PKCS11", FIPS_PROPQ, store_functions, "PKCS#11 storage functions"},
	{NULL, NULL, NULL, NULL}
};

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
	PROVIDER_CTX_set_handle(prov_ctx, handle);

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
	if (p != NULL && !PROVIDER_CTX_set_provider_name(p, prov_ctx))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !PROVIDER_CTX_set_openssl_version(p, prov_ctx))
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

	switch (operation_id) {
	case OSSL_OP_KEYMGMT:
		return p11_keymgmts;
	case OSSL_OP_SIGNATURE:
		return p11_signatures;
	case OSSL_OP_ASYM_CIPHER:
		return p11_asym_cipher;
	case OSSL_OP_STORE:
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
		{3, "Failed to set store context parameters"},
		{4, "Failed to encode X.509 certificate"},
		{5, "OSSL_STORE object callback failed"},
		{0, NULL} /* Sentinel value */
	};

	(void)ctx;
	return reason_strings;
}

/******************************************************************************/
/* KEYMGMT functions                                                          */
/******************************************************************************/

/* Allocate and initialize new key management object. */
static void *keymgmt_new(void *ctx)
{
	return p11_keydata_new(ctx);
}

/* Load key object from opaque reference and transfer ownership. */
static void *keymgmt_load(const void *reference, size_t reference_sz)
{
	P11_KEYDATA *keydata;

	if (reference == NULL || reference_sz != sizeof(keydata))
		return NULL;

	/* The contents of the reference is the address to our object */
	keydata = *(P11_KEYDATA * const *)reference;

	/* We grabbed, so we detach it */
	*(P11_KEYDATA **)reference = NULL;
	return keydata;
}

/* Free key management object and release associated resources. */
static void keymgmt_free(void *provkey)
{
	p11_keydata_free(provkey);
}

/* Check if key object satisfies requested selection (private/public key availability). */
static int keymgmt_has(const void *provkey, int selection)
{
	const P11_KEYDATA *keydata = (const P11_KEYDATA *)provkey;

	if (keydata == NULL)
		return 0;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
		return p11_keydata_is_private(keydata);

	/* We always return OK when asked for a PUBLIC KEY, even if we only have
	 * a private key, as we can try to fetch the associated public key */
	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
		return 1;

	return 0; /* Unsupported selection */
}

/*
 * Compare two key objects for the requested components, preferring public key
 * material and falling back to private key data when needed.
 */
static int keymgmt_match(const void *provkey1, const void *provkey2, int selection)
{
	const P11_KEYDATA *keydata1 = (P11_KEYDATA *)provkey1;
	const P11_KEYDATA *keydata2 = (P11_KEYDATA *)provkey2;
	int ok = 1;

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
		ok = ok && keydata1 != NULL && keydata2 != NULL;

	if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
		/* Match public key material first. Private key comparison is
		 * used only as a fallback when public key data is unavailable,
		 * avoidingredundant checks (e.g. EC group) */
		int key_checked = 0;

		if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
			/* validate whether the public keys match */
			key_checked = p11_public_equal(keydata1, keydata2);
		}
		if (!key_checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
			/* validate whether the private keys match, not covered by tests */
			//key_checked = keydata1->is_private && keydata2->is_private && private_match(keydata1, keydata2);
			/* TODO */
		}
		ok = ok && key_checked;
	}
	return ok;
}

/* Return provider operation name for supported operations. */
static const char *keymgmt_query_operation_name(int id)
{
	switch (id) {
	case OSSL_OP_SIGNATURE:
	case OSSL_OP_ASYM_CIPHER:
		return "PKCS11";
	}
	return NULL;
}

/* Import public key parameters into key object from OSSL_PARAM array. */
static int keymgmt_import(void *provkey, int selection, const OSSL_PARAM *params)
{
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;

	if (keydata == NULL || params == NULL)
		return 0;

	if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
		return 0;

	if (!p11_keydata_set_params(keydata, params))
		return 0;

	return 1;
}

/* Return supported import parameter types for public key data. */
static const OSSL_PARAM *keymgmt_import_types(int selection)
{
	static const OSSL_PARAM types[] = {
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_END
	};

	if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
		return types;

	return NULL;
}

/*
 * Extract values indicated by selection from keydata, create an OSSL_PARAM array
 * with them and call param_cb with that array as well as the given cbarg.
 * Used via EVP_PKEY_get_raw_public_key() from private key
 */
static int keymgmt_export(void *provkey, int selection, OSSL_CALLBACK *param_cb,
	void *cbarg)
{
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;

	if (keydata == NULL || param_cb == NULL)
		return 0;

	if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
		return 1;

	switch (p11_keydata_get_type(keydata)) {
	case EVP_PKEY_RSA:
		return export_rsa_pub(keydata, param_cb, cbarg);
	case EVP_PKEY_EC:
		return export_ec_pub(keydata, param_cb, cbarg);
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		return export_eddsa_pub(keydata, param_cb, cbarg);
	default:
		return 0;
    }
}

/* Return supported export parameter types for public key data. */
static const OSSL_PARAM *keymgmt_export_types(int selection)
{
	static const OSSL_PARAM types[] = {
		/* RSA */
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		/* EC, ED25519, ED449 */
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_END
	};

	if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
		return types;

	return NULL;
}

/*
 * Populate requested key attributes, including size, security properties,
 * and encoded public key when available.
 */
static int keymgmt_get_params(void *provkey, OSSL_PARAM params[])
{
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;
	const OSSL_PARAM *key_params;
	const OSSL_PARAM *pub;
	OSSL_PARAM *p;
	int bits, secbits;
#if OPENSSL_VERSION_NUMBER >= 0x30600000L
	int category;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */

	if (keydata == NULL || params == NULL)
		return 0;

	bits = p11_keydata_get_bits(keydata);
	secbits = p11_keydata_get_security_bits(keydata);
#if OPENSSL_VERSION_NUMBER >= 0x30600000L
	category = p11_keydata_get_security_category(keydata);
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */
	key_params = p11_keydata_get_params(keydata);

	/* EVP_PKEY_get_bits(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
	if (p != NULL && !OSSL_PARAM_set_int(p, bits))
		return 0;

	/* EVP_PKEY_get_security_bits(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
	if (p != NULL && !OSSL_PARAM_set_int(p, secbits))
		return 0;

	/* EVP_PKEY_get_size() */
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
	if (p != NULL && !OSSL_PARAM_set_int(p, (int)p11_keydata_get_sigsize(keydata)))
		return 0;

#if OPENSSL_VERSION_NUMBER >= 0x30600000L
	/* EVP_PKEY_get_security_category(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
	if (p != NULL && !OSSL_PARAM_set_int(p, category))
		return 0;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */

	/* EVP_PKEY_get1_encoded_public_key(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
	if (p != NULL &&
	    p11_keydata_get_type(keydata) == EVP_PKEY_EC && key_params != NULL) {
		pub = OSSL_PARAM_locate_const(key_params, OSSL_PKEY_PARAM_PUB_KEY);
		if (pub != NULL && pub->data != NULL &&
		    !OSSL_PARAM_set_octet_string(p, pub->data, pub->data_size))
			return 0;
	}
	return 1;
}

/* Return list of key parameters that can be retrieved from the key object. */
static const OSSL_PARAM *keymgmt_gettable_params(void *provctx)
{
	static const OSSL_PARAM gettable[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
#if OPENSSL_VERSION_NUMBER >= 0x30600000L
		OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY, NULL),
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
		OSSL_PARAM_END
	};
	(void)provctx;
	return gettable;
}

/* Duplicate key object by increasing its reference count.
 * Used via EVP_PKEY_dup(). */
static void *keymgmt_dup(const void *provkey, int selection)
{
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;

	(void)selection;

	if (keydata == NULL)
		return NULL;

	if (!p11_keydata_up_ref(keydata))
		return NULL;

	return keydata;
}

/******************************************************************************/
/* Signature functions                                                        */
/******************************************************************************/

/* Allocate and initialize signature context structure. */
static void *signature_newctx(void *ctx, const char *propq)
{
	return p11_signature_ctx_new(ctx, propq);
}

/* Release signature context and associated resources. */
static void signature_freectx(void *ctx)
{
	p11_signature_ctx_free(ctx);
}

/*
 * Duplicate signature context. Used via EVP_PKEY_CTX_dup().
 * Required by EVP_DigestVerifyFinal() in OpenSSL 3.0.
 * Must be a real duplicate, as finalizing the operation mutates
 * the digest state.
 */
static void *signature_dupctx(void *ctx)
{
	return p11_signature_dupctx(ctx);
}

/*
 * Initialize signature operation for signing precomputed digest data.
 * Used via:
 * EVP_PKEY_sign_init(), EVP_PKEY_sign(),
 * EVP_SignInit(), EVP_SignUpdate(), EVP_SignFinal()
 */
static int signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_signature_ctx_init(ctx, provkey, params);
}

/*
 * Sign input data or return required signature size.
 * Used after signature_sign_init() and via EVP_PKEY_sign().
 */
static int signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
	size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	size_t need;
	int rv;

	if (sig_ctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	need = p11_signature_ctx_get_sigsize(sig_ctx);
	if (need == 0)
		return 0;

	if (sig == NULL) {
		*siglen = need;
		return 1; /* length query */
	}
	if (sigsize < need) {
		*siglen = need;
		return 0; /* buffer too small */
	}

	/* do the signing using your PKCS#11 layer */
	rv = PKCS11_evp_pkey_sign(
		p11_signature_ctx_get_evp_pkey(sig_ctx),
		p11_signature_ctx_get_type(sig_ctx),
		p11_signature_ctx_get_mdname(sig_ctx),
		p11_signature_ctx_get_pad_mode(sig_ctx),
		p11_signature_ctx_get_pss_saltlen(sig_ctx),
		p11_signature_ctx_get_mgf1_mdname(sig_ctx),
		NULL, 0,
		sig, siglen, tbs, tbslen);

	return (rv > 0);
}

/*
 * Initialize verify operation with key.
 * Used via:
 * EVP_PKEY_verify_init(), EVP_PKEY_verify(),
 * EVP_VerifyInit(), EVP_VerifyUpdate(), EVP_VerifyFinal()
 */
static int signature_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_signature_ctx_init(ctx, provkey, params);
}

/*
 * Verify signature against input data.
 * Used after signature_verify_init() and via EVP_PKEY_verify().
 */
static int signature_verify(void *ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	return p11_signature_ctx_verify(ctx, sig, siglen, tbs, tbslen);
}

/*
 * Initialize the signing context.
 * For Ed25519/Ed448, mdname is ignored and one-shot DigestSign is used.
 * For RSA/EC, mdname is required and DigestSignUpdate/Final use mdctx.
 * Used via EVP_DigestSignInit().
 */
static int signature_digest_sign_init(void *ctx, const char *mdname, void *provkey,
	const OSSL_PARAM params[])
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;

	if (sig_ctx == NULL || keydata == NULL)
		return 0;

	if (!p11_signature_ctx_init(sig_ctx, keydata, params))
		return 0;

	if (p11_keydata_get_type(keydata) == EVP_PKEY_ED25519 ||
		p11_keydata_get_type(keydata) == EVP_PKEY_ED448)
		return 1; /* Ed25519 / Ed448 do not use an external digest */

	/* For signature algorithms the default digest algorithm is SHA256 */
	if (mdname == NULL)
		mdname = "SHA256";

	md = EVP_get_digestbyname(mdname);
	if (md == NULL)
		return 0;

	if (!p11_signature_ctx_init_digest(sig_ctx))
		return 0;

	if (!p11_signature_ctx_set_mdname(sig_ctx, mdname))
		return 0;

	mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
	if (mdctx == NULL)
		return 0;

	if (EVP_DigestInit_ex2(mdctx, md, params) != 1)
		return 0;

	return 1;
}
/*
 * Update digest context with input data for signature operation.
 * Used via EVP_DigestSignUpdate().
 */
static int signature_digest_sign_update(void *ctx, const unsigned char *data,
	size_t datalen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	EVP_MD_CTX *mdctx;

	if (sig_ctx == NULL || data == NULL)
		return 0;

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA does not support streaming DigestSignUpdate/Final */
		return 0;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
		if (mdctx == NULL)
			return 0;
		return EVP_DigestUpdate(mdctx, data, datalen) == 1;

	default:
		return 0;
	}
	return 0;
}

/*
 * Finalize digest-based signing operation and produce signature or required size.
 * Used via EVP_DigestSignFinal().
 */
static int signature_digest_sign_final(void *ctx, unsigned char *sig,
	size_t *siglen, size_t sigsize)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	EVP_MD_CTX *mdctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	size_t need, rv;

	if (sig_ctx == NULL || siglen == NULL)
		return 0;

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA should use one-shot signature_digest_sign() */
		return 0;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		break;

	default:
		return 0;
	}

	need = p11_signature_ctx_get_sigsize(sig_ctx);
	if (need == 0)
		return 0;

	if (sig == NULL) {
		*siglen = need;
		return 1; /* length query */
	}

	if (sigsize < need) {
		*siglen = need; /* buffer too small */
		return 0;
	}

	mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
	if (mdctx == NULL)
		return 0;

	if (EVP_DigestFinal_ex(mdctx, md, &mdlen) != 1)
		return 0;

	rv = PKCS11_evp_pkey_sign(
		p11_signature_ctx_get_evp_pkey(sig_ctx),
		p11_signature_ctx_get_type(sig_ctx),
		p11_signature_ctx_get_mdname(sig_ctx),
		p11_signature_ctx_get_pad_mode(sig_ctx),
		p11_signature_ctx_get_pss_saltlen(sig_ctx),
		p11_signature_ctx_get_mgf1_mdname(sig_ctx),
		NULL, 0,
		sig, siglen, md, (size_t)mdlen);

	return (rv > 0);
}

/*
 * Sign input data and produce signature or required size.
 * Used via EVP_DigestSign().
 */
static int signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen,
	size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	const char *mdname;
	const EVP_MD *mdalg;
	size_t need;
	int rv;

	if (sig_ctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	need = p11_signature_ctx_get_sigsize(sig_ctx);
	if (need == 0)
		return 0;

	if (sig == NULL) {
		*siglen = need;
		return 1; /* length query */
	}

	if (sigsize < need) {
		*siglen = need;
		return 0; /* buffer too small */
	}

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA signs the message directly */
		rv = PKCS11_evp_pkey_sign(
			p11_signature_ctx_get_evp_pkey(sig_ctx),
			p11_signature_ctx_get_type(sig_ctx),
			NULL, 0, 0, NULL,
			NULL, 0,
			sig, siglen, tbs, tbslen);
		return (rv > 0);

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		mdname = p11_signature_ctx_get_mdname(sig_ctx);
		if (mdname == NULL)
			return 0;

		mdalg = EVP_get_digestbyname(mdname);
		if (mdalg == NULL)
			return 0;

		if (EVP_Digest(tbs, tbslen, md, &mdlen, mdalg, NULL) != 1)
			return 0;

		rv = PKCS11_evp_pkey_sign(
			p11_signature_ctx_get_evp_pkey(sig_ctx),
			p11_signature_ctx_get_type(sig_ctx),
			p11_signature_ctx_get_mdname(sig_ctx),
			p11_signature_ctx_get_pad_mode(sig_ctx),
			p11_signature_ctx_get_pss_saltlen(sig_ctx),
			p11_signature_ctx_get_mgf1_mdname(sig_ctx),
			NULL, 0,
			sig, siglen, md, (size_t)mdlen);
		return (rv > 0);

	default:
		return 0;
	}
}

/*
 * Initialize the verification context.
 * For Ed25519/Ed448, mdname is ignored and one-shot DigestVerify is used.
 * For RSA/EC, mdname selects the digest used by DigestVerifyUpdate/Final.
 * If not provided, SHA256 is used by default.
 * Used via EVP_DigestVerifyInit().
 */
static int signature_digest_verify_init(void *ctx, const char *mdname,
	void *provkey, const OSSL_PARAM params[])
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;

	if (sig_ctx == NULL || keydata == NULL)
		return 0;

	if (!p11_signature_ctx_init(sig_ctx, keydata, params))
		return 0;

	if (p11_keydata_get_type(keydata) == EVP_PKEY_ED25519 ||
		p11_keydata_get_type(keydata) == EVP_PKEY_ED448)
		return 1; /* Ed25519 / Ed448 do not use an external digest */

	/* For signature algorithms the default digest algorithm is SHA256 */
	if (mdname == NULL)
		mdname = "SHA256";

	md = EVP_get_digestbyname(mdname);
	if (md == NULL)
		return 0;

	if (!p11_signature_ctx_init_digest(sig_ctx))
		return 0;

	if (!p11_signature_ctx_set_mdname(sig_ctx, mdname))
		return 0;

	mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
	if (mdctx == NULL)
		return 0;

	if (EVP_DigestInit_ex2(mdctx, md, params) != 1)
		return 0;

	return 1;
}

/*
 * Update digest context with input data for verify operation.
 * Used via EVP_DigestVerifyUpdate().
 */
static int signature_digest_verify_update(void *ctx, const unsigned char *data,
	size_t datalen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	EVP_MD_CTX *mdctx;

	if (sig_ctx == NULL || data == NULL)
		return 0;

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA does not support streaming DigestVerifyUpdate/Final */
		return 0;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
		if (mdctx == NULL)
			return 0;
		return EVP_DigestUpdate(mdctx, data, datalen) == 1;

	default:
		return 0;
	}
	return 0;
}

/*
 * Finalize digest-based verify operation and verify the signature.
 * Used via EVP_DigestVerifyFinal()
 */
static int signature_digest_verify_final(void *ctx, const unsigned char *sig,
	size_t siglen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	EVP_MD_CTX *mdctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;

	if (sig_ctx == NULL || sig == NULL)
		return 0;

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA should use one-shot EVP_DigestVerify() */
		return 0;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		break;

	default:
		return 0;
	}

	mdctx = p11_signature_ctx_get_mdctx(sig_ctx);
	if (mdctx == NULL)
		return 0;

	if (EVP_DigestFinal_ex(mdctx, md, &mdlen) != 1)
		return 0;

	return p11_signature_ctx_verify(sig_ctx, sig, siglen, md, (size_t)mdlen);
}

/*
 * Verify signature against input data in one-shot digest mode.
 * Used via EVP_DigestVerify().
 */
static int signature_digest_verify(void *ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	const char *mdname;
	const EVP_MD *mdalg;

	if (sig_ctx == NULL || sig == NULL || tbs == NULL)
		return 0;

	switch (p11_signature_ctx_get_type(sig_ctx)) {
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		/* EdDSA verifies the message directly */
		return p11_signature_ctx_verify(sig_ctx, sig, siglen, tbs, tbslen);

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		mdname = p11_signature_ctx_get_mdname(sig_ctx);
		if (mdname == NULL)
			return 0;

		mdalg = EVP_get_digestbyname(mdname);
		if (mdalg == NULL)
			return 0;

		if (EVP_Digest(tbs, tbslen, md, &mdlen, mdalg, NULL) != 1)
			return 0;

		return p11_signature_ctx_verify(sig_ctx, sig, siglen, md, (size_t)mdlen);

	default:
		return 0;
	}
	return 0;
}

/* Get signature context parameters. */
static int signature_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)vctx;
	OSSL_PARAM *p;
	const char *mdname;
	const char *mgf1_mdname;
	const char *pad_mode_str;
	int pad_mode;
	int pss_saltlen;

	if (sig_ctx == NULL)
		return 0;

	if (params == NULL)
		return 1;

	mdname = p11_signature_ctx_get_mdname(sig_ctx);
	pad_mode = p11_signature_ctx_get_pad_mode(sig_ctx);
	mgf1_mdname = p11_signature_ctx_get_mgf1_mdname(sig_ctx);
	pss_saltlen = p11_signature_ctx_get_pss_saltlen(sig_ctx);

	/* digest, EVP_PKEY_CTX_get_signature_md() */
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p != NULL && mdname != NULL) {
		if (!OSSL_PARAM_set_utf8_string(p, mdname))
			return 0;
	}

	/* pad-mode (RSA), EVP_PKEY_CTX_get_rsa_padding() */
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
	if (p != NULL) {
		if (p->data_type == OSSL_PARAM_INTEGER) {
			if (!OSSL_PARAM_set_int(p, pad_mode))
				return 0;
		} else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			pad_mode_str = p11_signature_pad_mode_to_string(pad_mode);
			if (pad_mode_str == NULL ||
			    !OSSL_PARAM_set_utf8_string(p, pad_mode_str))
				return 0;
		}
	}

	/* mgf1-digest,
	 * EVP_PKEY_CTX_get_rsa_mgf1_md(),
	 * EVP_PKEY_CTX_get_rsa_mgf1_md_name() */
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
	if (p != NULL && pad_mode == RSA_PKCS1_PSS_PADDING) {
		const char *mgf1 = (mgf1_mdname != NULL) ? mgf1_mdname : mdname;

		if (mgf1 == NULL || !OSSL_PARAM_set_utf8_string(p, mgf1))
			return 0;
	}

	/* pss-saltlen, EVP_PKEY_CTX_get_rsa_pss_saltlen() */
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
	if (p != NULL && pad_mode == RSA_PKCS1_PSS_PADDING) {
		if (p->data_type == OSSL_PARAM_INTEGER) {
			if (!OSSL_PARAM_set_int(p, pss_saltlen))
				return 0;
		} else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			const char *saltlen_str =
				p11_signature_pss_saltlen_to_string(pss_saltlen);

			if (saltlen_str == NULL ||
			    !OSSL_PARAM_set_utf8_string(p, saltlen_str))
				return 0;
		}
	}
	return 1;
}

/* Return signature context parameters that can be retrieved. */
static const OSSL_PARAM *signature_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM settable[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
		OSSL_PARAM_END
	};

	(void)ctx;
	(void)provctx;
	return settable;
}

/* Set signature context parameters (digest, padding, PSS options) */
static int signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	P11_SIGNATURE_CTX *sig_ctx = (P11_SIGNATURE_CTX *)ctx;
	const OSSL_PARAM *p;
	int pad_mode;

	if (sig_ctx == NULL)
		return 0;

	if (params == NULL)
		return 1;

	/* digest, EVP_PKEY_CTX_set_signature_md() */
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p != NULL) {
		const char *s = NULL;

		if (!OSSL_PARAM_get_utf8_string_ptr(p, &s) || s == NULL)
			return 0;

		if (!p11_signature_ctx_set_mdname(sig_ctx, s))
			return 0;
	}

	/* pad-mode (RSA), EVP_PKEY_CTX_set_rsa_padding(), -pkeyopt rsa_padding_mode */
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
	if (p != NULL) {
		if (!pad_mode_from_param(p, &pad_mode))
			return 0;

		if (!p11_signature_ctx_set_pad_mode(sig_ctx, pad_mode))
			return 0;
	}

	/* PSS-only params (RSA) */
	if (p11_signature_ctx_get_pad_mode(sig_ctx) == RSA_PKCS1_PSS_PADDING) {
		/* mgf1-digest, EVP_PKEY_CTX_set_rsa_mgf1_md() */
		p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
		if (p != NULL) {
			const char *mgf1 = NULL;

			if (!OSSL_PARAM_get_utf8_string_ptr(p, &mgf1) || mgf1 == NULL)
				return 0;

			if (!p11_signature_ctx_set_mgf1_mdname(sig_ctx, mgf1))
				return 0;
		}

		/* pss-saltlen, EVP_PKEY_CTX_set_rsa_pss_saltlen(), -pkeyopt rsa_pss_saltlen */
		p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
		if (p != NULL) {
			int saltlen = 0;
			const char *s = NULL;

			if (OSSL_PARAM_get_int(p, &saltlen)) {
				/* got int directly */
			} else if (OSSL_PARAM_get_utf8_string_ptr(p, &s) && s != NULL) {
				if (OPENSSL_strcasecmp(s, "digest") == 0)
					saltlen = RSA_PSS_SALTLEN_DIGEST; /* -1 */
				else if (OPENSSL_strcasecmp(s, "auto") == 0)
					saltlen = RSA_PSS_SALTLEN_AUTO; /* -2 */
				else if (OPENSSL_strcasecmp(s, "max") == 0)
					saltlen = RSA_PSS_SALTLEN_MAX; /* -3 */
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
				else if (OPENSSL_strcasecmp(s, "auto-digestmax") == 0)
					saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX; /* -4 */
#endif /* RSA_PSS_SALTLEN_AUTO_DIGEST_MAX */
				else
					saltlen = atoi(s); /* minimalistic */
			} else {
				return 0;
			}

			if (!p11_signature_ctx_set_pss_saltlen(sig_ctx, saltlen))
				return 0;
		}
	}
	return 1;
}

/* Return signature context parameters that can be retrieved (same as gettable) */
static const OSSL_PARAM *signature_settable_ctx_params(void *ctx, void *provctx)
{
	return signature_gettable_ctx_params(ctx, provctx);
}


/******************************************************************************/
/* Asymmetric cipher functions                                                */
/******************************************************************************/

/* Create and initialize asymmetric cipher context. */
static void *asym_cipher_newctx(void *ctx)
{
	return p11_asym_cipher_ctx_new(ctx);
}

/* Free asymmetric cipher context. */
static void asym_cipher_freectx(void *ctx)
{
	p11_asym_cipher_ctx_free(ctx);
}

/*
 * Duplicate asymmetric cipher context. Used via EVP_PKEY_CTX_dup().
 * Must be a real duplicate, as the context contains mutable per-operation
 * parameters (padding, OAEP settings) that must not be shared.
 */
static void *asym_cipher_dupctx(void *ctx)
{
	return p11_asym_cipher_dupctx(ctx);
}


/* Initialize encryption operation with key. */
static int asym_cipher_encrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_asym_cipher_ctx_init(ctx, provkey, params);
}

/* Encrypt input data with asymmetric cipher context. */
static int asym_cipher_encrypt(void *ctx, unsigned char *out, size_t *outlen,
	size_t outsize, const unsigned char *in, size_t inlen)
{
	P11_ASYM_CIPHER_CTX *asym_ctx = (P11_ASYM_CIPHER_CTX *)ctx;
	int rv;

	if (asym_ctx == NULL)
		return 0;

	rv = p11_asym_cipher_ctx_encrypt(asym_ctx, out, outlen, outsize, in, inlen);
	if (rv <= 0)
		return 0;
	return 1;
}

/* Initialize decryption operation with key */
static int asym_cipher_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_asym_cipher_ctx_init(ctx, provkey, params);
}

/* Decrypt input data using asymmetric cipher context or return required output size. */
static int asym_cipher_decrypt(void *ctx, unsigned char *out, size_t *outlen,
	size_t outsize, const unsigned char *in, size_t inlen)
{
	P11_ASYM_CIPHER_CTX *asym_ctx = (P11_ASYM_CIPHER_CTX *)ctx;
	size_t need;
	int rv;

	if (asym_ctx == NULL || outlen == NULL || in == NULL)
		return 0;

	need = p11_asym_cipher_ctx_get_outsize(asym_ctx);
	if (need == 0)
		return 0;

	if (out == NULL) {
		/* For RSA decrypt the plaintext is at most modulus size.
		 * The exact OAEP plaintext length is only known after decrypt,
		 * so return a safe upper bound. */
		*outlen = need; /* length query */
		return 1;
	}

	if (outsize < need) {
		*outlen = need;
		return 0; /* buffer too small */
	}

	rv = PKCS11_evp_pkey_decrypt(
		p11_asym_cipher_ctx_get_evp_pkey(asym_ctx),
		p11_asym_cipher_ctx_get_type(asym_ctx),
		p11_asym_cipher_ctx_get_oaep_mdname(asym_ctx),
		p11_asym_cipher_ctx_get_pad_mode(asym_ctx),
		p11_asym_cipher_ctx_get_mgf1_mdname(asym_ctx),
		p11_asym_cipher_ctx_get_oaep_label(asym_ctx),
		p11_asym_cipher_ctx_get_oaep_labellen(asym_ctx),
		out, outlen, &outsize, in, inlen);
	return (rv > 0);
}

/* Get asymmetric cipher context parameters. */
static int asym_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	P11_ASYM_CIPHER_CTX *asym_ctx = (P11_ASYM_CIPHER_CTX *)vctx;
	OSSL_PARAM *p;
	const char *pad_mode_str = NULL;
	const char *oaep_mdname;
	const char *mgf1_mdname;
	int pad_mode;

	if (asym_ctx == NULL)
		return 0;

	if (params == NULL)
		return 1;

	pad_mode = p11_asym_cipher_ctx_get_pad_mode(asym_ctx);

	/* defaults */
	oaep_mdname = p11_asym_cipher_ctx_get_oaep_mdname(asym_ctx);
	if (oaep_mdname == NULL)
		oaep_mdname = "SHA1";

	mgf1_mdname = p11_asym_cipher_ctx_get_mgf1_mdname(asym_ctx);
	if (mgf1_mdname == NULL)
		mgf1_mdname = oaep_mdname;

	switch (pad_mode) {
	case RSA_NO_PADDING:
		pad_mode_str = OSSL_PKEY_RSA_PAD_MODE_NONE;
		break;
	case RSA_PKCS1_PADDING:
		pad_mode_str = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
		break;
	case RSA_PKCS1_OAEP_PADDING:
		pad_mode_str = OSSL_PKEY_RSA_PAD_MODE_OAEP;
		break;
	default:
		pad_mode_str = NULL;
		break;
	}

	/* EVP_PKEY_CTX_get_rsa_padding(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
	if (p != NULL) {
		if (p->data_type == OSSL_PARAM_INTEGER) {
			if (!OSSL_PARAM_set_int(p, pad_mode))
				return 0;
		} else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			if (pad_mode_str == NULL ||
			    !OSSL_PARAM_set_utf8_string(p, pad_mode_str))
				return 0;
		}
	}

	/* EVP_PKEY_CTX_get_rsa_oaep_md(), not covered by tests
	 * EVP_PKEY_CTX_get_rsa_oaep_md_name(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
	if (p != NULL && pad_mode == RSA_PKCS1_OAEP_PADDING &&
		!OSSL_PARAM_set_utf8_string(p, oaep_mdname))
		return 0;

	/* EVP_PKEY_CTX_get_rsa_mgf1_md(), not covered by tests
	 * EVP_PKEY_CTX_get_rsa_mgf1_md_name(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
	if (p != NULL && pad_mode == RSA_PKCS1_OAEP_PADDING &&
		!OSSL_PARAM_set_utf8_string(p, mgf1_mdname))
		return 0;

	/* EVP_PKEY_CTX_get0_rsa_oaep_label(), not covered by tests */
	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
	if (p != NULL && pad_mode == RSA_PKCS1_OAEP_PADDING) {
		unsigned char *label = p11_asym_cipher_ctx_get_oaep_label(asym_ctx);
		size_t labellen = p11_asym_cipher_ctx_get_oaep_labellen(asym_ctx);

		if (label != NULL) {
			if (!OSSL_PARAM_set_octet_string(p, label, labellen))
				return 0;
		} else {
			if (!OSSL_PARAM_set_octet_string(p, NULL, 0))
				return 0;
		}
	}
	return 1;
}

/* Return asymmetric cipher context parameters that can be retrieved. */
static const OSSL_PARAM *asym_cipher_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM gettable[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
		OSSL_PARAM_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
		OSSL_PARAM_END
	};

	(void)ctx;
	(void)provctx;
	return gettable;
}

/* Set asymmetric cipher context parameters from OSSL_PARAM input */
static int asym_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	P11_ASYM_CIPHER_CTX *asym_ctx = (P11_ASYM_CIPHER_CTX *)vctx;
	const OSSL_PARAM *p;
	const char *str = NULL;
	int pad_mode;

	if (asym_ctx == NULL)
		return 0;

	if (params == NULL)
		return 1;

	/* PAD_MODE (can be int or string)
	 * EVP_PKEY_CTX_set_rsa_padding(), -pkeyopt rsa_padding_mode:oaep */
	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
	if (p != NULL) {
		if (!pad_mode_from_param(p, &pad_mode))
			return 0;

		if (!p11_asym_cipher_ctx_set_pad_mode(asym_ctx, pad_mode))
			return 0;
	}

	/* OAEP digest
	 * EVP_PKEY_CTX_set_rsa_oaep_md(), not covered by tests
	 * EVP_PKEY_CTX_set_rsa_oaep_md_name(), not covered by tests */
	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
	if (p != NULL) {
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str) || str == NULL)
			return 0;

		if (!p11_asym_cipher_ctx_set_oaep_mdname(asym_ctx, str))
			return 0;
	}

	/* MGF1 digest
	 * EVP_PKEY_CTX_set_rsa_mgf1_md(), not covered by tests
	 * EVP_PKEY_CTX_set_rsa_mgf1_md_name(), not covered by tests */
	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
	if (p != NULL) {
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str) || str == NULL)
			return 0;

		if (!p11_asym_cipher_ctx_set_mgf1_mdname(asym_ctx, str))
			return 0;
	}

	/* OAEP label
	 * EVP_PKEY_CTX_set0_rsa_oaep_label(), not covered by tests */
	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
	if (p != NULL) {
		if (p->data_type != OSSL_PARAM_OCTET_STRING)
			return 0;

		if (p->data_size > 0 && p->data == NULL)
			return 0;

		if (!p11_asym_cipher_ctx_set_oaep_label(asym_ctx, p->data, p->data_size))
			return 0;
	}

	return 1;
}

/* Return asymmetric cipher context parameters that can be set (same as gettable) */
static const OSSL_PARAM *asym_cipher_settable_ctx_params(void *ctx, void *provctx)
{
	return asym_cipher_gettable_ctx_params(ctx, provctx);
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
	if (!PROVIDER_CTX_is_initialized(prov_ctx)) {
		/* Set parameters into the util_ctx */
		if (!PROVIDER_CTX_set_parameters(prov_ctx)) {
			PROVIDER_CTX_log(prov_ctx, LOG_ERR, 2, OPENSSL_LINE, OPENSSL_FUNC, NULL);
			return NULL;
		}
	}
	PROVIDER_CTX_initialize(prov_ctx);

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
 * Set store context parameters.
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
		PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 3, OPENSSL_LINE,
			OPENSSL_FUNC, NULL);
		return 0;
	}

	param = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
	if (param != NULL) {
		char *propq = NULL;

		if (!OSSL_PARAM_get_utf8_string(param, &propq, 0)) {
			PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 3,
				OPENSSL_LINE, OPENSSL_FUNC, NULL);
			return 0;
		}

		OPENSSL_free(store_ctx->propq);
		store_ctx->propq = propq;
	}

	return 1;
}

/*
 * Returns a constant array of descriptor OSSL_PARAM(3), for parameters that
 * p11_store_set_ctx_params() can handle.
 */
static const OSSL_PARAM *store_settable_ctx_params(void *ctx)
{
	static const OSSL_PARAM settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
		OSSL_PARAM_END
	};

	(void)(ctx);
	return settable_ctx_params;
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

	/* try fetching a certificate  */
	if (store_ctx->types_tried == 0) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type ==  OSSL_STORE_INFO_CERT) {
			X509 *cert = PROVIDER_CTX_get_cert_from_uri(store_ctx->prov_ctx,
				store_ctx->uri, ui_method, ui_data);

			if (cert != NULL) {
				/* If we have a data type, it should be a PEM name */
				const char *data_type = "PEM_STRING_X509";
				int object_type = OSSL_OBJECT_CERT;
				unsigned char *tmp, *data = NULL;
				OSSL_PARAM params[4], *p = params;
				int len = i2d_X509(cert, NULL);

				if (len < 0) {
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 4, OPENSSL_LINE, OPENSSL_FUNC, "%s", store_ctx->uri);
					X509_free(cert);
					return 0;
				}
				tmp = data = OPENSSL_malloc((size_t)len);
				if (!tmp) {
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 1, OPENSSL_LINE, OPENSSL_FUNC, "%s", store_ctx->uri);
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
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 5, OPENSSL_LINE, OPENSSL_FUNC, "%s", store_ctx->uri);
					OPENSSL_free(data);
					return 0;
				}
				OPENSSL_free(data);
				return 1;
			}
		}
	}
	/* try fetching a public key */
	if (store_ctx->types_tried == 1) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type == OSSL_STORE_INFO_PUBKEY) {
			EVP_PKEY *key = PROVIDER_CTX_get_pubkey_from_uri(store_ctx->prov_ctx,
				store_ctx->uri, ui_method, ui_data);
			P11_KEYDATA *keydata = p11_keydata_from_evp_pkey(store_ctx->prov_ctx, key, 0);

			EVP_PKEY_free(key);
			if (keydata != NULL) {
				int object_type = OSSL_OBJECT_PKEY;
				OSSL_PARAM params[4], *p = params;

				*p++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)p11_keydata_get_name(keydata), 0);
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &keydata, sizeof(keydata));
				*p = OSSL_PARAM_construct_end();

				if (!object_cb(params, object_cbarg)) {
					/* callback failed */
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 5, OPENSSL_LINE, OPENSSL_FUNC, "%s", store_ctx->uri);
					p11_keydata_free(keydata);
					return 0;
				}
				p11_keydata_free(keydata);
				return 1;
			}
		}
	}
	/* try fetching a private key */
	if (store_ctx->types_tried == 2) {
		store_ctx->types_tried++;
		if (store_ctx->expected_type == 0 || store_ctx->expected_type == OSSL_STORE_INFO_PKEY) {
			EVP_PKEY *key = PROVIDER_CTX_get_privkey_from_uri(store_ctx->prov_ctx,
				store_ctx->uri, ui_method, ui_data);
			P11_KEYDATA *keydata = p11_keydata_from_evp_pkey(store_ctx->prov_ctx, key, 1);

			EVP_PKEY_free(key);
			PROVIDER_CTX_set_ui_method(store_ctx->prov_ctx, ui_method, NULL);
			if (keydata != NULL) {
				int object_type = OSSL_OBJECT_PKEY;
				OSSL_PARAM params[4], *p = params;

				*p++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)p11_keydata_get_name(keydata), 0);
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &keydata, sizeof(keydata));
				*p = OSSL_PARAM_construct_end();

				if (!object_cb(params, object_cbarg)) {
					/* callback failed */
					PROVIDER_CTX_log(store_ctx->prov_ctx, LOG_ERR, 5, OPENSSL_LINE, OPENSSL_FUNC, "%s", store_ctx->uri);
					p11_keydata_free(keydata);
					return 0;
				}
				p11_keydata_free(keydata);
				return 1;
			}
		}
	}
	return 0;
}

/*
 * Indicates whether all expected objects from the URI have been processed.
 * The expected sequence is:
 * 0 - OSSL_STORE_INFO_CERT   - X.509 certificate (X509 *)
 * 1 - OSSL_STORE_INFO_PUBKEY - public key (EVP_PKEY *)
 * 2 - OSSL_STORE_INFO_PKEY   - private key (EVP_PKEY *)
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

	OPENSSL_free(store_ctx->propq);
	OPENSSL_free(store_ctx->uri);
	OPENSSL_free(store_ctx);
	return 1;
}

/* vim: set noexpandtab: */
