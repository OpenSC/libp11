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

#define PKCS11_PROPQ "provider=pkcs11prov"

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
PROVIDER_FN(keymgmt_gen_set_params);
PROVIDER_FN(keymgmt_gen);
PROVIDER_FN(keymgmt_gen_cleanup);

PROVIDER_FN(signature_newctx);
PROVIDER_FN(signature_freectx);
PROVIDER_FN(signature_dupctx);
PROVIDER_FN(signature_sign_init);
PROVIDER_FN(signature_sign);
PROVIDER_FN(signature_verify_init);
PROVIDER_FN(signature_verify);
PROVIDER_FN(signature_verify_recover_init);
PROVIDER_FN(signature_verify_recover);
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

PROVIDER_FN(keyexch_newctx);
PROVIDER_FN(keyexch_freectx);
PROVIDER_FN(keyexch_dupctx);
PROVIDER_FN(keyexch_init);
PROVIDER_FN(keyexch_set_peer);
PROVIDER_FN(keyexch_derive);
PROVIDER_FN(keyexch_set_ctx_params);
PROVIDER_FN(keyexch_settable_ctx_params);
PROVIDER_FN(keyexch_get_ctx_params);
PROVIDER_FN(keyexch_gettable_ctx_params);

PROVIDER_FN(kem_newctx);
PROVIDER_FN(kem_freectx);
PROVIDER_FN(kem_dupctx);
PROVIDER_FN(kem_encapsulate_init);
PROVIDER_FN(kem_encapsulate);
PROVIDER_FN(kem_decapsulate_init);
PROVIDER_FN(kem_decapsulate);
PROVIDER_FN(kem_get_ctx_params);
PROVIDER_FN(kem_gettable_ctx_params);
PROVIDER_FN(kem_set_ctx_params);
PROVIDER_FN(kem_settable_ctx_params);

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

static const OSSL_DISPATCH signature_functions[] = {
	{OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))signature_newctx},
	{OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))signature_freectx},
	{OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))signature_dupctx},
	{OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))signature_sign_init},
	{OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))signature_sign},
	{OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))signature_verify_init},
	{OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))signature_verify},
	{OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))signature_verify_recover_init},
	{OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void))signature_verify_recover},
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

static const OSSL_DISPATCH keyexch_functions[] = {
	{OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))keyexch_newctx},
	{OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))keyexch_freectx},
	{OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))keyexch_dupctx},
	{OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))keyexch_init},
	{OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))keyexch_set_peer},
	{OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))keyexch_derive},
	{OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))keyexch_get_ctx_params},
	{OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))keyexch_gettable_ctx_params},
	{OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))keyexch_set_ctx_params},
	{OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))keyexch_settable_ctx_params},
	OSSL_DISPATCH_END
};

static const OSSL_DISPATCH asym_kem_functions[] = {
	{OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kem_newctx},
	{OSSL_FUNC_KEM_FREECTX, (void (*)(void))kem_freectx},
	{OSSL_FUNC_KEM_DUPCTX, (void (*)(void))kem_dupctx},
	{OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kem_encapsulate_init},
	{OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate},
	{OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kem_decapsulate_init},
	{OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kem_decapsulate},
	{OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))kem_get_ctx_params},
	{OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))kem_gettable_ctx_params},
	{OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))kem_set_ctx_params},
	{OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))kem_settable_ctx_params},
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

#define KEYMGMT_COMMON_DISPATCH \
	{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keymgmt_new}, \
	{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keymgmt_load}, \
	{OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keymgmt_free}, \
	{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keymgmt_has}, \
	{OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keymgmt_match}, \
	{OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, \
		(void (*)(void))keymgmt_query_operation_name}, \
	{OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))keymgmt_import}, \
	{OSSL_FUNC_KEYMGMT_IMPORT_TYPES, \
		(void (*)(void))keymgmt_import_types}, \
	{OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))keymgmt_export}, \
	{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, \
		(void (*)(void))keymgmt_export_types}, \
	{OSSL_FUNC_KEYMGMT_GET_PARAMS, \
		(void (*)(void))keymgmt_get_params}, \
	{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, \
		(void (*)(void))keymgmt_gettable_params}, \
	{OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))keymgmt_dup}

#define KEYMGMT_GEN_DISPATCH(gen_init, gen_settable) \
	{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))(gen_init)}, \
	{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, \
		(void (*)(void))keymgmt_gen_set_params}, \
	{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, \
		(void (*)(void))(gen_settable)}, \
	{OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))keymgmt_gen}, \
	{OSSL_FUNC_KEYMGMT_GEN_CLEANUP, \
		(void (*)(void))keymgmt_gen_cleanup}

static OSSL_FUNC_keymgmt_gen_settable_params_fn rsa_keymgmt_gen_settable_params;

#ifndef OPENSSL_NO_EC
static OSSL_FUNC_keymgmt_gen_settable_params_fn ec_keymgmt_gen_settable_params;
#endif /* OPENSSL_NO_EC */

static OSSL_FUNC_keymgmt_gen_settable_params_fn common_keymgmt_gen_settable_params;

static void *keymgmt_gen_init_common(void *provctx, int type,
	int selection, const OSSL_PARAM params[]);

#define DEFINE_KEYMGMT_FUNCTIONS(name, type, gen_settable) \
	static void *name##_keymgmt_gen_init(void *provctx, int selection, \
		const OSSL_PARAM params[]) \
	{ \
		return keymgmt_gen_init_common(provctx, type, selection, params); \
	} \
	static const OSSL_DISPATCH name##_keymgmt_functions[] = { \
		KEYMGMT_COMMON_DISPATCH, \
		KEYMGMT_GEN_DISPATCH(name##_keymgmt_gen_init, gen_settable), \
		OSSL_DISPATCH_END \
	};

DEFINE_KEYMGMT_FUNCTIONS(rsa, EVP_PKEY_RSA, rsa_keymgmt_gen_settable_params)

#ifndef OPENSSL_NO_EC
DEFINE_KEYMGMT_FUNCTIONS(ec, EVP_PKEY_EC, ec_keymgmt_gen_settable_params)
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_ECX
DEFINE_KEYMGMT_FUNCTIONS(ed25519, EVP_PKEY_ED25519,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(ed448, EVP_PKEY_ED448,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(x25519, EVP_PKEY_X25519,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(x448, EVP_PKEY_X448,
	common_keymgmt_gen_settable_params)
#endif /* OPENSSL_NO_ECX */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
DEFINE_KEYMGMT_FUNCTIONS(mldsa44, EVP_PKEY_ML_DSA_44,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(mldsa65, EVP_PKEY_ML_DSA_65,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(mldsa87, EVP_PKEY_ML_DSA_87,
	common_keymgmt_gen_settable_params)
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_ML_KEM
DEFINE_KEYMGMT_FUNCTIONS(mlkem512, EVP_PKEY_ML_KEM_512,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(mlkem768, EVP_PKEY_ML_KEM_768,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(mlkem1024, EVP_PKEY_ML_KEM_1024,
	common_keymgmt_gen_settable_params)
#endif /* OPENSSL_NO_ML_KEM */

#ifndef OPENSSL_NO_SLH_DSA
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_128s, EVP_PKEY_SLH_DSA_SHA2_128S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_128f, EVP_PKEY_SLH_DSA_SHA2_128F,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_192s, EVP_PKEY_SLH_DSA_SHA2_192S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_192f, EVP_PKEY_SLH_DSA_SHA2_192F,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_256s, EVP_PKEY_SLH_DSA_SHA2_256S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_sha2_256f, EVP_PKEY_SLH_DSA_SHA2_256F,
	common_keymgmt_gen_settable_params)

DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_128s, EVP_PKEY_SLH_DSA_SHAKE_128S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_128f, EVP_PKEY_SLH_DSA_SHAKE_128F,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_192s, EVP_PKEY_SLH_DSA_SHAKE_192S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_192f, EVP_PKEY_SLH_DSA_SHAKE_192F,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_256s, EVP_PKEY_SLH_DSA_SHAKE_256S,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(slhdsa_shake_256f, EVP_PKEY_SLH_DSA_SHAKE_256F,
	common_keymgmt_gen_settable_params)
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

DEFINE_KEYMGMT_FUNCTIONS(falcon512, EVP_PKEY_FALCON512,
	common_keymgmt_gen_settable_params)
DEFINE_KEYMGMT_FUNCTIONS(falcon1024, EVP_PKEY_FALCON1024,
	common_keymgmt_gen_settable_params)


/*
 * Keymgmt algorithms: must be real key types (e.g. RSA, EC), not provider names.
 */
static const OSSL_ALGORITHM p11_keymgmts[] = {
	{"RSA:rsaEncryption", PKCS11_PROPQ, rsa_keymgmt_functions,
		"PKCS#11 RSA keymgm functions"},
#ifndef OPENSSL_NO_EC
	{"EC:id-ecPublicKey", PKCS11_PROPQ, ec_keymgmt_functions,
		"PKCS#11 EC keymgm functions"},
	{"ECDH", PKCS11_PROPQ, ec_keymgmt_functions,
		"PKCS#11 key exchange functions"},
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ECX
	{"ED25519", PKCS11_PROPQ, ed25519_keymgmt_functions,
		"PKCS#11 Ed25519 keymgm functions"},
	{"ED448", PKCS11_PROPQ, ed448_keymgmt_functions,
		"PKCS#11 Ed448 keymgm functions"},
	{"X25519", PKCS11_PROPQ, x25519_keymgmt_functions,
		"PKCS#11 X25519 keymgm functions"},
	{"X448", PKCS11_PROPQ, x448_keymgmt_functions,
		"PKCS#11 X448 keymgm functions"},
#endif /* OPENSSL_NO_ECX */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
	{"ML-DSA-44", PKCS11_PROPQ, mldsa44_keymgmt_functions,
		"PKCS#11 ML-DSA-44 keymgmt functions"},
	{"ML-DSA-65", PKCS11_PROPQ, mldsa65_keymgmt_functions,
		"PKCS#11 ML-DSA-65 keymgmt functions"},
	{"ML-DSA-87", PKCS11_PROPQ, mldsa87_keymgmt_functions,
		"PKCS#11 ML-DSA-87 keymgmt functions"},
#endif /* OPENSSL_NO_ML_DSA */
#ifndef OPENSSL_NO_ML_KEM
	{"ML-KEM-512", PKCS11_PROPQ, mlkem512_keymgmt_functions,
		"PKCS#11 ML-KEM-512 keymgmt functions"},
	{"ML-KEM-768", PKCS11_PROPQ, mlkem768_keymgmt_functions,
		"PKCS#11 ML-KEM-768 keymgmt functions"},
	{"ML-KEM-1024", PKCS11_PROPQ, mlkem1024_keymgmt_functions,
		"PKCS#11 ML-KEM-1024 keymgmt functions"},
#endif /* OPENSSL_NO_ML_KEM */
#ifndef OPENSSL_NO_SLH_DSA
	{"SLH-DSA-SHA2-128s", PKCS11_PROPQ, slhdsa_sha2_128s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-128s keymgmt functions"},
	{"SLH-DSA-SHA2-128f", PKCS11_PROPQ, slhdsa_sha2_128f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-128f keymgmt functions"},
	{"SLH-DSA-SHA2-192s", PKCS11_PROPQ, slhdsa_sha2_192s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-192s keymgmt functions"},
	{"SLH-DSA-SHA2-192f", PKCS11_PROPQ, slhdsa_sha2_192f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-192f keymgmt functions"},
	{"SLH-DSA-SHA2-256s", PKCS11_PROPQ, slhdsa_sha2_256s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-256s keymgmt functions"},
	{"SLH-DSA-SHA2-256f", PKCS11_PROPQ, slhdsa_sha2_256f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHA2-256f keymgmt functions"},
	{"SLH-DSA-SHAKE-128s", PKCS11_PROPQ, slhdsa_shake_128s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-128s keymgmt functions"},
	{"SLH-DSA-SHAKE-128f", PKCS11_PROPQ, slhdsa_shake_128f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-128f keymgmt functions"},
	{"SLH-DSA-SHAKE-192s", PKCS11_PROPQ, slhdsa_shake_192s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-192s keymgmt functions"},
	{"SLH-DSA-SHAKE-192f", PKCS11_PROPQ, slhdsa_shake_192f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-192f keymgmt functions"},
	{"SLH-DSA-SHAKE-256s", PKCS11_PROPQ, slhdsa_shake_256s_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-256s keymgmt functions"},
	{"SLH-DSA-SHAKE-256f", PKCS11_PROPQ, slhdsa_shake_256f_keymgmt_functions,
		"PKCS#11 SLH-DSA-SHAKE-256f keymgmt functions"},
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */
	{"FALCON-512:FN-DSA-512:falcon512", PKCS11_PROPQ, falcon512_keymgmt_functions,
		"PKCS#11 Falcon-512 keymgmt"},
	{"FALCON-1024:FN-DSA-1024:falcon1024", PKCS11_PROPQ, falcon1024_keymgmt_functions,
		"PKCS#11 Falcon-1024 keymgmt"},
	{NULL, NULL, NULL, NULL}
};

const OSSL_ALGORITHM p11_signatures[] = {
	{"PKCS11", PKCS11_PROPQ, signature_functions, "PKCS#11 signature functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_asym_cipher[] = {
	{"PKCS11", PKCS11_PROPQ, asym_cipher_functions, "PKCS#11 asym_cipher functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_keyexch[] = {
	{"PKCS11", PKCS11_PROPQ, keyexch_functions, "PKCS#11 key exchange functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_asym_kem[] = {
	{"PKCS11", PKCS11_PROPQ, asym_kem_functions, "PKCS#11 asymmetric kem functions"},
	{NULL, NULL, NULL, NULL}
};

static const OSSL_ALGORITHM p11_storemgmt[] = {
	{"PKCS11", PKCS11_PROPQ, store_functions, "PKCS#11 storage functions"},
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

	ERR_load_P11_strings();

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
	ERR_unload_P11_strings();
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
	case OSSL_OP_KEYEXCH:
		return p11_keyexch;
	case OSSL_OP_KEM:
		return p11_asym_kem;
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
			/* validate whether the private keys match, not covered by tests
			 * TODO
			 * key_checked = p11_keydata_is_private(keydata1) &&
			 * p11_keydata_is_private(keydata2) &&
			 * p11_private_equal(keydata1, keydata2);
			 */
			key_checked = 0;
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
	case OSSL_OP_KEYEXCH:
	case OSSL_OP_KEM:
		return "PKCS11";
	}
	return NULL;
}

/* Import public key parameters into key object from OSSL_PARAM array. */
static int keymgmt_import(void *provkey, int selection, const OSSL_PARAM *params)
{
	P11_KEYDATA *keydata = (P11_KEYDATA *)provkey;

	if (keydata == NULL)
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

	return p11_keydata_export_pub(keydata, param_cb, cbarg);
}

/* Return supported export parameter types for public key data. */
static const OSSL_PARAM *keymgmt_export_types(int selection)
{
	static const OSSL_PARAM types[] = {
		/* RSA */
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		/* EC, ED25519, ED449, X25519, X448 */
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
	return p11_keymgmt_get_params(provkey, params);
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
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
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

/*
 * KEYMGMT generation initialization needs to know the concrete key type.
 * The remaining KEYMGMT callbacks are shared by all supported algorithms.
 */
static void *keymgmt_gen_init_common(void *provctx, int type,
	int selection, const OSSL_PARAM params[])
{
	if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
		return NULL;

	return p11_keygen_ctx_new(provctx, type, params);
}

/* Set additional parameters from params in the key object generation context genctx. */
static int keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	return p11_keygen_ctx_set_params(genctx, params);
}

static const OSSL_PARAM *rsa_keymgmt_gen_settable_params(
	void *genctx, void *provctx)
{
	static const OSSL_PARAM keymgmt_gen_settable_rsa[] = {
		OSSL_PARAM_utf8_string("pkcs11_uri", NULL, 0),
		OSSL_PARAM_uint(OSSL_PKEY_PARAM_RSA_BITS, NULL),
		OSSL_PARAM_END
	};

	(void)genctx;
	(void)provctx;
	return keymgmt_gen_settable_rsa;
}

#ifndef OPENSSL_NO_EC
static const OSSL_PARAM *ec_keymgmt_gen_settable_params(
	void *genctx, void *provctx)
{
	static const OSSL_PARAM keymgmt_gen_settable_ec[] = {
		OSSL_PARAM_utf8_string("pkcs11_uri", NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_END
	};

	(void)genctx;
	(void)provctx;
	return keymgmt_gen_settable_ec;
}
#endif /* OPENSSL_NO_EC */

static const OSSL_PARAM *common_keymgmt_gen_settable_params(
	void *genctx, void *provctx)
{
	static const OSSL_PARAM keymgmt_gen_settable_common[] = {
		OSSL_PARAM_utf8_string("pkcs11_uri", NULL, 0),
		OSSL_PARAM_END
	};

	(void)genctx;
	(void)provctx;
	return keymgmt_gen_settable_common;
}

/* Perform the key object generation itself, and return the result. */
static void *keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
	(void)cb;
	(void)cbarg;
	return p11_keygen_ctx_generate(genctx);
}

/* Clean up and free the key object generation context. */
static void keymgmt_gen_cleanup(void *genctx)
{
	p11_keygen_ctx_free(genctx);
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
	return p11_signature_ctx_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
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
 * Initialize signature recovery verification operation with key.
 * Used via EVP_PKEY_verify_recover_init().
 */
static int signature_verify_recover_init(void *ctx, void *keydata, const OSSL_PARAM params[])
{
	return p11_signature_ctx_init(ctx, keydata, params);
}

/*
 * Recover signed data from signature.
 * Used after signature_verify_recover_init() and via EVP_PKEY_verify_recover().
 */
static int signature_verify_recover(void *ctx, unsigned char *rout, size_t *routlen,
	size_t routsize, const unsigned char *sig, size_t siglen)
{
	return p11_signature_ctx_verifyrecover(ctx, rout, routlen, routsize, sig, siglen);
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
	return p11_signature_digest_sign_init(ctx, mdname, provkey, params);
}

/*
 * Update digest context with input data for signature operation.
 * Used via EVP_DigestSignUpdate().
 */
static int signature_digest_sign_update(void *ctx, const unsigned char *data,
	size_t datalen)
{
	return p11_signature_digest_sign_update(ctx, data, datalen);
}

/*
 * Finalize digest-based signing operation and produce signature or required size.
 * Used via EVP_DigestSignFinal().
 */
static int signature_digest_sign_final(void *ctx, unsigned char *sig,
	size_t *siglen, size_t sigsize)
{
	return p11_signature_digest_sign_final(ctx, sig, siglen, sigsize);
}

/*
 * Sign input data and produce signature or required size.
 * Used via EVP_DigestSign().
 */
static int signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen,
	size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	return p11_signature_digest_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
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
	return p11_signature_digest_verify_init(ctx, mdname, provkey, params);
}

/*
 * Update digest context with input data for verify operation.
 * Used via EVP_DigestVerifyUpdate().
 */
static int signature_digest_verify_update(void *ctx, const unsigned char *data,
	size_t datalen)
{
	return p11_signature_digest_verify_update(ctx, data, datalen);
}

/*
 * Finalize digest-based verify operation and verify the signature.
 * Used via EVP_DigestVerifyFinal()
 */
static int signature_digest_verify_final(void *ctx, const unsigned char *sig,
	size_t siglen)
{
	return p11_signature_digest_verify_final(ctx, sig, siglen);
}

/*
 * Verify signature against input data in one-shot digest mode.
 * Used via EVP_DigestVerify().
 */
static int signature_digest_verify(void *ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	return p11_signature_digest_verify(ctx, sig, siglen, tbs, tbslen);
}

/* Get signature context parameters, EVP_PKEY_CTX_get_params(). */
static int signature_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	return p11_signature_ctx_get_params(vctx, params);
}

/* Return signature context parameters that can be retrieved. */
static const OSSL_PARAM *signature_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM gettable[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
		OSSL_PARAM_END
	};

	(void)ctx;
	(void)provctx;
	return gettable;
}

/* Set signature context parameters (digest, padding, PSS options) */
static int signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	return p11_signature_ctx_set_params(ctx, params);
}

/* Return signature context parameters that can be retrieved */
static const OSSL_PARAM *signature_settable_ctx_params(void *ctx, void *provctx)
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
	return p11_asym_cipher_ctx_encrypt(ctx, out, outlen, outsize, in, inlen);
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
	return p11_asym_cipher_ctx_decrypt(ctx, out, outlen, outsize, in, inlen);
}

/* Get asymmetric cipher context parameters. */
static int asym_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	return p11_asym_cipher_ctx_get_params(vctx, params);
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
	return p11_asym_cipher_ctx_set_params(vctx, params);
}

/* Return asymmetric cipher context parameters that can be set (same as gettable) */
static const OSSL_PARAM *asym_cipher_settable_ctx_params(void *ctx, void *provctx)
{
	return asym_cipher_gettable_ctx_params(ctx, provctx);
}


/******************************************************************************/
/* Key exchange functions                                                     */
/******************************************************************************/

/* Create and initialize key exchange context. */
static void *keyexch_newctx(void *provctx)
{
	return p11_keyexch_ctx_new(provctx);
}

/* Free key exchange context. */
static void keyexch_freectx(void *ctx)
{
	p11_keyexch_ctx_free(ctx);
}

/* Duplicate key exchange context. */
static void *keyexch_dupctx(void *ctx)
{
	return p11_keyexch_dupctx(ctx);
}

/* Initialize a key exchange operation with the local private key. */
static int keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_keyexch_ctx_init(ctx, provkey, params);
}

/* Set the peer public key for shared-secret derivation. */
static int keyexch_set_peer(void *ctx, void *provkey)
{
	return p11_keyexch_ctx_set_peer(ctx, provkey);
}

/* Derive the shared secret, or return the required output size. */
static int keyexch_derive(void *ctx,
	unsigned char *secret, size_t *secretlen, size_t outlen)
{
	return p11_keyexch_ctx_derive(ctx, secret, secretlen, outlen);
}

/* Return current key exchange context parameters. */
static int keyexch_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
	return p11_keyexch_ctx_get_params(ctx, params);
}

/* Return the list of gettable key exchange context parameters. */
static const OSSL_PARAM *keyexch_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM gettable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
		OSSL_PARAM_END
	};

	(void)ctx;
	(void)provctx;
	return gettable_ctx_params;
}

/* Set key exchange context parameters. */
static int keyexch_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	return p11_keyexch_ctx_set_params(ctx, params);
}

/* Return the list of settable key exchange context parameters (same as gettable). */
static const OSSL_PARAM *keyexch_settable_ctx_params(void *ctx, void *provctx)
{
	return keyexch_gettable_ctx_params(ctx, provctx);
}


/******************************************************************************/
/* Asymmetric kem functions                                                   */
/******************************************************************************/

/* Create and initialize asymmetric KEM context. */
static void *kem_newctx(void *provctx)
{
	return p11_kem_ctx_new(provctx);
}

/* Free asymmetric KEM context. */

static void kem_freectx(void *ctx)
{
	p11_kem_ctx_free(ctx);
}

/* Duplicate asymmetric KEM context. */
static void *kem_dupctx(void *ctx)
{
	return p11_kem_ctx_dupctx(ctx);
}

/*
 * Initialize an asymmetric KEM context for encapsulation using
 * the recipient's public key.
 */
static int kem_encapsulate_init(void *ctx, void *provkey,
	const OSSL_PARAM params[])
{
	return p11_kem_ctx_init(ctx, provkey, params);
}

/* Encapsulate a shared secret using an ML-KEM public key. */
static int kem_encapsulate(void *ctx, unsigned char *out, size_t *outlen,
	unsigned char *secret, size_t *secretlen)
{
	return p11_kem_ctx_encapsulate(ctx, out, outlen, secret, secretlen);
}

/*
 * Initialise a context for an asymmetric decapsulation given a provider side
 * asymmetric KEM context in the ctx parameter, a pointer to a provider key
 * object in the provkey parameter, and a name of the algorithm.
 */
static int kem_decapsulate_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
	return p11_kem_ctx_init(ctx, provkey, params);
}

/* Perform the actual decapsulation. */
static int kem_decapsulate(void *ctx, unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	return p11_kem_ctx_decapsulate(ctx, out, outlen, in, inlen);
}

/* Return the current asymmetric KEM context parameters. */
static int kem_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
	if (ctx == NULL)
		return 0;

	(void)params;
	return 1;
}

/*
 * Return the list of gettable asymmetric KEM context parameters.
 * No parameters are currently recognised by built-in asymmetric kem algorithms.
 */
static const OSSL_PARAM *kem_gettable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM gettable[] = {
		OSSL_PARAM_END
	};

	(void)ctx;
	(void)provctx;
	return gettable;
}

/*
 * Set asymmetric KEM context parameters.
 * OSSL_KEM_PARAM_IKME is not supported because PKCS#11 ML-KEM
 * encapsulation uses randomness generated internally by the token.
 * This parameter should not be used for purposes other than testing.
 */
static int kem_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	if (ctx == NULL)
		return 0;

	(void)params;
	return 1;
}

/*
 * Return the list of settable asymmetric KEM context parameters.
 * No parameters are currently recognised by built-in asymmetric kem algorithms.
 */
static const OSSL_PARAM *kem_settable_ctx_params(void *ctx, void *provctx)
{
	return kem_gettable_ctx_params(ctx, provctx);
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

	(void)ctx;
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
