/*
 * Copyright © 2025-2026 Mobi - Com Polska Sp. z o.o.
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

#ifndef _PROVIDER_HELPERS_H
#define _PROVIDER_HELPERS_H

#include "util.h"
#include "libp11-int.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/param_build.h>

/* OPENSSL_strcasecmp() is available since OpenSSL 3.0.3.
 * Provide fallback for older versions. */
#if OPENSSL_VERSION_NUMBER < 0x30000030L
#ifdef _WIN32
#include <string.h>
#define OPENSSL_strcasecmp _stricmp
#else /* _WIN32 */
#include <strings.h>
#define OPENSSL_strcasecmp strcasecmp
#endif /* _WIN32 */
#endif /* OPENSSL_VERSION_NUMBER < 0x30000030L */

/* Opaque provider-side types, defined in provider_helpers.c. */
typedef struct provider_ctx PROVIDER_CTX;
typedef struct p11_keydata_st P11_KEYDATA;
typedef struct p11_keygen_ctx P11_KEYGEN_CTX;
typedef struct p11_signature_ctx P11_SIGNATURE_CTX;
typedef struct p11_asym_cipher_ctx P11_ASYM_CIPHER_CTX;
typedef struct p11_keyexch_ctx P11_KEYEXCH_CTX;
typedef struct p11_kem_ctx P11_KEM_CTX;

/******************************************************************************/
/* PROVIDER interface helpers                                                 */
/******************************************************************************/
void PROVIDER_CTX_log(PROVIDER_CTX *prov_ctx, int level, int reason, int line,
	const char *file, const char *format, ...);
PROVIDER_CTX *PROVIDER_CTX_new(void);
void PROVIDER_CTX_destroy(PROVIDER_CTX *prov_ctx);
void PROVIDER_CTX_get_core_functions(PROVIDER_CTX *prov_ctx,
	const OSSL_DISPATCH *in);
int PROVIDER_CTX_get_core_parameters(PROVIDER_CTX *prov_ctx);
void PROVIDER_CTX_set_handle(PROVIDER_CTX *prov_ctx,
	const OSSL_CORE_HANDLE *handle);
int PROVIDER_CTX_set_provider_name(OSSL_PARAM *p, PROVIDER_CTX *prov_ctx);
int PROVIDER_CTX_set_openssl_version(OSSL_PARAM *p, PROVIDER_CTX *prov_ctx);
int PROVIDER_CTX_set_parameters(PROVIDER_CTX *prov_ctx);
int PROVIDER_CTX_is_initialized(PROVIDER_CTX *prov_ctx);
void PROVIDER_CTX_initialize(PROVIDER_CTX *prov_ctx);
X509 *PROVIDER_CTX_get_cert_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data);
EVP_PKEY *PROVIDER_CTX_get_pubkey_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data);
EVP_PKEY *PROVIDER_CTX_get_privkey_from_uri(PROVIDER_CTX *prov_ctx,
	const char *uri, UI_METHOD *ui_method, void *ui_data);
int PROVIDER_CTX_set_ui_method(PROVIDER_CTX *prov_ctx, UI_METHOD *ui_method,
	void *ui_data);

/******************************************************************************/
/* KEYMGMT helper functions                                                   */
/******************************************************************************/
P11_KEYDATA *p11_keydata_new(PROVIDER_CTX *ctx);
int p11_keydata_up_ref(P11_KEYDATA *keydata);
void p11_keydata_free(P11_KEYDATA *keydata);
P11_KEYDATA *p11_keydata_from_evp_pkey(PROVIDER_CTX *ctx, EVP_PKEY *pkey,
	int is_private);
const char *p11_keydata_get_name(const P11_KEYDATA *keydata);
int p11_keydata_is_private(const P11_KEYDATA *keydata);
int p11_keydata_set_params(P11_KEYDATA *keydata, const OSSL_PARAM *params);
int p11_keymgmt_get_params(P11_KEYDATA *keydata, OSSL_PARAM params[]);
int p11_public_equal(const P11_KEYDATA *k1, const P11_KEYDATA *k2);
int p11_keydata_export_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb,
	void *cbarg);

/******************************************************************************/
/* KEY GENERATION helper functions                                            */
/******************************************************************************/
P11_KEYGEN_CTX *p11_keygen_ctx_new(PROVIDER_CTX *prov_ctx, int type,
	const OSSL_PARAM params[]);
void p11_keygen_ctx_free(P11_KEYGEN_CTX *genctx);
int p11_keygen_ctx_set_params(P11_KEYGEN_CTX *genctx, const OSSL_PARAM params[]);
P11_KEYDATA *p11_keygen_ctx_generate(P11_KEYGEN_CTX *genctx);

/******************************************************************************/
/* SIGNATURE helper functions                                                 */
/******************************************************************************/
P11_SIGNATURE_CTX *p11_signature_ctx_new(PROVIDER_CTX *ctx, const char *propq);
void p11_signature_ctx_free(P11_SIGNATURE_CTX *ctx);
P11_SIGNATURE_CTX *p11_signature_dupctx(P11_SIGNATURE_CTX *ctx);
int p11_signature_ctx_init(P11_SIGNATURE_CTX *sig_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[]);
int p11_signature_ctx_set_params(P11_SIGNATURE_CTX *sig_ctx,
	const OSSL_PARAM params[]);
int p11_signature_ctx_get_params(P11_SIGNATURE_CTX *sig_ctx,
	OSSL_PARAM params[]);
int p11_signature_ctx_sign(P11_SIGNATURE_CTX *sig_ctx,
	unsigned char *sig, size_t *siglen, size_t sigsize,
	const unsigned char *tbs, size_t tbslen);
int p11_signature_ctx_verify(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen);
int p11_signature_ctx_verifyrecover(P11_SIGNATURE_CTX *sig_ctx,
	unsigned char *rout, size_t *routlen, size_t routsize,
	const unsigned char *sig, size_t siglen);
int p11_signature_digest_sign_init(P11_SIGNATURE_CTX *sig_ctx,
	const char *mdname, P11_KEYDATA *keydata, const OSSL_PARAM params[]);
int p11_signature_digest_sign_update(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *data, size_t datalen);
int p11_signature_digest_sign_final(P11_SIGNATURE_CTX *sig_ctx,
	unsigned char *sig, size_t *siglen, size_t sigsize);
int p11_signature_digest_sign(P11_SIGNATURE_CTX *sig_ctx,
	unsigned char *sig, size_t *siglen, size_t sigsize,
	const unsigned char *tbs, size_t tbslen);
int p11_signature_digest_verify_init(P11_SIGNATURE_CTX *sig_ctx,
	const char *mdname, P11_KEYDATA *keydata, const OSSL_PARAM params[]);
int p11_signature_digest_verify_update(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *data, size_t datalen);
int p11_signature_digest_verify_final(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *sig, size_t siglen);
int p11_signature_digest_verify(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen);

/******************************************************************************/
/* ASYM CIPHER helper functions                                               */
/******************************************************************************/
P11_ASYM_CIPHER_CTX *p11_asym_cipher_ctx_new(PROVIDER_CTX *ctx);
void p11_asym_cipher_ctx_free(P11_ASYM_CIPHER_CTX *ctx);
P11_ASYM_CIPHER_CTX *p11_asym_cipher_dupctx(P11_ASYM_CIPHER_CTX *ctx);
int p11_asym_cipher_ctx_init(P11_ASYM_CIPHER_CTX *asym_ctx,
	P11_KEYDATA *keydata, const OSSL_PARAM params[]);
int p11_asym_cipher_ctx_set_params(P11_ASYM_CIPHER_CTX *asym_ctx,
	const OSSL_PARAM params[]);
int p11_asym_cipher_ctx_get_params(P11_ASYM_CIPHER_CTX *asym_ctx,
	OSSL_PARAM params[]);
int p11_asym_cipher_ctx_encrypt(P11_ASYM_CIPHER_CTX *asym_ctx,
	unsigned char *out, size_t *outlen, size_t outsize,
	const unsigned char *in, size_t inlen);
int p11_asym_cipher_ctx_decrypt(P11_ASYM_CIPHER_CTX *asym_ctx,
	unsigned char *out, size_t *outlen, size_t outsize,
	const unsigned char *in, size_t inlen);

/******************************************************************************/
/* KEY EXCHANGE helper functions                                              */
/******************************************************************************/
P11_KEYEXCH_CTX *p11_keyexch_ctx_new(PROVIDER_CTX *ctx);
void p11_keyexch_ctx_free(P11_KEYEXCH_CTX *keyexch_ctx);
P11_KEYEXCH_CTX *p11_keyexch_dupctx(P11_KEYEXCH_CTX *keyexch_ctx);
int p11_keyexch_ctx_init(P11_KEYEXCH_CTX *keyexch_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[]);
int p11_keyexch_ctx_set_params(P11_KEYEXCH_CTX *exch_ctx,
	const OSSL_PARAM params[]);
int p11_keyexch_ctx_get_params(P11_KEYEXCH_CTX *exch_ctx, OSSL_PARAM params[]);
int p11_keyexch_ctx_set_peer(P11_KEYEXCH_CTX *keyexch_ctx,
	P11_KEYDATA *provkey);
int p11_keyexch_ctx_derive(P11_KEYEXCH_CTX *exch_ctx, unsigned char *secret,
	size_t *secretlen, size_t outlen);

/******************************************************************************/
/* ASYM KEM helper functions                                                  */
/******************************************************************************/
P11_KEM_CTX *p11_kem_ctx_new(PROVIDER_CTX *ctx);
void p11_kem_ctx_free(P11_KEM_CTX *kem_ctx);
P11_KEM_CTX *p11_kem_ctx_dupctx(P11_KEM_CTX *kem_ctx);
int p11_kem_ctx_init(P11_KEM_CTX *kem_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[]);
int p11_kem_ctx_decapsulate(P11_KEM_CTX *kem_ctx, unsigned char *out,
	size_t *outlen, const unsigned char *in, size_t inlen);
int p11_kem_ctx_encapsulate(P11_KEM_CTX *kem_ctx, unsigned char *out,
	size_t *outlen, unsigned char *secret, size_t *secretlen);

#endif /* _PROVIDER_HELPERS_H */

/* vim: set noexpandtab: */
