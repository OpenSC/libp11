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

#ifndef _PROVIDER_HELPERS_H
#define _PROVIDER_HELPERS_H

#include "util.h"
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

/* opaque, defined in provider_helpers.c */
typedef struct provider_ctx PROVIDER_CTX;
typedef struct p11_keydata_st P11_KEYDATA;
typedef struct p11_signature_ctx P11_SIGNATURE_CTX;
typedef struct p11_asym_cipher_ctx P11_ASYM_CIPHER_CTX;

/******************************************************************************/
/* PROVIDER interface helpers                                                 */
/******************************************************************************/
void PROVIDER_CTX_log(PROVIDER_CTX *prov_ctx, int level, int reason, int line, const char *file, const char *format, ...);
PROVIDER_CTX *PROVIDER_CTX_new(void);
void PROVIDER_CTX_destroy(PROVIDER_CTX *prov_ctx);
void PROVIDER_CTX_get_core_functions(PROVIDER_CTX *prov_ctx, const OSSL_DISPATCH *in);
int PROVIDER_CTX_get_core_parameters(PROVIDER_CTX *prov_ctx);
void PROVIDER_CTX_set_handle(PROVIDER_CTX *prov_ctx, const OSSL_CORE_HANDLE *handle);
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
int PROVIDER_CTX_set_ui_method(PROVIDER_CTX *prov_ctx, UI_METHOD *ui_method, void *ui_data);

/******************************************************************************/
/* KEYMGMT helper functions                                                   */
/******************************************************************************/
P11_KEYDATA *p11_keydata_new(PROVIDER_CTX *ctx);
int p11_keydata_up_ref(P11_KEYDATA *keydata);
void p11_keydata_free(P11_KEYDATA *keydata);
P11_KEYDATA *p11_keydata_from_evp_pkey(PROVIDER_CTX *ctx, EVP_PKEY *pkey, int is_private);
const char *p11_keydata_get_name(P11_KEYDATA *keydata);
int p11_keydata_get_pub(const P11_KEYDATA *keydata, unsigned char **buf, size_t *len);
int p11_keydata_is_private(const P11_KEYDATA *keydata);
#if OPENSSL_VERSION_NUMBER >= 0x30600000L
int p11_keydata_get_security_category(const P11_KEYDATA *keydata);
#endif /* OPENSSL_VERSION_NUMBER >= 0x30600000L */
int p11_keydata_get_security_bits(const P11_KEYDATA *keydata);
int p11_keydata_get_bits(const P11_KEYDATA *keydata);
size_t p11_keydata_get_sigsize(const P11_KEYDATA *keydata);
int p11_keydata_get_type(const P11_KEYDATA *keydata);
OSSL_PARAM *p11_keydata_get_params(const P11_KEYDATA *key);
int p11_keydata_set_params(P11_KEYDATA *keydata, const OSSL_PARAM *params);
int p11_public_equal(const P11_KEYDATA *k1, const P11_KEYDATA *k2);
int pad_mode_from_param(const OSSL_PARAM *p, int *pad_mode);
int export_rsa_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg);
int export_ec_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg);
int export_eddsa_pub(P11_KEYDATA *keydata, OSSL_CALLBACK *param_cb, void *cbarg);

/******************************************************************************/
/* SIGNATURE helper functions                                                 */
/******************************************************************************/
P11_SIGNATURE_CTX *p11_signature_ctx_new(PROVIDER_CTX *ctx, const char *propq);
void p11_signature_ctx_free(P11_SIGNATURE_CTX *ctx);
P11_SIGNATURE_CTX *p11_signature_dupctx(P11_SIGNATURE_CTX *ctx);
int p11_signature_ctx_init(P11_SIGNATURE_CTX *sig_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[]);
int p11_signature_ctx_init_digest(P11_SIGNATURE_CTX *sig_ctx);

int p11_signature_ctx_verify(P11_SIGNATURE_CTX *sig_ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen);

EVP_PKEY *p11_signature_ctx_get_evp_pkey(const P11_SIGNATURE_CTX *sig_ctx);
size_t p11_signature_ctx_get_sigsize(const P11_SIGNATURE_CTX *sig_ctx);
int p11_signature_ctx_get_type(const P11_SIGNATURE_CTX *sig_ctx);

int p11_signature_ctx_set_mdname(P11_SIGNATURE_CTX *sig_ctx, const char *mdname);
const char *p11_signature_ctx_get_mdname(const P11_SIGNATURE_CTX *sig_ctx);

int p11_signature_ctx_set_pad_mode(P11_SIGNATURE_CTX *sig_ctx, int pad_mode);
int p11_signature_ctx_get_pad_mode(const P11_SIGNATURE_CTX *sig_ctx);

int p11_signature_ctx_set_pss_saltlen(P11_SIGNATURE_CTX *sig_ctx, int saltlen);
int p11_signature_ctx_get_pss_saltlen(const P11_SIGNATURE_CTX *sig_ctx);

int p11_signature_ctx_set_mgf1_mdname(P11_SIGNATURE_CTX *sig_ctx, const char *mdname);
const char *p11_signature_ctx_get_mgf1_mdname(const P11_SIGNATURE_CTX *sig_ctx);

EVP_MD_CTX *p11_signature_ctx_get_mdctx(P11_SIGNATURE_CTX *sig_ctx);
const char *p11_signature_pad_mode_to_string(int pad_mode);
const char *p11_signature_pss_saltlen_to_string(int saltlen);


/******************************************************************************/
/* ASYM CIPHER helper functions                                               */
/******************************************************************************/
P11_ASYM_CIPHER_CTX *p11_asym_cipher_ctx_new(PROVIDER_CTX *ctx);
void p11_asym_cipher_ctx_free(P11_ASYM_CIPHER_CTX *ctx);
P11_ASYM_CIPHER_CTX *p11_asym_cipher_dupctx(P11_ASYM_CIPHER_CTX *ctx);
int p11_asym_cipher_ctx_init(P11_ASYM_CIPHER_CTX *asym_ctx, P11_KEYDATA *keydata,
	const OSSL_PARAM params[]);

int p11_asym_cipher_ctx_encrypt(P11_ASYM_CIPHER_CTX *asym_ctx,
	unsigned char *out, size_t *outlen,
	size_t outsize, const unsigned char *in, size_t inlen);

EVP_PKEY *p11_asym_cipher_ctx_get_evp_pkey(const P11_ASYM_CIPHER_CTX *asym_ctx);
size_t p11_asym_cipher_ctx_get_outsize(const P11_ASYM_CIPHER_CTX *asym_ctx);
int p11_asym_cipher_ctx_get_type(const P11_ASYM_CIPHER_CTX *asym_ctx);

int p11_asym_cipher_ctx_set_oaep_mdname(P11_ASYM_CIPHER_CTX *asym_ctx, const char *mdname);
const char *p11_asym_cipher_ctx_get_oaep_mdname(const P11_ASYM_CIPHER_CTX *asym_ctx);

int p11_asym_cipher_ctx_set_pad_mode(P11_ASYM_CIPHER_CTX *asym_ctx, int pad_mode);
int p11_asym_cipher_ctx_get_pad_mode(const P11_ASYM_CIPHER_CTX *asym_ctx);

int p11_asym_cipher_ctx_set_mgf1_mdname(P11_ASYM_CIPHER_CTX *asym_ctx, const char *mdname);
const char *p11_asym_cipher_ctx_get_mgf1_mdname(const P11_ASYM_CIPHER_CTX *asym_ctx);

int p11_asym_cipher_ctx_set_oaep_label(P11_ASYM_CIPHER_CTX *asym_ctx,
	const unsigned char *label, size_t labellen);
unsigned char *p11_asym_cipher_ctx_get_oaep_label(const P11_ASYM_CIPHER_CTX *asym_ctx);
size_t p11_asym_cipher_ctx_get_oaep_labellen(const P11_ASYM_CIPHER_CTX *asym_ctx);

#endif /* _PROVIDER_HELPERS_H */

/* vim: set noexpandtab: */
