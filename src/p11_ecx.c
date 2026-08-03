/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * OpenSSL 3.x ENGINE compatibility wrappers for Ed25519, Ed448,
 * X25519 and X448 PKCS#11 keys.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "libp11-int.h"

#ifdef LIBP11_HAVE_ECX_METHODS

#define ED25519_SIG_LEN 64
#define ED448_SIG_LEN   114
#define X25519_PUB_LEN  32
#define X448_PUB_LEN    56

/*
 * EVP_PKEY_METHOD is retained only for the OpenSSL 3.x ENGINE compatibility
 * path. OpenSSL 4.x uses the provider implementations exclusively.
 */
typedef int (*P11_ECX_INIT_FN)(EVP_PKEY_CTX *);
typedef int (*P11_ECX_SIGN_FN)(EVP_PKEY_CTX *, unsigned char *, size_t *,
	const unsigned char *, size_t);
typedef int (*P11_ECX_DIGESTSIGN_FN)(EVP_MD_CTX *, unsigned char *, size_t *,
	const unsigned char *, size_t);
typedef int (*P11_ECX_DERIVE_FN)(EVP_PKEY_CTX *, unsigned char *, size_t *);

typedef enum {
	P11_ECX_EDDSA,
	P11_ECX_XDH
} P11_ECX_KIND;

typedef struct {
	int type;
	P11_ECX_KIND kind;
	EVP_PKEY_METHOD *method;
	P11_ECX_INIT_FN original_init;
	P11_ECX_SIGN_FN original_sign;
	P11_ECX_DIGESTSIGN_FN original_digestsign;
	P11_ECX_DERIVE_FN original_derive;
} P11_ECX_METHOD;

static P11_ECX_METHOD ecx_methods[] = {
	{ .type = EVP_PKEY_ED25519, .kind = P11_ECX_EDDSA },
	{ .type = EVP_PKEY_ED448, .kind = P11_ECX_EDDSA },
	{ .type = EVP_PKEY_X25519, .kind = P11_ECX_XDH },
	{ .type = EVP_PKEY_X448, .kind = P11_ECX_XDH }
};

/* Return the ECX method entry for the specified EVP_PKEY type. */
static P11_ECX_METHOD *ecx_method_by_type(int type)
{
	size_t i;

	for (i = 0; i < sizeof(ecx_methods) / sizeof(ecx_methods[0]); i++) {
		if (ecx_methods[i].type == type)
			return &ecx_methods[i];
	}
	return NULL;
}

/*
 * Sign input with a PKCS#11-backed Ed25519 or Ed448 key.
 * If sig is NULL, return the required signature size.
 */
static int pkcs11_eddsa_pmeth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	PKCS11_OBJECT_private *key;
	size_t required;

	if (ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	key = pkcs11_get_ex_data_object(pkey);
	if (key == NULL)
		return -1; /* foreign key: use the original OpenSSL method */

	if (key->object_class != CKO_PRIVATE_KEY)
		return -1;

	if (key->slot == NULL || key->slot->ctx == NULL)
		return 0;

	if ((key->slot->ctx->flags & PKCS11_FLAG_NO_METHODS) != 0)
		return -1;

	if (check_object_fork(key) < 0)
		return 0;

	if (siglen == NULL || tbs == NULL)
		return 0;

	switch (EVP_PKEY_get_id(pkey)) {
	case EVP_PKEY_ED25519:
		required = ED25519_SIG_LEN;
		break;
	case EVP_PKEY_ED448:
		required = ED448_SIG_LEN;
		break;
	default:
		return 0;
	}

	if (sig == NULL) {
		*siglen = required;
		return 1;
	}
	if (*siglen < required) {
		*siglen = required;
		return 0;
	}

	return pkcs11_evp_pkey_eddsa_sign(key, sig, siglen,
		tbs, tbslen) > 0 ? 1 : 0;
}

/* Sign with a PKCS#11-backed EdDSA key using EVP_DigestSign. */
static int pkcs11_eddsa_pmeth_digestsign(EVP_MD_CTX *mdctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY_CTX *ctx;

	if (mdctx == NULL)
		return 0;

	ctx = EVP_MD_CTX_pkey_ctx(mdctx);
	if (ctx == NULL)
		return 0;

	return pkcs11_eddsa_pmeth_sign(ctx, sig, siglen, tbs, tbslen);
}

/*
 * Derive a shared secret with a PKCS#11-backed X25519 or X448 key.
 * If secret is NULL, return the required secret length.
 */
static int pkcs11_xdh_pmeth_derive(EVP_PKEY_CTX *ctx,
	unsigned char *secret, size_t *secretlen)
{
	EVP_PKEY *pkey;
	EVP_PKEY *peerkey;
	PKCS11_OBJECT_private *key;
	unsigned char peer_public[X448_PUB_LEN];
	size_t peer_public_len = sizeof(peer_public);
	size_t required;

	if (ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	key = pkcs11_get_ex_data_object(pkey);
	if (key == NULL)
		return -1; /* foreign key: use the original OpenSSL method */

	if (key->object_class != CKO_PRIVATE_KEY)
		return -1;

	if (key->slot == NULL || key->slot->ctx == NULL)
		return 0;

	if ((key->slot->ctx->flags & PKCS11_FLAG_NO_METHODS) != 0)
		return -1;

	if (check_object_fork(key) < 0)
		return 0;

	if (secretlen == NULL)
		return 0;

	switch (EVP_PKEY_get_id(pkey)) {
	case EVP_PKEY_X25519:
		required = X25519_PUB_LEN;
		break;
	case EVP_PKEY_X448:
		required = X448_PUB_LEN;
		break;
	default:
		return 0;
	}

	if (secret == NULL) {
		*secretlen = required;
		return 1;
	}
	if (*secretlen < required) {
		*secretlen = required;
		return 0;
	}

	peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);
	if (peerkey == NULL)
		return 0;

	if (EVP_PKEY_get_raw_public_key(peerkey, NULL,
			&peer_public_len) != 1 ||
			peer_public_len != required ||
			peer_public_len > sizeof(peer_public))
		return 0;

	if (EVP_PKEY_get_raw_public_key(peerkey, peer_public,
			&peer_public_len) != 1)
		return 0;

	return pkcs11_evp_pkey_xdh_derive(key, peer_public,
		peer_public_len, secret, secretlen) > 0 ? 1 : 0;
}

/* Sign with libp11, falling back to OpenSSL for a foreign EdDSA key. */
static int pkcs11_ecx_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
	size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey = NULL;
	P11_ECX_METHOD *state = NULL;
	int ret;

	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = ecx_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_ECX_EDDSA)
		return 0;

	ret = pkcs11_eddsa_pmeth_sign(ctx, sig, siglen, tbs, tbslen);
	if (ret < 0 && state->original_sign != NULL)
		ret = state->original_sign(ctx, sig, siglen, tbs, tbslen);

	return ret;
}

/*
 * Sign with libp11 using EVP_DigestSign, falling back to OpenSSL for a
 * foreign EdDSA key.
 */
static int pkcs11_ecx_digestsign(EVP_MD_CTX *mdctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	P11_ECX_METHOD *state = NULL;
	int ret;

	if (mdctx != NULL)
		ctx = EVP_MD_CTX_pkey_ctx(mdctx);
	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = ecx_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_ECX_EDDSA)
		return 0;

	ret = pkcs11_eddsa_pmeth_digestsign(mdctx, sig, siglen,
		tbs, tbslen);
	if (ret < 0 && state->original_digestsign != NULL)
		ret = state->original_digestsign(mdctx, sig, siglen,
			tbs, tbslen);

	return ret;
}

/* Derive with libp11, falling back to OpenSSL for a foreign XDH key. */
static int pkcs11_ecx_derive(EVP_PKEY_CTX *ctx,
	unsigned char *secret, size_t *secretlen)
{
	EVP_PKEY *pkey = NULL;
	P11_ECX_METHOD *state = NULL;
	int ret;

	if (ctx != NULL)
		pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey != NULL)
		state = ecx_method_by_type(EVP_PKEY_get_id(pkey));

	if (state == NULL || state->kind != P11_ECX_XDH)
		return 0;

	ret = pkcs11_xdh_pmeth_derive(ctx, secret, secretlen);
	if (ret < 0 && state->original_derive != NULL)
		ret = state->original_derive(ctx, secret, secretlen);

	return ret;
}

/* Reset the cached ECX method state while preserving its type and kind. */
static void ecx_method_reset(P11_ECX_METHOD *state)
{
	state->method = NULL;
	state->original_init = NULL;
	state->original_sign = NULL;
	state->original_digestsign = NULL;
	state->original_derive = NULL;
}

/* Remove and free all registered ECX EVP_PKEY_METHOD wrappers. */
void pkcs11_ecx_methods_free(void)
{
	size_t i;

	for (i = 0; i < sizeof(ecx_methods) / sizeof(ecx_methods[0]); i++) {
		P11_ECX_METHOD *state = &ecx_methods[i];

		if (state->method == NULL)
			continue;

		EVP_PKEY_meth_remove(state->method);
		EVP_PKEY_meth_free(state->method);
		ecx_method_reset(state);
	}
}

/* Create and register an ECX EVP_PKEY_METHOD wrapper. */
static int pkcs11_ecx_method_new(P11_ECX_METHOD *state)
{
	const EVP_PKEY_METHOD *original;
	int original_type;
	int original_flags;

	if (state == NULL)
		return 0;

	if (state->method != NULL)
		return 1;

	original = EVP_PKEY_meth_find(state->type);
	if (original == NULL)
		return 0;

	EVP_PKEY_meth_get0_info(&original_type, &original_flags, original);
	if (original_type != state->type)
		return 0;

	if (state->kind == P11_ECX_EDDSA &&
			!(original_flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM))
		return 0;

	state->method = EVP_PKEY_meth_new(state->type, original_flags);
	if (state->method == NULL)
		return 0;

	EVP_PKEY_meth_copy(state->method, original);

	switch (state->kind) {
	case P11_ECX_EDDSA:
		EVP_PKEY_meth_get_sign(original,
			&state->original_init, &state->original_sign);
		EVP_PKEY_meth_get_digestsign(original,
			&state->original_digestsign);
		if (state->original_digestsign == NULL)
			goto error;
		EVP_PKEY_meth_set_sign(state->method,
			state->original_init, pkcs11_ecx_sign);
		EVP_PKEY_meth_set_digestsign(state->method,
			pkcs11_ecx_digestsign);
		break;
	case P11_ECX_XDH:
		EVP_PKEY_meth_get_derive(original,
			&state->original_init, &state->original_derive);
		if (state->original_derive == NULL)
			goto error;
		EVP_PKEY_meth_set_derive(state->method,
			state->original_init, pkcs11_ecx_derive);
		break;
	default:
		goto error;
	}

	/* Register the method globally */
	if (!EVP_PKEY_meth_add0(state->method))
		goto error;

	return 1;

error:
	EVP_PKEY_meth_free(state->method);
	ecx_method_reset(state);
	return 0;
}

/* Enable an ECX EVP_PKEY_METHOD wrapper for a PKCS#11 private key. */
int pkcs11_ecx_method_enable(PKCS11_OBJECT_private *key, int type)
{
	P11_ECX_METHOD *state;

	if (key == NULL || key->slot == NULL || key->slot->ctx == NULL)
		return 0;

	if (key->object_class != CKO_PRIVATE_KEY ||
			(key->slot->ctx->flags & PKCS11_FLAG_NO_METHODS) != 0)
		return 1;

	state = ecx_method_by_type(type);
	if (state == NULL)
		return 1;

	return pkcs11_ecx_method_new(state);
}

#endif /* LIBP11_HAVE_ECX_METHODS */

/* vim: set noexpandtab: */
