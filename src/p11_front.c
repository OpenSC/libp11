/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2016-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Copyright © 2025 Mobi - Com Polska Sp. z o.o.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
#include <openssl/objects.h>

#include "libp11-int.h"

/* The maximum length of PIN */
#define MAX_PIN_LENGTH   256

/* The following exported functions are *not* implemented here:
 * PKCS11_get_rsa_method
 * PKCS11_get_ecdsa_method
 * PKCS11_ecdsa_method_free
 * PKCS11_get_ec_key_method
 */

/* External interface to the libp11 features */

PKCS11_CTX *PKCS11_CTX_new_ex(int flags)
{
	return pkcs11_CTX_new(flags);
}

PKCS11_CTX *PKCS11_CTX_new(void)
{
	return pkcs11_CTX_new(0);
}

void PKCS11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	if (check_fork(ctx->_private) < 0)
		return;
	pkcs11_CTX_init_args(ctx, init_args);
}

int PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident)
{
	if (check_fork(ctx->_private) < 0)
		return -1;
	return pkcs11_CTX_load(ctx, ident);
}

void PKCS11_CTX_unload(PKCS11_CTX *ctx)
{
	if (check_fork(ctx->_private) < 0)
		return;
	pkcs11_CTX_unload(ctx);
}

void PKCS11_CTX_free(PKCS11_CTX *ctx)
{
	if (check_fork(ctx->_private) < 0)
		return;
	pkcs11_CTX_free(ctx);
}

int PKCS11_open_session(PKCS11_SLOT *pslot, int rw)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_open_session(slot, rw);
}

int PKCS11_enumerate_slots(PKCS11_CTX *pctx,
		PKCS11_SLOT **slotsp, unsigned int *nslotsp)
{
	PKCS11_CTX_private *ctx = pctx->_private;
	if (check_fork(ctx) < 0)
		return -1;
	if (!nslotsp)
		return -1;
	if (slotsp)
		*slotsp = 0;
	if (nslotsp)
		*nslotsp = 0;
	return pkcs11_enumerate_slots(ctx, slotsp, nslotsp);
}

int PKCS11_update_slots(PKCS11_CTX *pctx,
		PKCS11_SLOT **slotsp, unsigned int *nslotsp)
{
	PKCS11_CTX_private *ctx = pctx->_private;
	if (check_fork(ctx) < 0)
		return -1;
	if (!nslotsp)
		return -1;
	return pkcs11_enumerate_slots(ctx, slotsp, nslotsp);
}

unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *pslot)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return 0L;
	return pkcs11_get_slotid_from_slot(slot);
}

void PKCS11_release_all_slots(PKCS11_CTX *pctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	PKCS11_CTX_private *ctx = pctx->_private;
	if (check_fork(ctx) < 0)
		return;
	pkcs11_release_all_slots(slots, nslots);
}

PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	PKCS11_SLOT *slot, *best;
	PKCS11_TOKEN *tok;
	unsigned int n;

	if (check_fork(ctx->_private) < 0)
		return NULL;
	if (!slots)
		return NULL;

	best = NULL;
	for (n = 0, slot = slots; n < nslots; n++, slot++) {
		if ((tok = slot->token) != NULL) {
			if (!best ||
					(tok->initialized > best->token->initialized &&
					tok->userPinSet > best->token->userPinSet &&
					tok->loginRequired > best->token->loginRequired))
				best = slot;
		}
	}
	return best;
}

PKCS11_SLOT *PKCS11_find_next_token(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots,
		PKCS11_SLOT *current)
{
	int offset;

	if (check_fork(ctx->_private) < 0)
		return NULL;
	if (!slots)
		return NULL;

	if (current) {
		offset = (int)(current + 1 - slots);
		if (offset < 1 || (unsigned int)offset >= nslots)
			return NULL;
	} else {
		offset = 0;
	}

	return PKCS11_find_token(ctx, slots + offset, nslots - offset);
}

int PKCS11_is_logged_in(PKCS11_SLOT *pslot, int so, int *res)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_is_logged_in(slot, so, res);
}

int PKCS11_login(PKCS11_SLOT *pslot, int so, const char *pin)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_login(slot, so, pin);
}

int PKCS11_logout(PKCS11_SLOT *pslot)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_logout(slot);
}

int PKCS11_enumerate_keys_ext(PKCS11_TOKEN *token, const PKCS11_KEY *key_template,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	PKCS11_KEY tmpl_local = {0};

	if (!key_template) {
		tmpl_local.isPrivate = 1;
		key_template = &tmpl_local;
	}

	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_enumerate_keys(slot, CKO_PRIVATE_KEY, key_template, keys, nkeys);
}

int PKCS11_enumerate_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	return PKCS11_enumerate_keys_ext(token, NULL, keys, nkeys);
}

int PKCS11_remove_key(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_remove_object(key);
}

int PKCS11_enumerate_public_keys_ext(PKCS11_TOKEN *token, const PKCS11_KEY *key_template,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	PKCS11_KEY tmpl_local = {0};

	if (!key_template) {
		tmpl_local.isPrivate = 0;
		key_template = &tmpl_local;
	}

	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_enumerate_keys(slot, CKO_PUBLIC_KEY, key_template, keys, nkeys);
}

int PKCS11_enumerate_public_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	return PKCS11_enumerate_public_keys_ext(token, NULL, keys, nkeys);
}

int PKCS11_get_key_type(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_type(key);
}

EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, CKO_PRIVATE_KEY);
}

EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, CKO_PUBLIC_KEY);
}

PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_find_certificate(key);
}

PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *pcert)
{
	PKCS11_OBJECT_private *cert = pcert->_private;
	if (check_object_fork(cert) < 0)
		return NULL;
	return pkcs11_find_key(cert);
}

int PKCS11_enumerate_certs_ext(PKCS11_TOKEN *token, const PKCS11_CERT *cert_template,
		PKCS11_CERT **certs, unsigned int *ncerts)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_enumerate_certs(slot, cert_template, certs, ncerts);
}

int PKCS11_enumerate_certs(PKCS11_TOKEN *token,
		PKCS11_CERT **certs, unsigned int *ncerts)
{
	return PKCS11_enumerate_certs_ext(token, NULL, certs, ncerts);
}

int PKCS11_remove_certificate(PKCS11_CERT *pcert)
{
	PKCS11_OBJECT_private *cert = pcert->_private;
	if (check_object_fork(cert) < 0)
		return -1;
	return pkcs11_remove_object(cert);
}

int PKCS11_init_token(PKCS11_TOKEN *token, const char *pin,
		const char *label)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_init_token(slot, pin, label);
}

int PKCS11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	int r;

	if (check_slot_fork(slot) < 0)
		return -1;
	r = pkcs11_init_pin(slot, pin);
	if (r == 0)
		r = pkcs11_refresh_token(token->slot);
	return r;
}

int PKCS11_change_pin(PKCS11_SLOT *pslot,
		const char *old_pin, const char *new_pin)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	int r;

	if (check_slot_fork(slot) < 0)
		return -1;
	r = pkcs11_change_pin(slot, old_pin, new_pin);
	if (r == 0)
		r = pkcs11_refresh_token(pslot);
	return r;
}

int PKCS11_store_private_key(PKCS11_TOKEN *token,
		EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_private_key(slot, pk, label, id, id_len);
}

int PKCS11_store_public_key(PKCS11_TOKEN *token,
		EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_public_key(slot, pk, label, id, id_len);
}

int PKCS11_store_certificate(PKCS11_TOKEN *token, X509 *x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert)
{
	PKCS11_SLOT_private *slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_certificate(slot, x509, label, id, id_len, ret_cert);
}

int PKCS11_seed_random(PKCS11_SLOT *pslot, const unsigned char *s, unsigned int s_len)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	int r;

	if (check_slot_fork(slot) < 0)
		return -1;
	r = pkcs11_seed_random(slot, s, s_len);
	if (r == 0)
		r = pkcs11_refresh_token(pslot);
	return r;
}

int PKCS11_generate_random(PKCS11_SLOT *pslot, unsigned char *r, unsigned int r_len)
{
	PKCS11_SLOT_private *slot = pslot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_generate_random(slot, r, r_len);
}

void ERR_load_PKCS11_strings(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
	ERR_load_P11_strings();
	ERR_load_CKR_strings();
}

int PKCS11_set_ui_method(PKCS11_CTX *pctx, UI_METHOD *ui_method, void *ui_user_data)
{
	PKCS11_CTX_private *ctx = pctx->_private;
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_set_ui_method(ctx, ui_method, ui_user_data);
}

/* External interface to the deprecated features */

int PKCS11_keygen(PKCS11_TOKEN *token, PKCS11_KGEN_ATTRS *kg)
{
	PKCS11_SLOT_private *slot;

	if (token == NULL || kg == NULL || kg->id_len > MAX_PIN_LENGTH)
		return -1;

	slot = token->slot->_private;
	if (check_slot_fork(slot) < 0)
		return -1;

	switch(kg->type) {
	case EVP_PKEY_RSA:
		return pkcs11_rsa_keygen(slot, kg->kgen.rsa->bits,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return pkcs11_ec_keygen(slot, kg->kgen.ec->curve,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* OPENSSL_NO_EC */
#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		return pkcs11_eddsa_keygen(slot, kg->kgen.nid->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
	case EVP_PKEY_X25519:
	case EVP_PKEY_X448:
		return pkcs11_xdh_keygen(slot, kg->kgen.eddsa->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
	case EVP_PKEY_ML_DSA_44:
	case EVP_PKEY_ML_DSA_65:
	case EVP_PKEY_ML_DSA_87:
		return pkcs11_mldsa_keygen(slot, kg->kgen.nid->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_ML_KEM
	case EVP_PKEY_ML_KEM_512:
	case EVP_PKEY_ML_KEM_768:
	case EVP_PKEY_ML_KEM_1024:
		return pkcs11_mlkem_keygen(slot, kg->kgen.nid->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* OPENSSL_NO_ML_KEM */

#ifndef OPENSSL_NO_SLH_DSA
	case EVP_PKEY_SLH_DSA_SHA2_128S:
	case EVP_PKEY_SLH_DSA_SHA2_128F:
	case EVP_PKEY_SLH_DSA_SHA2_192S:
	case EVP_PKEY_SLH_DSA_SHA2_192F:
	case EVP_PKEY_SLH_DSA_SHA2_256S:
	case EVP_PKEY_SLH_DSA_SHA2_256F:
	case EVP_PKEY_SLH_DSA_SHAKE_128S:
	case EVP_PKEY_SLH_DSA_SHAKE_128F:
	case EVP_PKEY_SLH_DSA_SHAKE_192S:
	case EVP_PKEY_SLH_DSA_SHAKE_192F:
	case EVP_PKEY_SLH_DSA_SHAKE_256S:
	case EVP_PKEY_SLH_DSA_SHAKE_256F:
		return pkcs11_slhdsa_keygen(slot, kg->kgen.nid->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_FALCON512:
	case EVP_PKEY_FALCON1024:
		return pkcs11_falcon_keygen(slot, kg->kgen.nid->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

	default:
		return -1;
	}
}

int PKCS11_generate_key(PKCS11_TOKEN *token, int algorithm,
		unsigned int param, /* bits for RSA, nid for EC, unused for EdDSA */
		char *label, unsigned char *id, size_t id_len)
{
	PKCS11_params key_params = { .extractable = 0, .sensitive = 1 };
#ifndef OPENSSL_NO_EC
	PKCS11_EC_KGEN ec_kgen;
#endif /* OPENSSL_NO_EC */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	PKCS11_NID_KGEN nid_kgen;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
	PKCS11_RSA_KGEN rsa_kgen;
	PKCS11_KGEN_ATTRS kgen_attrs = { 0 };

	switch (algorithm) {
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		ec_kgen.curve = OBJ_nid2sn(param);
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_EC,
			.kgen.ec = &ec_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* OPENSSL_NO_EC */
#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED25519:
		nid_kgen.nid = NID_ED25519;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ED25519,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ED448:
		nid_kgen.nid = NID_ED448;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ED448,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_X25519:
		nid_kgen.nid = NID_X25519;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_X25519,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_X448:
		nid_kgen.nid = NID_X448;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_X448,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
	case EVP_PKEY_ML_DSA_44:
		nid_kgen.nid = NID_ML_DSA_44;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_DSA_44,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ML_DSA_65:
		nid_kgen.nid = NID_ML_DSA_65;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_DSA_65,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ML_DSA_87:
		nid_kgen.nid = NID_ML_DSA_87;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_DSA_87,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_ML_KEM
	case EVP_PKEY_ML_KEM_512:
		nid_kgen.nid = NID_ML_KEM_512;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_KEM_512,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ML_KEM_768:
		nid_kgen.nid = NID_ML_KEM_768;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_KEM_768,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ML_KEM_1024:
		nid_kgen.nid = NID_ML_KEM_1024;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ML_KEM_1024,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* OPENSSL_NO_ML_KEM */

#ifndef OPENSSL_NO_SLH_DSA
	case EVP_PKEY_SLH_DSA_SHA2_128S:
		nid_kgen.nid = NID_SLH_DSA_SHA2_128s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_128S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHA2_128F:
		nid_kgen.nid = NID_SLH_DSA_SHA2_128f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_128F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHA2_192S:
		nid_kgen.nid = NID_SLH_DSA_SHA2_192s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_192S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHA2_192F:
		nid_kgen.nid = NID_SLH_DSA_SHA2_192f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_192F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHA2_256S:
		nid_kgen.nid = NID_SLH_DSA_SHA2_256s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_256S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHA2_256F:
		nid_kgen.nid = NID_SLH_DSA_SHA2_256f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHA2_256F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_128S:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_128s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_128S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_128F:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_128f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_128F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_192S:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_192s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_192S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_192F:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_192f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_192F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_256S:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_256s;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_256S,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_SLH_DSA_SHAKE_256F:
		nid_kgen.nid = NID_SLH_DSA_SHAKE_256f;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_SLH_DSA_SHAKE_256F,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_FALCON512:
		nid_kgen.nid = NID_FALCON_512;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_FALCON512,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
	case EVP_PKEY_FALCON1024:
		nid_kgen.nid = NID_FALCON_1024;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_FALCON1024,
			.kgen.nid = &nid_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

	default:
		rsa_kgen.bits = param;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_RSA,
			.kgen.rsa = &rsa_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
	}

	return PKCS11_keygen(token, &kgen_attrs);
}

int PKCS11_get_key_size(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_size(key);
}

int PKCS11_get_key_modulus(PKCS11_KEY *pkey, BIGNUM **bn)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_modulus(key, bn);
}

int PKCS11_get_key_exponent(PKCS11_KEY *pkey, BIGNUM **bn)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_exponent(key, bn);
}

int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_sign(type, m, m_len, sigret, siglen, key);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int PKCS11_evp_pkey_sign(EVP_PKEY *pk, int type, const char *mdname,
	const int pad_mode, const int pss_saltlen, const char *mgf1_mdname,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_object(pk);

	if (check_object_fork(key) < 0)
		return -1;

	switch (type) {
	case EVP_PKEY_RSA:
		return pkcs11_evp_pkey_rsa_sign(key, pk, mdname,
			pad_mode, pss_saltlen, mgf1_mdname,
			sig, siglen, tbs, tbslen);

#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return pkcs11_evp_pkey_ec_sign(key, sig, siglen, tbs, tbslen);
#endif /* OPENSSL_NO_EC */

#if !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		return pkcs11_evp_pkey_eddsa_sign(key, sig, siglen, tbs, tbslen);
#endif /* !defined(OPENSSL_NO_ECX) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#ifndef OPENSSL_NO_ML_DSA
	case EVP_PKEY_ML_DSA_44:
	case EVP_PKEY_ML_DSA_65:
	case EVP_PKEY_ML_DSA_87:
		return pkcs11_evp_pkey_mldsa_sign(key, sig, siglen, tbs, tbslen);
#endif /* OPENSSL_NO_ML_DSA */

#ifndef OPENSSL_NO_SLH_DSA
	case EVP_PKEY_SLH_DSA_SHA2_128S:
	case EVP_PKEY_SLH_DSA_SHA2_128F:
	case EVP_PKEY_SLH_DSA_SHA2_192S:
	case EVP_PKEY_SLH_DSA_SHA2_192F:
	case EVP_PKEY_SLH_DSA_SHA2_256S:
	case EVP_PKEY_SLH_DSA_SHA2_256F:
	case EVP_PKEY_SLH_DSA_SHAKE_128S:
	case EVP_PKEY_SLH_DSA_SHAKE_128F:
	case EVP_PKEY_SLH_DSA_SHAKE_192S:
	case EVP_PKEY_SLH_DSA_SHAKE_192F:
	case EVP_PKEY_SLH_DSA_SHAKE_256S:
	case EVP_PKEY_SLH_DSA_SHAKE_256F:
		return pkcs11_evp_pkey_slhdsa_sign(key, sig, siglen, tbs, tbslen);
#endif /* OPENSSL_NO_SLH_DSA */
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

	case EVP_PKEY_FALCON512:
	case EVP_PKEY_FALCON1024:
		return pkcs11_evp_pkey_falcon_sign(key, sig, siglen, tbs, tbslen);

	default:
		return -2; /* type not supported */
	}
}

int PKCS11_evp_pkey_verify(EVP_PKEY *pk, int type,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_OBJECT_private *obj = pkcs11_get_ex_data_object(pk);
	PKCS11_OBJECT_private *key;
	int ret = -1;

	if (check_object_fork(obj) < 0)
		return -1;

	if (obj->object_class == CKO_PUBLIC_KEY) {
		key = pkcs11_object_ref(obj);
	} else {
		key = pkcs11_object_from_object(obj, CK_INVALID_HANDLE, CKO_PUBLIC_KEY);
	}

	if (key == NULL)
		return -1;

	switch (type) {
	case EVP_PKEY_FALCON512:
	case EVP_PKEY_FALCON1024:
		ret = pkcs11_evp_pkey_falcon_verify(key, sig, siglen, tbs, tbslen);
		break;
	default:
		ret = -2; /* type not supported */
		break;
	}

	pkcs11_object_free(key);
	return ret;
}

int PKCS11_evp_pkey_decrypt(EVP_PKEY *pk, int type, const char *mdname,
	const int pad_mode, const char *mgf1_mdname,
	unsigned char *oaep_label, size_t oaep_labellen,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_object(pk);

	if (check_object_fork(key) < 0)
		return -1;

	switch (type) {
	case EVP_PKEY_RSA:
		return pkcs11_evp_pkey_rsa_decrypt(key, mdname,
			pad_mode, mgf1_mdname,
			oaep_label, oaep_labellen,
			out, outlen, in, inlen);
	default:
		return -2; /* type not supported */
	}
}

#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_ECX)
int PKCS11_evp_pkey_derive(EVP_PKEY *pk, int type,
	const unsigned char *peer_pub, size_t peer_pub_len,
	int cofactor_mode, unsigned char *secret, size_t *secretlen)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_object(pk);

	if (check_object_fork(key) < 0)
		return -1;

	switch (type) {
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return pkcs11_evp_pkey_ecdh_derive(key, peer_pub, peer_pub_len,
			cofactor_mode, secret, secretlen);
#endif /* EVP_PKEY_EC */
#ifndef OPENSSL_NO_ECX
	case EVP_PKEY_X25519:
	case EVP_PKEY_X448:
		return pkcs11_evp_pkey_xdh_derive(key, peer_pub, peer_pub_len,
			secret, secretlen);
#endif /* EVP_PKEY_ECX */
	default:
		return -2; /* type not supported */
	}
}
#endif /* !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_ECX) */

int PKCS11_evp_pkey_decapsulate(EVP_PKEY *pk, int type,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	PKCS11_OBJECT_private *key = pkcs11_get_ex_data_object(pk);

	if (check_object_fork(key) < 0)
		return -1;

	switch (type) {
	case EVP_PKEY_RSA:
		return pkcs11_evp_pkey_rsa_decapsulate(key, out, outlen,
			in, inlen);
#if !defined(OPENSSL_NO_ML_KEM) && OPENSSL_VERSION_NUMBER >= 0x30500000L
	case EVP_PKEY_ML_KEM_512:
	case EVP_PKEY_ML_KEM_768:
	case EVP_PKEY_ML_KEM_1024:
		return pkcs11_evp_pkey_ml_kem_decapsulate(key, out, outlen,
			in, inlen);
#endif /* !defined(OPENSSL_NO_ML_KEM) && OPENSSL_VERSION_NUMBER >= 0x30500000L */
	default:
		return -2; /* type not supported */
	}
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

int PKCS11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *pkey, int padding)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_private_encrypt(flen, from, to, key, padding);
}

int PKCS11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *pkey, int padding)
{
	PKCS11_OBJECT_private *key = pkey->_private;
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_private_decrypt(flen, from, to, key, padding);
}

int PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_KEY *key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	P11err(P11_F_PKCS11_VERIFY, P11_R_NOT_SUPPORTED);
	return -1;
}

void PKCS11_set_vlog_a_method(PKCS11_CTX *pctx, PKCS11_VLOG_A_CB cb)
{
	pctx->_private->vlog_a = cb;
}

/* vim: set noexpandtab: */
