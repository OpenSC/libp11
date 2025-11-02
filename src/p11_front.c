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

PKCS11_CTX *PKCS11_CTX_new(void)
{
	return pkcs11_CTX_new();
}

void PKCS11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	if (check_fork(PRIVCTX(ctx)) < 0)
		return;
	pkcs11_CTX_init_args(ctx, init_args);
}

int PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident)
{
	if (check_fork(PRIVCTX(ctx)) < 0)
		return -1;
	return pkcs11_CTX_load(ctx, ident);
}

void PKCS11_CTX_unload(PKCS11_CTX *ctx)
{
	if (check_fork(PRIVCTX(ctx)) < 0)
		return;
	pkcs11_CTX_unload(ctx);
}

void PKCS11_CTX_free(PKCS11_CTX *ctx)
{
	if (check_fork(PRIVCTX(ctx)) < 0)
		return;
	pkcs11_CTX_free(ctx);
}

int PKCS11_open_session(PKCS11_SLOT *pslot, int rw)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_open_session(slot, rw);
}

int PKCS11_enumerate_slots(PKCS11_CTX *pctx,
		PKCS11_SLOT **slotsp, unsigned int *nslotsp)
{
	PKCS11_CTX_private *ctx = PRIVCTX(pctx);
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
	PKCS11_CTX_private *ctx = PRIVCTX(pctx);
	if (check_fork(ctx) < 0)
		return -1;
	if (!nslotsp)
		return -1;
	return pkcs11_enumerate_slots(ctx, slotsp, nslotsp);
}

unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *pslot)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
	if (check_slot_fork(slot) < 0)
		return 0L;
	return pkcs11_get_slotid_from_slot(slot);
}

void PKCS11_release_all_slots(PKCS11_CTX *pctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	PKCS11_CTX_private *ctx = PRIVCTX(pctx);
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

	if (check_fork(PRIVCTX(ctx)) < 0)
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

	if (check_fork(PRIVCTX(ctx)) < 0)
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
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_is_logged_in(slot, so, res);
}

int PKCS11_login(PKCS11_SLOT *pslot, int so, const char *pin)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_login(slot, so, pin);
}

int PKCS11_logout(PKCS11_SLOT *pslot)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_logout(slot);
}

int PKCS11_enumerate_keys_ext(PKCS11_TOKEN *token, const PKCS11_KEY *key_template,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
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
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_remove_object(key);
}

int PKCS11_enumerate_public_keys_ext(PKCS11_TOKEN *token, const PKCS11_KEY *key_template,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
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
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_type(key);
}

EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, CKO_PRIVATE_KEY);
}

EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, CKO_PUBLIC_KEY);
}

PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return NULL;
	return pkcs11_find_certificate(key);
}

PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *pcert)
{
	PKCS11_OBJECT_private *cert = PRIVCERT(pcert);
	if (check_object_fork(cert) < 0)
		return NULL;
	return pkcs11_find_key(cert);
}

int PKCS11_enumerate_certs_ext(PKCS11_TOKEN *token, const PKCS11_CERT *cert_template,
		PKCS11_CERT **certs, unsigned int *ncerts)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
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
	PKCS11_OBJECT_private *cert = PRIVCERT(pcert);
	if (check_object_fork(cert) < 0)
		return -1;
	return pkcs11_remove_object(cert);
}

int PKCS11_init_token(PKCS11_TOKEN *token, const char *pin,
		const char *label)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_init_token(slot, pin, label);
}

int PKCS11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
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
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
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
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_private_key(slot, pk, label, id, id_len);
}

int PKCS11_store_public_key(PKCS11_TOKEN *token,
		EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_public_key(slot, pk, label, id, id_len);
}

int PKCS11_store_certificate(PKCS11_TOKEN *token, X509 *x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(token->slot);
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_store_certificate(slot, x509, label, id, id_len, ret_cert);
}

int PKCS11_seed_random(PKCS11_SLOT *pslot, const unsigned char *s, unsigned int s_len)
{
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
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
	PKCS11_SLOT_private *slot = PRIVSLOT(pslot);
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
	PKCS11_CTX_private *ctx = PRIVCTX(pctx);
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

	slot = PRIVSLOT(token->slot);
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
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		return pkcs11_eddsa_keygen(slot, kg->kgen.eddsa->nid,
				kg->key_label, kg->key_id, kg->id_len, kg->key_params);
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */
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
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
	PKCS11_EDDSA_KGEN eddsa_kgen;
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */
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
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
	case EVP_PKEY_ED25519:
		eddsa_kgen.nid = NID_ED25519;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ED25519,
			.kgen.eddsa = &eddsa_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;

	case EVP_PKEY_ED448:
		eddsa_kgen.nid = NID_ED448;
		kgen_attrs = (PKCS11_KGEN_ATTRS){
			.type = EVP_PKEY_ED448,
			.kgen.eddsa = &eddsa_kgen,
			.token_label = (const char *)token->label,
			.key_label = label,
			.key_id = (const unsigned char *)id,
			.id_len = id_len,
			.key_params = &key_params
		};
		break;
# endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* OPENSSL_NO_EC */
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
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_size(key);
}

int PKCS11_get_key_modulus(PKCS11_KEY *pkey, BIGNUM **bn)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_modulus(key, bn);
}

int PKCS11_get_key_exponent(PKCS11_KEY *pkey, BIGNUM **bn)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_get_key_exponent(key, bn);
}

int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *pkey)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_sign(type, m, m_len, sigret, siglen, key);
}

int PKCS11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *pkey, int padding)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
	if (check_object_fork(key) < 0)
		return -1;
	return pkcs11_private_encrypt(flen, from, to, key, padding);
}

int PKCS11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *pkey, int padding)
{
	PKCS11_OBJECT_private *key = PRIVKEY(pkey);
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
	PRIVCTX(pctx)->vlog_a = cb;
}

/* vim: set noexpandtab: */
