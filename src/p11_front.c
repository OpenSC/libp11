/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2016 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#include "libp11-int.h"

/* The following exported functions are *not* implemented here:
 * ERR_load_PKCS11_strings
 * PKCS11_get_rsa_method
 * PKCS11_get_ecdsa_method
 * PKCS11_ecdsa_method_free
 * PKCS11_get_ec_key_method
 */

/*
 * PKCS#11 reinitialization after fork
 * It wipes out the internal state of the PKCS#11 library
 * Any libp11 references to this state are no longer valid
 */
static int check_fork_int(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (_P11_detect_fork(cpriv->forkid)) {
		if (pkcs11_CTX_reload(ctx) < 0)
			return -1;
		cpriv->forkid = _P11_get_forkid();
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also relogins and reopens the session if needed
 */
static int check_slot_fork_int(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (check_fork_int(SLOT2CTX(slot)) < 0)
		return -1;
	if (spriv->forkid != cpriv->forkid) {
		if (spriv->loggedIn) {
			int saved = spriv->haveSession;
			spriv->haveSession = 0;
			spriv->loggedIn = 0;
			if (pkcs11_relogin(slot) < 0)
				return -1;
			spriv->haveSession = saved;
		}
		if (spriv->haveSession) {
			spriv->haveSession = 0;
			if (pkcs11_reopen_session(slot) < 0)
				return -1;
		}
		spriv->forkid = cpriv->forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also reloads the key
 */
static int check_key_fork_int(PKCS11_KEY *key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (check_slot_fork_int(slot) < 0)
		return -1;
	if (spriv->forkid != kpriv->forkid) {
		pkcs11_reload_key(key);
		kpriv->forkid = spriv->forkid;
	}
	return 0;
}

/*
 * Locking interface to check_fork_int()
 */
static int check_fork(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (ctx == NULL)
		return -1;
	cpriv = PRIVCTX(ctx);
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_fork_int(ctx);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Locking interface to check_slot_fork_int()
 */
static int check_slot_fork(PKCS11_SLOT *slot)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (slot == NULL)
		return -1;
	cpriv = PRIVCTX(SLOT2CTX(slot));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_slot_fork_int(slot);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize token (just its slot)
 */
static int check_token_fork(PKCS11_TOKEN *token)
{
	if (token == NULL)
		return -1;
	return check_slot_fork(TOKEN2SLOT(token));
}

/*
 * Locking interface to check_key_fork_int()
 */
static int check_key_fork(PKCS11_KEY *key)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (key == NULL)
		return -1;
	cpriv = PRIVCTX(KEY2CTX(key));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_key_fork_int(key);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize cert (just its token)
 */
static int check_cert_fork(PKCS11_CERT *cert)
{
	if (cert == NULL)
		return -1;
	return check_token_fork(CERT2TOKEN(cert));
}

/* External interface to the libp11 features */

PKCS11_CTX *PKCS11_CTX_new(void)
{
	return pkcs11_CTX_new();
}

void PKCS11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_init_args(ctx, init_args);
}

int PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident)
{
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_CTX_load(ctx, ident);
}

void PKCS11_CTX_unload(PKCS11_CTX *ctx)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_unload(ctx);
}

void PKCS11_CTX_free(PKCS11_CTX *ctx)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_free(ctx);
}

int PKCS11_open_session(PKCS11_SLOT *slot, int rw)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_open_session(slot, rw, 0);
}

int PKCS11_enumerate_slots(PKCS11_CTX *ctx,
		PKCS11_SLOT **slotsp, unsigned int *nslotsp)
{
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_enumerate_slots(ctx, slotsp, nslotsp);
}

unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *slot)
{
	if (check_slot_fork(slot) < 0)
		return 0L;
	return pkcs11_get_slotid_from_slot(slot);
}

void PKCS11_release_all_slots(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_release_all_slots(ctx, slots, nslots);
}

PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	if (check_fork(ctx) < 0)
		return NULL;
	return pkcs11_find_token(ctx, slots, nslots);
}

int PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_is_logged_in(slot, so, res);
}

int PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_login(slot, so, pin, 0);
}

int PKCS11_login_callback(PKCS11_SLOT * slot, int so, PKCS11_LOGIN_CALLBACKS * callbacks)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_login_callback(slot, so, callbacks, 0);
}

int PKCS11_logout(PKCS11_SLOT *slot)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_logout(slot);
}

int PKCS11_enumerate_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_keys(token, CKO_PRIVATE_KEY, keys, nkeys);
}

int PKCS11_enumerate_public_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_keys(token, CKO_PUBLIC_KEY, keys, nkeys);
}

int PKCS11_get_key_type(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_type(key);
}

EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, 1);
}

EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, 0);
}

PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_find_certificate(key);
}

PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *cert)
{
	if (check_cert_fork(cert) < 0)
		return NULL;
	return pkcs11_find_key(cert);
}

int PKCS11_enumerate_certs(PKCS11_TOKEN *token,
		PKCS11_CERT **certs, unsigned int *ncerts)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_certs(token, certs, ncerts);
}

int PKCS11_init_token(PKCS11_TOKEN *token, const char *pin,
		const char *label)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_init_token(token, pin, label);
}

int PKCS11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_init_pin(token, pin);
}

int PKCS11_change_pin(PKCS11_SLOT *slot,
		const char *old_pin, const char *new_pin)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_change_pin(slot, old_pin, new_pin);
}

int PKCS11_store_private_key(PKCS11_TOKEN *token,
		EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_private_key(token, pk, label, id, id_len);
}

int PKCS11_store_public_key(PKCS11_TOKEN *token,
    	EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_public_key(token, pk, label, id, id_len);
}

int PKCS11_store_certificate(PKCS11_TOKEN *token, X509 *x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_certificate(token, x509, label, id, id_len, ret_cert);
}

int PKCS11_seed_random(PKCS11_SLOT *slot, const unsigned char *s, unsigned int s_len)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_seed_random(slot, s, s_len);
}

int PKCS11_generate_random(PKCS11_SLOT *slot, unsigned char *r, unsigned int r_len)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_generate_random(slot, r, r_len);
}

/* External interface to the deprecated features */

int PKCS11_generate_key(PKCS11_TOKEN *token,
		int algorithm, unsigned int bits,
		char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_generate_key(token, algorithm, bits, label, id, id_len);
}

int PKCS11_get_key_size(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_size(key);
}

int PKCS11_get_key_modulus(PKCS11_KEY *key, BIGNUM **bn)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_modulus(key, bn);
}

int PKCS11_get_key_exponent(PKCS11_KEY *key, BIGNUM **bn)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_exponent(key, bn);
}

int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_sign(type, m, m_len, sigret, siglen, key);
}

int PKCS11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *key, int padding)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_private_encrypt(flen, from, to, key, padding);
}

int PKCS11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *key, int padding)
{
	if (check_key_fork(key) < 0)
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
	PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
	return -1;
}

/* vim: set noexpandtab: */
