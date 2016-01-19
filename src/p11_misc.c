/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include <string.h>
#include <openssl/crypto.h>

/* PKCS11 strings are fixed size blank padded,
 * so when strduping them we must make sure
 * we stop at the end of the buffer, and while we're
 * at it it's nice to remove the padding */
char *pkcs11_strdup(char *mem, size_t size)
{
	char *res;

	while (size && mem[size - 1] == ' ')
		size--;
	res = OPENSSL_malloc(size + 1);
	if (res == NULL)
		return NULL;
	memcpy(res, mem, size);
	res[size] = '\0';
	return res;
}

/*
 * Dup memory
 */
void *memdup(const void *src, size_t size)
{
	void *dst;

	dst = OPENSSL_malloc(size);
	if (dst == NULL)
		return NULL;
	memcpy(dst, src, size);
	return dst;
}

/*
 * PKCS#11 reinitialization after fork
 * It wipes out the internal state of the PKCS#11 library
 * Any libp11 references to this state are no longer valid
 */
static int check_fork_int(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);

	if (_P11_detect_fork(priv->forkid)) {
		if (PKCS11_CTX_reload(ctx) < 0)
			return -1;
		priv->forkid = _P11_get_forkid();
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
	PKCS11_CTX_private *priv = PRIVCTX(ctx);

	if (check_fork_int(SLOT2CTX(slot)) < 0)
		return -1;
	if (spriv->forkid != priv->forkid) {
		if (spriv->loggedIn) {
			int saved = spriv->haveSession;
			spriv->haveSession = 0;
			spriv->loggedIn = 0;
			if (PKCS11_relogin(slot) < 0)
				return -1;
			spriv->haveSession = saved;
		}
		if (spriv->haveSession) {
			spriv->haveSession = 0;
			if (PKCS11_reopen_session(slot) < 0)
				return -1;
		}
		spriv->forkid = priv->forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also reloads the key
 */
static int check_key_fork_int(PKCS11_KEY *key)
{
	PKCS11_KEY_private *priv = PRIVKEY(key);
	PKCS11_SLOT *slot = TOKEN2SLOT(priv->parent);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (check_slot_fork_int(slot) < 0)
		return -1;
	if (spriv->forkid != priv->forkid) {
		pkcs11_reload_key(key);
		priv->forkid = spriv->forkid;
	}
	return 0;
}

/*
 * Locking interface to check_fork_int()
 */
int check_fork(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	int rv;

	pkcs11_w_lock(priv->lockid);
	rv = check_fork_int(ctx);
	pkcs11_w_unlock(priv->lockid);
	return rv;
}

/*
 * Locking interface to check_slot_fork_int()
 */
int check_slot_fork(PKCS11_SLOT *slot)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	int rv;

	pkcs11_w_lock(priv->lockid);
	rv = check_slot_fork_int(slot);
	pkcs11_w_unlock(priv->lockid);
	return rv;
}

/*
 * Locking interface to check_key_fork_int()
 */
int check_key_fork(PKCS11_KEY *key)
{
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	int rv;

	CRYPTO_w_lock(priv->lockid);
	rv = check_key_fork_int(key);
	CRYPTO_w_unlock(priv->lockid);
	return rv;
}

/*
 * CRYPTO dynlock wrappers: 0 is an invalid dynamic lock ID
 */
int pkcs11_get_new_dynlockid()
{
	int i;

	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL)
		return 0; /* Dynamic callbacks not set */
	i = CRYPTO_get_new_dynlockid();
	if (i == 0)
		ERR_clear_error(); /* Dynamic locks are optional -> ignore */
	return i;
}

void pkcs11_destroy_dynlockid(int i)
{
	if(i)
		CRYPTO_destroy_dynlockid(i);
}

/* vim: set noexpandtab: */
