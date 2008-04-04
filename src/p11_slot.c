/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
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

#include <config.h>
#include <string.h>
#include <openssl/buffer.h>
#include "libp11-int.h"

static int pkcs11_init_slot(PKCS11_CTX *, PKCS11_SLOT *, CK_SLOT_ID);
static int pkcs11_check_token(PKCS11_CTX *, PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

/*
 * Enumerate slots
 */
int
PKCS11_enumerate_slots(PKCS11_CTX * ctx, PKCS11_SLOT ** slotp, unsigned int *countp)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);

	CK_SLOT_ID *slotid;
	CK_ULONG nslots, n;
	PKCS11_SLOT *slots;
	int rv;

	rv = priv->method->C_GetSlotList(FALSE, NULL_PTR, &nslots);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_SLOTS, rv);

	slotid = (CK_SLOT_ID *)OPENSSL_malloc(nslots * sizeof(CK_SLOT_ID));
	if (slotid == NULL) return (-1);

	rv = priv->method->C_GetSlotList(FALSE, slotid, &nslots);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_SLOTS, rv);

	slots = (PKCS11_SLOT *) pkcs11_malloc(nslots * sizeof(PKCS11_SLOT));
	for (n = 0; n < nslots; n++) {
		if (pkcs11_init_slot(ctx, &slots[n], slotid[n])) {
			while (n--)
				pkcs11_release_slot(ctx, slots + n);
			OPENSSL_free(slotid);
			OPENSSL_free(slots);
			return -1;
		}
	}

	*slotp = slots;
	*countp = nslots;
	OPENSSL_free(slotid);
	return 0;
}

/*
 * Find a slot with a token that looks "valuable"
 */
PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX * ctx,  PKCS11_SLOT * slots, unsigned int nslots)
{
	PKCS11_SLOT *slot, *best;
	PKCS11_TOKEN *tok;
	unsigned int n;

	if (! slots)
		return NULL;

	best = NULL;
	for (n = 0, slot = slots; n < nslots; n++, slot++) {
		if ((tok = slot->token) != NULL) {
			if (best == NULL
			    || (tok->initialized > best->token->initialized
				&& tok->userPinSet > best->token->userPinSet
				&& tok->loginRequired > best->token->loginRequired))
				best = slot;
		}
	}
	return best;
}

/*
 * Open a session with this slot
 */
int PKCS11_open_session(PKCS11_SLOT * slot, int rw)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	if (priv->haveSession) {
		CRYPTOKI_call(ctx, C_CloseSession(priv->session));
		priv->haveSession = 0;
	}
	rv = CRYPTOKI_call(ctx,
			   C_OpenSession(priv->id,
					 CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION :
							       0), NULL, NULL,
					 &priv->session));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_OPEN_SESSION, rv);
	priv->haveSession = 1;

	return 0;
}

/*
 * Authenticate with the card
 */
int PKCS11_login(PKCS11_SLOT * slot, int so, const char *pin)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	/* Calling PKCS11_login invalidates all cached
	 * keys we have */
	if (slot->token)
		pkcs11_destroy_keys(slot->token);
	if (priv->loggedIn) {
		/* already logged in, log out first */
		if (PKCS11_logout(slot))
			return -1;
	}
	if (!priv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (PKCS11_open_session(slot, so))
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Login(priv->session,
					so ? CKU_SO : CKU_USER,
					(CK_UTF8CHAR *) pin,
					pin ? strlen(pin) : 0));
	if (rv && rv != CKR_USER_ALREADY_LOGGED_IN)  /* logged in -> OK   */
		CRYPTOKI_checkerr(PKCS11_F_PKCS11_LOGIN, rv);
	priv->loggedIn = 1;
	return 0;
}

/*
 * Log out
 */
int PKCS11_logout(PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	/* Calling PKCS11_logout invalidates all cached
	 * keys we have */
	if (slot->token)
		pkcs11_destroy_keys(slot->token);
	if (!priv->haveSession) {
		PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Logout(priv->session));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_LOGOUT, rv);
	priv->loggedIn = 0;
	return 0;
}

/*
 * Initialize the token
 */
int PKCS11_init_token(PKCS11_TOKEN * token, const char *pin, const char *label)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(TOKEN2SLOT(token));
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	if (!label)
		label = "PKCS#11 Token";
	rv = CRYPTOKI_call(ctx, C_InitToken(priv->id,
					    (CK_UTF8CHAR *) pin, strlen(pin),
					    (CK_UTF8CHAR *) label));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_INIT_TOKEN, rv);

	/* FIXME: how to update the token?
	 * PKCS11_CTX_private *cpriv;
	 * int n;
	 * cpriv = PRIVCTX(ctx);
	 * for (n = 0; n < cpriv->nslots; n++) {
	 * 	if (pkcs11_check_token(ctx, cpriv->slots + n) < 0)
	 * 		return -1;
	 * }
	 */

	return 0;
}

/*
 * Set the User PIN
 */
int PKCS11_init_pin(PKCS11_TOKEN * token, const char *pin)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(TOKEN2SLOT(token));
	PKCS11_CTX *ctx = priv->parent;
	int len, rv;

	if (!priv->haveSession) {
		PKCS11err(PKCS11_F_PKCS11_INIT_PIN, PKCS11_NO_SESSION);
		return -1;
	}

	len = pin ? strlen(pin) : 0;
	rv = CRYPTOKI_call(ctx, C_InitPIN(priv->session, (CK_UTF8CHAR *) pin, len));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_INIT_PIN, rv);

	return pkcs11_check_token(ctx, TOKEN2SLOT(token));
}

/*
 * Change the User PIN
 */
int PKCS11_change_pin(PKCS11_SLOT * slot, const char *old_pin,
		const char *new_pin)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int old_len, new_len, rv;

	if (!priv->haveSession) {
		PKCS11err(PKCS11_F_PKCS11_CHANGE_PIN, PKCS11_NO_SESSION);
		return -1;
	}

	old_len = old_pin ? strlen(old_pin) : 0;
	new_len = new_pin ? strlen(new_pin) : 0;
	rv = CRYPTOKI_call(ctx, C_SetPIN(priv->session, (CK_UTF8CHAR *) old_pin,
		old_len, (CK_UTF8CHAR *) new_pin, new_len));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CHANGE_PIN, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Seed the random number generator
 */
int PKCS11_seed_random(PKCS11_SLOT *slot, const unsigned char *s,
		unsigned int s_len)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	if (!priv->haveSession && PKCS11_open_session(slot, 0)) {
		PKCS11err(PKCS11_F_PKCS11_SEED_RANDOM, PKCS11_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_SeedRandom(priv->session, (CK_BYTE_PTR) s, s_len));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_SEED_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Generate random numbers
 */
int PKCS11_generate_random(PKCS11_SLOT *slot, unsigned char *r,
		unsigned int r_len)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	if (!priv->haveSession && PKCS11_open_session(slot, 0)) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_RANDOM, PKCS11_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_GenerateRandom(priv->session, (CK_BYTE_PTR) r, r_len));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_GENERATE_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Helper functions
 */
static int pkcs11_init_slot(PKCS11_CTX * ctx, PKCS11_SLOT * slot, CK_SLOT_ID id)
{
	PKCS11_SLOT_private *priv;
	CK_SLOT_INFO info;
	int rv;

	rv = CRYPTOKI_call(ctx, C_GetSlotInfo(id, &info));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_SLOTS, rv);

	priv = PKCS11_NEW(PKCS11_SLOT_private);
	priv->parent = ctx;
	priv->id = id;

	slot->description = PKCS11_DUP(info.slotDescription);
	slot->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;
	slot->_private = priv;

	if ((info.flags & CKF_TOKEN_PRESENT) && pkcs11_check_token(ctx, slot))
		return -1;

	return 0;
}

void PKCS11_release_all_slots(PKCS11_CTX * ctx,  PKCS11_SLOT *slots, unsigned int nslots)
{
	int i;

	for (i=0; i < nslots; i++)
		pkcs11_release_slot(ctx, &slots[i]);
	OPENSSL_free(slots);
}

void pkcs11_release_slot(PKCS11_CTX * ctx, PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);

	CRYPTOKI_call(ctx, C_CloseAllSessions(priv->id));
	OPENSSL_free(slot->_private);
	OPENSSL_free(slot->description);
	OPENSSL_free(slot->manufacturer);
	if (slot->token) {
		pkcs11_destroy_token(slot->token);
		OPENSSL_free(slot->token);
	}
	memset(slot, 0, sizeof(*slot));
}

static int pkcs11_check_token(PKCS11_CTX * ctx, PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_TOKEN_private *tpriv;
	CK_TOKEN_INFO info;
	PKCS11_TOKEN *token;
	int rv;

	if (slot->token)
		pkcs11_destroy_token(slot->token);
	else
		slot->token = PKCS11_NEW(PKCS11_TOKEN);
	token = slot->token;

	rv = CRYPTOKI_call(ctx, C_GetTokenInfo(priv->id, &info));
	if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED) {
		OPENSSL_free(token);
		slot->token = NULL;
		return 0;
	}
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CHECK_TOKEN, rv);

	/* We have a token */
	tpriv = PKCS11_NEW(PKCS11_TOKEN_private);
	tpriv->parent = slot;
	tpriv->nkeys = -1;
	tpriv->ncerts = -1;

	token->label = PKCS11_DUP(info.label);
	token->manufacturer = PKCS11_DUP(info.manufacturerID);
	token->model = PKCS11_DUP(info.model);
	token->serialnr = PKCS11_DUP(info.serialNumber);
	token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
	token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
	token->secureLogin = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
	token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
	token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
	token->_private = tpriv;

	return 0;
}

static void pkcs11_destroy_token(PKCS11_TOKEN * token)
{
	pkcs11_destroy_keys(token);
	pkcs11_destroy_certs(token);

	OPENSSL_free(token->label);
	OPENSSL_free(token->manufacturer);
	OPENSSL_free(token->model);
	OPENSSL_free(token->serialnr);
	OPENSSL_free(token->_private);
	memset(token, 0, sizeof(*token));
}
