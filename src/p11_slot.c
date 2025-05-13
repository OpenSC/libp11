/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#define _POSIX_C_SOURCE 200809L
#include "libp11-int.h"
#include <string.h>
#include <openssl/buffer.h>

static PKCS11_SLOT_private *pkcs11_slot_new(PKCS11_CTX_private *, CK_SLOT_ID);
static int pkcs11_init_slot(PKCS11_CTX_private *, PKCS11_SLOT *, PKCS11_SLOT_private *);
static void pkcs11_release_slot(PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

/*
 * Get slotid from private
 */
unsigned long pkcs11_get_slotid_from_slot(PKCS11_SLOT_private *slot)
{
	return slot->id;
}

/*
 * Enumerate slots
 */
int pkcs11_enumerate_slots(PKCS11_CTX_private *ctx, PKCS11_SLOT **slotp,
		unsigned int *countp)
{
	CK_SLOT_ID *slotid;
	CK_ULONG nslots, n, i;
	PKCS11_SLOT *slots;
	int rv;

	rv = ctx->method->C_GetSlotList(FALSE, NULL_PTR, &nslots);
	CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);
	if (nslots > 0x10000)
		return -1;

	if (!slotp) {
		/* Fast path for size inquiry */
		*countp = nslots;
		return 0;
	}

	slotid = OPENSSL_malloc(nslots * sizeof(*slotid));
	if (!slotid)
		return -1;

	rv = ctx->method->C_GetSlotList(FALSE, slotid, &nslots);
	if (rv != CKR_OK) {
		OPENSSL_free(slotid);
		CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);
	}

	slots = OPENSSL_malloc(nslots * sizeof(*slots));
	if (!slots) {
		OPENSSL_free(slotid);
		return -1;
	}

	memset(slots, 0, nslots * sizeof(PKCS11_SLOT));
	for (n = 0; n < nslots; n++) {
		PKCS11_SLOT_private *slot = NULL;
		for (i = 0; i < *countp; i++) {
			PKCS11_SLOT_private *slot_old_private =
				PRIVSLOT(&((*slotp)[i]));
			if (slot_old_private->id != slotid[n])
				continue;
			/* Increase ref count so it doesn't get freed when ref
			 * count is decremented in pkcs11_release_all_slots
			 * at the end of this function. */
			slot = pkcs11_slot_ref(slot_old_private);
			break;
		}
		if (!slot)
			slot = pkcs11_slot_new(ctx, slotid[n]);

		if (pkcs11_init_slot(ctx, &slots[n], slot)) {
			pkcs11_slot_unref(slot);
			pkcs11_release_all_slots(slots, n);
			OPENSSL_free(slotid);
			return -1;
		}
	}

	OPENSSL_free(slotid);
	pkcs11_release_all_slots(*slotp, *countp);
	*slotp = slots;
	*countp = nslots;
	return 0;
}

/*
 * Open a session with this slot
 */
int pkcs11_open_session(PKCS11_SLOT_private *slot, int rw)
{
	PKCS11_CTX_private *ctx = slot->ctx;

	pthread_mutex_lock(&slot->lock);
	/* If different mode requested, flush pool */
	if (rw != slot->rw_mode) {
		CRYPTOKI_call(ctx, C_CloseAllSessions(slot->id));
		slot->rw_mode = rw;
		slot->logged_in = -1;
	}
	slot->num_sessions = 0;
	slot->session_head = slot->session_tail = 0;
	pthread_mutex_unlock(&slot->lock);

	return 0;
}


static void pkcs11_wipe_cache(PKCS11_SLOT_private *slot)
{
	pkcs11_destroy_keys(slot, CKO_PRIVATE_KEY);
	pkcs11_destroy_keys(slot, CKO_PUBLIC_KEY);
	pkcs11_destroy_certs(slot);
}

int pkcs11_get_session(PKCS11_SLOT_private *slot, int rw, CK_SESSION_HANDLE *sessionp)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	int rv = CKR_OK;
	CK_SESSION_INFO session_info;

	if (rw < 0)
		return -1;

	pthread_mutex_lock(&slot->lock);
	if (slot->rw_mode < 0)
		slot->rw_mode = rw;
	rw = slot->rw_mode;
	do {
		/* Get session from the pool */
		if (slot->session_head != slot->session_tail) {
			*sessionp = slot->session_pool[slot->session_head];
			slot->session_head = (slot->session_head + 1) % slot->session_poolsize;

			/* Check if session is valid */
			rv = CRYPTOKI_call(ctx,
				C_GetSessionInfo(*sessionp, &session_info));
			if (rv == CKR_OK) {
				break;
			} else {
				/* Forget this session */
				slot->num_sessions--;
				if (slot->num_sessions == 0) {
					/* Object handles are valid across
					 * sessions, so the cache should only be
					 * cleared when there are no valid
					 * sessions.*/
					pkcs11_wipe_cache(slot);
				}
				continue;
			}
		}

		/* Check if new can be instantiated */
		if (slot->num_sessions < slot->max_sessions) {
			rv = CRYPTOKI_call(ctx,
				C_OpenSession(slot->id,
					CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0),
					NULL, NULL, sessionp));
			if (rv == CKR_OK) {
				slot->num_sessions++;
				break;
			} else {
				pthread_mutex_unlock(&slot->lock);
				return -1;
			}

			/* Remember the maximum session count */
			if (rv == CKR_SESSION_COUNT)
				slot->max_sessions = slot->num_sessions;
		}

		/* Wait for a session to become available */
		pthread_cond_wait(&slot->cond, &slot->lock);
	} while (1);
	pthread_mutex_unlock(&slot->lock);

	return 0;
}

void pkcs11_put_session(PKCS11_SLOT_private *slot, CK_SESSION_HANDLE session)
{
	pthread_mutex_lock(&slot->lock);

	slot->session_pool[slot->session_tail] = session;
	slot->session_tail = (slot->session_tail + 1) % slot->session_poolsize;
	pthread_cond_signal(&slot->cond);

	pthread_mutex_unlock(&slot->lock);
}

/*
 * Determines if user is authenticated with token
 */
int pkcs11_is_logged_in(PKCS11_SLOT_private *slot, int so, int *res)
{
	*res = slot->logged_in == so;
	return 0;
}

/*
 * Authenticate with the card.
 */
int pkcs11_login(PKCS11_SLOT_private *slot, int so, const char *pin)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int rv;

	if (slot->logged_in >= 0)
		return 0; /* Nothing to do */

	/* SO needs a r/w session, user can be checked with a r/o session. */
	if (pkcs11_get_session(slot, so, &session))
		return -1;

	rv = CRYPTOKI_call(ctx,
		C_Login(session, so ? CKU_SO : CKU_USER,
			(CK_UTF8CHAR *) pin, pin ? (unsigned long) strlen(pin) : 0));
	pkcs11_put_session(slot, session);

	if (rv && rv != CKR_USER_ALREADY_LOGGED_IN) { /* logged in -> OK */
		CRYPTOKI_checkerr(CKR_F_PKCS11_LOGIN, rv);
	}
	if (slot->prev_pin != pin) {
		if (slot->prev_pin) {
			OPENSSL_cleanse(slot->prev_pin, strlen(slot->prev_pin));
			OPENSSL_free(slot->prev_pin);
		}
		slot->prev_pin = OPENSSL_strdup(pin);
	}
	slot->logged_in = so;
	return 0;
}

/*
 * Reopens the slot by creating a session and logging in if needed.
 */
int pkcs11_reload_slot(PKCS11_SLOT_private *slot)
{
	int logged_in = slot->logged_in;

	slot->num_sessions = 0;
	slot->session_head = slot->session_tail = 0;
	if (logged_in >= 0) {
		slot->logged_in = -1;
		if (pkcs11_login(slot, logged_in, slot->prev_pin))
			return -1;
	}

	return 0;
}

/*
 * Log out
 */
int pkcs11_logout(PKCS11_SLOT_private *slot)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int rv = CKR_OK;

	/* Calling PKCS11_logout invalidates all cached
	 * keys we have */
	pkcs11_wipe_cache(slot);

	if (pkcs11_get_session(slot, slot->logged_in, &session) == 0) {
		rv = CRYPTOKI_call(ctx, C_Logout(session));
		pkcs11_put_session(slot, session);
	}
	CRYPTOKI_checkerr(CKR_F_PKCS11_LOGOUT, rv);
	slot->logged_in = -1;
	return 0;
}

/*
 * Initialize the token
 */
int pkcs11_init_token(PKCS11_SLOT_private *slot, const char *pin, const char *label)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	unsigned char ck_label[32];
	int rv;

	/* Must be padded with blank characters */
	memset(ck_label, ' ', sizeof ck_label);

	if (!label)
		label = "PKCS#11 Token";

	/* Must not be null terminated */
	memcpy(ck_label, label, strnlen(label, sizeof(ck_label)));

	rv = CRYPTOKI_call(ctx,
		C_InitToken(slot->id,
			(CK_UTF8CHAR *) pin, (unsigned long) strlen(pin),
			(CK_UTF8CHAR *) ck_label));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_TOKEN, rv);

	/* FIXME: how to update the token? */
#if 0
	PKCS11_CTX_private *cpriv;
	int n;
	cpriv = PRIVCTX(ctx);

	for (n = 0; n < cpriv->nslots; n++) {
		if (pkcs11_check_token(ctx, cpriv->slots + n) < 0)
			return -1;
	}
#endif

	return 0;
}

/*
 * Set the User PIN
 */
int pkcs11_init_pin(PKCS11_SLOT_private *slot, const char *pin)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_OBJECT_HANDLE session;
	int len, rv;

	if (pkcs11_get_session(slot, 1, &session)) {
		P11err(P11_F_PKCS11_INIT_PIN, P11_R_NO_SESSION);
		return -1;
	}

	len = pin ? (int) strlen(pin) : 0;
	rv = CRYPTOKI_call(ctx, C_InitPIN(session, (CK_UTF8CHAR *) pin, len));
	pkcs11_put_session(slot, session);
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_PIN, rv);

	return 0;
}

/*
 * Change the User PIN
 */
int pkcs11_change_pin(PKCS11_SLOT_private *slot, const char *old_pin,
		const char *new_pin)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int old_len, new_len, rv;

	if (pkcs11_get_session(slot, 1, &session)) {
		P11err(P11_F_PKCS11_CHANGE_PIN, P11_R_NO_SESSION);
		return -1;
	}

	old_len = old_pin ? (int) strlen(old_pin) : 0;
	new_len = new_pin ? (int) strlen(new_pin) : 0;
	rv = CRYPTOKI_call(ctx,
		C_SetPIN(session, (CK_UTF8CHAR *) old_pin, old_len,
			(CK_UTF8CHAR *) new_pin, new_len));
	pkcs11_put_session(slot, session);
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHANGE_PIN, rv);

	return 0;
}

/*
 * Seed the random number generator
 */
int pkcs11_seed_random(PKCS11_SLOT_private *slot, const unsigned char *s,
		unsigned int s_len)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int rv;

	if (pkcs11_get_session(slot, 0, &session)) {
		P11err(P11_F_PKCS11_SEED_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_SeedRandom(session, (CK_BYTE_PTR) s, s_len));
	pkcs11_put_session(slot, session);
	CRYPTOKI_checkerr(CKR_F_PKCS11_SEED_RANDOM, rv);

	return 0;
}

/*
 * Generate random numbers
 */
int pkcs11_generate_random(PKCS11_SLOT_private *slot, unsigned char *r,
		unsigned int r_len)
{
	PKCS11_CTX_private *ctx = slot->ctx;
	CK_SESSION_HANDLE session;
	int rv;

	if (pkcs11_get_session(slot, 0, &session)) {
		P11err(P11_F_PKCS11_GENERATE_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_GenerateRandom(session, (CK_BYTE_PTR) r, r_len));
	pkcs11_put_session(slot, session);

	CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_RANDOM, rv);

	return 0;
}

/*
 * Helper functions
 */
static PKCS11_SLOT_private *pkcs11_slot_new(PKCS11_CTX_private *ctx, CK_SLOT_ID id)
{
	PKCS11_SLOT_private *slot;

	slot = OPENSSL_malloc(sizeof(*slot));
	if (!slot)
		return NULL;
	memset(slot, 0, sizeof(*slot));
	slot->refcnt = 1;
	slot->ctx = ctx;
	slot->id = id;
	slot->forkid = ctx->forkid;
	slot->logged_in = -1;
	slot->rw_mode = -1;
	slot->max_sessions = 16;
	slot->session_poolsize = slot->max_sessions + 1;
	slot->session_pool = OPENSSL_malloc(slot->session_poolsize * sizeof(CK_SESSION_HANDLE));
	pthread_mutex_init(&slot->lock, 0);
	pthread_cond_init(&slot->cond, 0);
	return slot;
}

PKCS11_SLOT_private *pkcs11_slot_ref(PKCS11_SLOT_private *slot)
{
	pkcs11_atomic_add(&slot->refcnt, 1, &slot->lock);
	return slot;
}

int pkcs11_slot_unref(PKCS11_SLOT_private *slot)
{
	if (pkcs11_atomic_add(&slot->refcnt, -1, &slot->lock) != 0)
		return 0;

	pkcs11_wipe_cache(slot);
	if (slot->prev_pin) {
		OPENSSL_cleanse(slot->prev_pin, strlen(slot->prev_pin));
		OPENSSL_free(slot->prev_pin);
	}
	CRYPTOKI_call(slot->ctx, C_CloseAllSessions(slot->id));
	OPENSSL_free(slot->session_pool);
	pthread_mutex_destroy(&slot->lock);
	pthread_cond_destroy(&slot->cond);

	return 1;
}

static int pkcs11_init_slot(PKCS11_CTX_private *ctx, PKCS11_SLOT *slot, PKCS11_SLOT_private *spriv)
{
	CK_SLOT_INFO info;
	int rv;

	rv = CRYPTOKI_call(ctx, C_GetSlotInfo(spriv->id, &info));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_SLOT, rv);

	slot->_private = spriv;
	slot->description = PKCS11_DUP(info.slotDescription);
	slot->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;

	if (info.flags & CKF_TOKEN_PRESENT) {
		if (pkcs11_refresh_token(slot))
			return -1;
	}
	return 0;
}

void pkcs11_release_all_slots(PKCS11_SLOT *slots, unsigned int nslots)
{
	unsigned int i;

	for (i = 0; i < nslots; i++)
		pkcs11_release_slot(&slots[i]);
	OPENSSL_free(slots);
}

static void pkcs11_release_slot(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (slot->token) {
		pkcs11_destroy_token(slot->token);
		OPENSSL_free(slot->token);
	}
	if (spriv) {
		if (pkcs11_slot_unref(spriv) != 0) {
			OPENSSL_free(slot->_private);
		}
	}
	OPENSSL_free(slot->description);
	OPENSSL_free(slot->manufacturer);

	memset(slot, 0, sizeof(*slot));
}

int pkcs11_refresh_token(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX_private *ctx = spriv->ctx;
	CK_TOKEN_INFO info;
	int rv;

	if (slot->token)
		pkcs11_destroy_token(slot->token);

	rv = CRYPTOKI_call(ctx, C_GetTokenInfo(spriv->id, &info));
	if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED) {
		OPENSSL_free(slot->token);
		slot->token = NULL;
		return 0;
	}
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHECK_TOKEN, rv);

	/* We have a token */
	if (!slot->token) {
		slot->token = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
		if (!slot->token)
			return -1;
		memset(slot->token, 0, sizeof(PKCS11_TOKEN));
	}

	slot->token->label = PKCS11_DUP(info.label);
	slot->token->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->token->model = PKCS11_DUP(info.model);
	slot->token->serialnr = PKCS11_DUP(info.serialNumber);
	slot->token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
	slot->token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
	slot->token->secureLogin = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
	slot->token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
	slot->token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
	slot->token->hasRng = (info.flags & CKF_RNG) ? 1 : 0;
	slot->token->userPinCountLow = (info.flags & CKF_USER_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->userPinFinalTry = (info.flags & CKF_USER_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->userPinLocked = (info.flags & CKF_USER_PIN_LOCKED) ? 1 : 0;
	slot->token->userPinToBeChanged = (info.flags & CKF_USER_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->soPinCountLow = (info.flags & CKF_SO_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->soPinFinalTry = (info.flags & CKF_SO_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->soPinLocked = (info.flags & CKF_SO_PIN_LOCKED) ? 1 : 0;
	slot->token->soPinToBeChanged = (info.flags & CKF_SO_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->slot = slot;

	spriv->secure_login = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;

	return 0;
}

static void pkcs11_destroy_token(PKCS11_TOKEN *token)
{
	pkcs11_wipe_cache(PRIVSLOT(token->slot));
	OPENSSL_free(token->label);
	OPENSSL_free(token->manufacturer);
	OPENSSL_free(token->model);
	OPENSSL_free(token->serialnr);
	memset(token, 0, sizeof(*token));
}

/* vim: set noexpandtab: */
