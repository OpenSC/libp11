/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include "libp11-int.h"

#ifndef _WIN32

static unsigned int P11_forkid = 0;

#ifdef HAVE_PTHREAD

#include <pthread.h>

static void _P11_atfork_child(void)
{
	P11_forkid++;
}

__attribute__((constructor))
int _P11_register_fork_handler(void)
{
	if (pthread_atfork(0, 0, _P11_atfork_child) != 0)
		return -1;
	return 0;
}

static unsigned int  _P11_update_forkid(void)
{
	return P11_forkid;
}

#else /* HAVE_PTHREAD */

#include <unistd.h>

static unsigned int _P11_update_forkid(void)
{
	P11_forkid = (unsigned int)getpid();
	return P11_forkid;
}

#endif /* HAVE_PTHREAD */

#define CHECK_FORKID(ctx, forkid, function_call) \
	do { \
		int rv = 0; \
		_P11_update_forkid(); \
		if (forkid != P11_forkid) { \
			pthread_mutex_lock(&ctx->fork_lock); \
			function_call; \
			pthread_mutex_unlock(&ctx->fork_lock); \
		} \
		return rv; \
	} while (0)

#else /* !_WIN32 */

#define P11_forkid 0
#define _P11_update_forkid() 0
#define CHECK_FORKID(ctx, forkid, function_call) return 0

#endif /* !_WIN32 */

unsigned int get_forkid()
{
	_P11_update_forkid();
	return P11_forkid;
}

/*
 * PKCS#11 reinitialization after fork
 * It wipes out the internal state of the PKCS#11 library
 * Any libp11 references to this state are no longer valid
 */
static int check_fork_int(PKCS11_CTX_private *ctx)
{
	if (ctx->forkid != P11_forkid) {
		if (pkcs11_CTX_reload(ctx) < 0)
			return -1;
		ctx->forkid = P11_forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also relogins and reopens the session if needed
 */
static int check_slot_fork_int(PKCS11_SLOT_private *slot)
{
	PKCS11_CTX_private *ctx = slot->ctx;

	if (check_fork_int(ctx) < 0)
		return -1;
	if (slot->forkid != ctx->forkid) {
		if (pkcs11_reload_slot(slot) < 0)
			return -1;
		slot->forkid = ctx->forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also reloads the object
 */
static int check_object_fork_int(PKCS11_OBJECT_private *obj)
{
	PKCS11_SLOT_private *slot = obj->slot;

	if (check_slot_fork_int(slot) < 0)
		return -1;

	if (slot->forkid != obj->forkid) {
		if (pkcs11_reload_object(obj) < 0)
			return -1;
		obj->forkid = slot->forkid;
	}
	return 0;
}

/*
 * Locking interface to check_fork_int()
 */
int check_fork(PKCS11_CTX_private *ctx)
{
	if (!ctx)
		return -1;
	CHECK_FORKID(ctx, ctx->forkid, check_fork_int(ctx));
}

/*
 * Locking interface to check_slot_fork_int()
 */
int check_slot_fork(PKCS11_SLOT_private *slot)
{
	if (!slot)
		return -1;
	CHECK_FORKID(slot->ctx, slot->forkid, check_slot_fork_int(slot));
}

/*
 * Locking interface to check_object_fork_int()
 */
int check_object_fork(PKCS11_OBJECT_private *obj)
{
	if (!obj)
		return -1;
	CHECK_FORKID(obj->slot->ctx, obj->forkid, check_object_fork_int(obj));
}

/* vim: set noexpandtab: */
