/* libp11, a simple layer on top of PKCS#11 API
 * Copyright (C) 2017 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2017-2025 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#if defined(HAVE_PTHREAD)

#include <pthread.h>

#elif defined( _WIN32)

/* Simple wrappers for used pthread API using Windows Vista+ APIs. */
#if _WIN32_WINNT < 0x0600
#error Windows Vista (or Server 2008) or later required.
#endif

#include <windows.h>

typedef CRITICAL_SECTION pthread_mutex_t;
typedef void pthread_mutexattr_t;

static int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
	(void)attr;
	InitializeCriticalSection(mutex);
	return 0;
}

static int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	DeleteCriticalSection(mutex);
	return 0;
}

static int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	EnterCriticalSection(mutex);
	return 0;
}

static int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	LeaveCriticalSection(mutex);
	return 0;
}

typedef CONDITION_VARIABLE pthread_cond_t;
typedef void pthread_condattr_t;

static int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr)
{
	(void)attr;
	InitializeConditionVariable(cond);
	return 0;
}

static int pthread_cond_destroy(pthread_cond_t *cond)
{
	(void)cond;
	return 0;
}

static int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if (!SleepConditionVariableCS(cond, mutex, INFINITE))
		return 1;
	return 0;
}

static int pthread_cond_signal(pthread_cond_t *cond)
{
	WakeConditionVariable(cond);
	return 0;
}

#else

#error Locking not supported on this platform.

#endif

/* vim: set noexpandtab: */
