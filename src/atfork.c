/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2014 Red Hat
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
#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <atfork.h>

#ifdef __sun
# pragma fini(lib_deinit)
# pragma init(lib_init)
# define _CONSTRUCTOR
# define _DESTRUCTOR
#else
# define _CONSTRUCTOR __attribute__((constructor))
# define _DESTRUCTOR __attribute__((destructor))
#endif

unsigned int P11_forkid = 0;

#ifndef _WIN32

# ifdef HAVE_ATFORK
static void fork_handler(void)
{
	P11_forkid++;
}
# endif

# if defined(HAVE___REGISTER_ATFORK)
extern int __register_atfork(void (*)(void), void(*)(void), void (*)(void), void *);
extern void *__dso_handle;

_CONSTRUCTOR
int _P11_register_fork_handler(void)
{
	if (__register_atfork(0, 0, fork_handler, __dso_handle) != 0)
		return -1;
	return 0;
}

# else

unsigned int _P11_get_forkid(void)
{
	return getpid();
}

int _P11_detect_fork(unsigned int forkid)
{
	if (getpid() == forkid)
		return 0;
	return 1;
}

/* we have to detect fork manually */
_CONSTRUCTOR
int _P11_register_fork_handler(void)
{
	P11_forkid = getpid();
	return 0;
}

# endif

#endif /* !_WIN32 */

/* vim: set noexpandtab: */
