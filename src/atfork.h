/*
 * Copyright (C) 2014 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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

#ifndef ATFORK_H
# define ATFORK_H

extern unsigned int P11_forkid;

#if defined(HAVE___REGISTER_ATFORK)
# define HAVE_ATFORK
#endif

#ifndef _WIN32

/* API */
int _P11_register_fork_handler(void); /* global init */

# if defined(HAVE_ATFORK)
inline static int _P11_detect_fork(unsigned int forkid)
{
	if (forkid == P11_forkid)
		return 0;
	return 1;
}

inline static unsigned int _P11_get_forkid(void)
{
	return P11_forkid;
}
# else
int _P11_detect_fork(unsigned int forkid);
unsigned int _P11_get_forkid(void);
# endif

#else

# define _P11_detect_fork(x) 0
# define _P11_get_forkid() 0

#endif

#endif

/* vim: set noexpandtab: */
