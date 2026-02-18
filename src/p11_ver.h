/* libp11, a simple layer on top of PKCS#11 API
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
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

#define LIBP11_VERSION_MAJOR 0
#define LIBP11_VERSION_MINOR 4
#define LIBP11_VERSION_FIX   19

/*
 * The LIBP11_VERSION_NUMBER layout is 0xMMmmffff, where
 *  - MM represents hexadecimal encoding of LIBP11_VERSION_MAJOR
 *  - mm represents hexadecimal encoding of LIBP11_VERSION_MINOR
 *  - ffff represents hexadecimal encoding of LIBP11_VERSION_FIX
 */
#define LIBP11_VERSION_NUMBER ( \
    (LIBP11_VERSION_MAJOR<<24) | \
    (LIBP11_VERSION_MINOR<<16) | \
    LIBP11_VERSION_FIX)

/* vim: set noexpandtab: */
