#!/bin/bash

# Copyright © 2024-2026 Mobi - Com Polska Sp. z o.o.
# Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# Save original library path for later restoration
TEMP_LD_LIBRARY_PATH=${LD_LIBRARY_PATH}

# Use the configured OpenSSL library path if found
OPENSSL_LIBDIR=$(pkg-config --variable=libdir --silence-errors openssl)
if test -n "${OPENSSL_LIBDIR}"; then
    export LD_LIBRARY_PATH="${OPENSSL_LIBDIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

# Use the configured OpenSSL executable path if found
OPENSSL_PREFIX=$(pkg-config --variable=prefix --silence-errors openssl)
if test -n "${OPENSSL_PREFIX}"; then
    OPENSSL=$(PATH="${OPENSSL_PREFIX}/bin:${PATH}" command -v openssl 2>/dev/null || echo openssl)
else
    OPENSSL=openssl
fi

# Use the compiled and not the installed libp11.so
export LD_LIBRARY_PATH="$(pwd)/../src/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "Compiled with: $(${OPENSSL} version)"
