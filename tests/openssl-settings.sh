#!/bin/bash

# Copyright © 2024 Mobi - Com Polska Sp. z o.o.
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

# OpenSSL settings
if test -n ${PKG_CONFIG_PATH}; then
    OPENSSL_PATH="${PKG_CONFIG_PATH}/../.."
    if command -v "${OPENSSL_PATH}/bin/openssl" &> /dev/null; then
        OPENSSL="${OPENSSL_PATH}/bin/openssl"
        export LD_LIBRARY_PATH="${OPENSSL_PATH}/lib64:${OPENSSL_PATH}/lib"
    else
        OPENSSL=openssl
    fi
else
    OPENSSL=openssl
fi
echo "Compiled with: `${OPENSSL} version`"
