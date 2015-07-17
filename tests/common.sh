#!/bin/sh

# Copyright (C) 2013 Nikos Mavrogiannopoulos
# Copyright (C) 2015 Red Hat, Inc.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

mkdir -p $outdir

if test -f /usr/lib64/pkcs11/libsofthsm2.so; then
	ADDITIONAL_PARAM="/usr/lib64/pkcs11/libsofthsm2.so"
else
	if test -f /usr/lib/softhsm/libsofthsm.so; then
		ADDITIONAL_PARAM="/usr/lib/softhsm/libsofthsm.so"
	else
		ADDITIONAL_PARAM="/usr/lib64/softhsm/libsofthsm.so"
	fi
fi

if ! test -x /usr/bin/pkcs11-tool;then
	exit 77
fi

init_card () {
	PIN="$1"
	PUK="$2"

	if test -x "/usr/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm2-util"
	fi

	if test -x "/usr/bin/softhsm"; then
		export SOFTHSM_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm"
	fi

	if test -z "${SOFTHSM_TOOL}"; then
		echo "Could not find softhsm(2) tool"
		exit 77
	fi

	if test -z "${SOFTHSM_CONF}"; then
		rm -rf $outdir/softhsm-testpkcs11.db
		mkdir -p $outdir/softhsm-testpkcs11.db
		echo "objectstore.backend = file" > "${SOFTHSM2_CONF}"
		echo "directories.tokendir = $outdir/softhsm-testpkcs11.db" >> "${SOFTHSM2_CONF}"
	else
		rm -rf $outdir/softhsm-testpkcs11.db
		echo "0:$outdir/softhsm-testpkcs11.db" > "${SOFTHSM_CONF}"
	fi


	echo -n "* Initializing smart card... "
	${SOFTHSM_TOOL} --init-token --slot 0 --label "libp11-test" --so-pin "${PUK}" --pin "${PIN}" >/dev/null
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

PIN=1234
PUK=1234
init_card $PIN $PUK

# generate key in token
pkcs11-tool -p $PIN --module $ADDITIONAL_PARAM -d 00010203 -a server-key -l -w ${file_dir}/key.der -y privkey >/dev/null
if test $? != 0;then
	exit 1;
fi

pkcs11-tool -p $PIN --module $ADDITIONAL_PARAM -d 00010203 -a server-key -l -w ${file_dir}/cert.der -y cert >/dev/null
if test $? != 0;then
	exit 1;
fi

echo "***************"
echo "Listing objects"
echo "***************"
pkcs11-tool -p $PIN --module $ADDITIONAL_PARAM -l -O
