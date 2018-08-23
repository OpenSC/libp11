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

OPENSSL_VERSION=$(./openssl_version | cut -d ' ' -f 2)
case "${OPENSSL_VERSION}" in
0.*)
    echo "EC tests skipped with OpenSSL ${OPENSSL_VERSION}"
	exit 77
	;;
*)
	;;
esac

echo "Current directory: $(pwd)"
echo "Source directory: ${srcdir}"
echo "Output directory: ${outdir}"

mkdir -p $outdir

for i in /usr/lib64/pkcs11 /usr/lib64/softhsm /usr/lib/x86_64-linux-gnu/softhsm /usr/local/lib/softhsm /opt/local/lib/softhsm /usr/lib/softhsm /usr/lib ;do
	if test -f "$i/libsofthsm2.so"; then
		MODULE="$i/libsofthsm2.so"
		break
	else
		if test -f "$i/libsofthsm.so";then
			MODULE="$i/libsofthsm.so"
			break
		fi
	fi
done

if (! test -x /usr/bin/pkcs11-tool && ! test -x /usr/local/bin/pkcs11-tool);then
	exit 77
fi

init_card () {
	PIN="$1"
	PUK="$2"

	if test -x "/usr/bin/softhsm"; then
		export SOFTHSM_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm"
	fi

	if test -x "/usr/local/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/local/bin/softhsm2-util"
	fi

	if test -x "/opt/local/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/opt/local/bin/softhsm2-util"
	fi

	if test -x "/usr/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm2-util"
	fi

	if test -z "${SOFTHSM_TOOL}"; then
		echo "Could not find softhsm(2) tool"
		exit 77
	fi

	if test -n "${SOFTHSM2_CONF}"; then
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
pkcs11-tool -p $PIN --module $MODULE -d 01020304 -a server-key -l -w ${srcdir}/ec-prvkey.der -y privkey >/dev/null
if test $? != 0;then
	exit 1;
fi

# pkcs11-tool currently only supports RSA public keys
pkcs11-tool -p $PIN --module $MODULE -d 01020304 -a server-key -l -w ${srcdir}/ec-pubkey.der -y pubkey >/dev/null
if test $? != 0;then
	exit 1;
fi

pkcs11-tool -p $PIN --module $MODULE -d 01020304 -a server-key -l -w ${srcdir}/ec-cert.der -y cert >/dev/null
if test $? != 0;then
	exit 1;
fi

echo "***************"
echo "Listing objects"
echo "***************"
pkcs11-tool -p $PIN --module $MODULE -l -O
